"""Password hashing, session tokens, Fernet key management, login lockout."""
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

SESSION_COOKIE = "tih_session"
SESSION_TTL = timedelta(hours=24)


def hash_password(password: str) -> str:
    return ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return ph.verify(password_hash, password)
    except (VerifyMismatchError, ValueError):
        return False


def new_session_token() -> tuple[str, str]:
    """Return (cookie_value, sha256 stored in DB)."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ponytail: in-memory lockout dict — single-process MVP; move to Redis
# (`tih:lock:{email}`, INCR+EXPIRE) if the API ever runs multi-worker.
_failed_logins: dict[str, list[float]] = {}
LOCKOUT_LIMIT = 5
LOCKOUT_WINDOW = timedelta(minutes=15)


def is_locked(email: str) -> bool:
    now = datetime.now(timezone.utc).timestamp()
    attempts = [t for t in _failed_logins.get(email, []) if now - t < LOCKOUT_WINDOW.total_seconds()]
    _failed_logins[email] = attempts
    return len(attempts) >= LOCKOUT_LIMIT


def record_failed_login(email: str) -> None:
    now = datetime.now(timezone.utc).timestamp()
    _failed_logins.setdefault(email, []).append(now)


def clear_failed_logins(email: str) -> None:
    _failed_logins.pop(email, None)


def get_fernet() -> Fernet:
    """Master Fernet key from SETTINGS_FERNET_KEY; generate + persist to .env once if absent."""
    import os

    key = os.environ.get("SETTINGS_FERNET_KEY")
    if key:
        return Fernet(key.encode())

    dotenv_path = Path(os.environ.get("TIH_DOTENV", ".env"))
    key = Fernet.generate_key().decode()
    lines = dotenv_path.read_text().splitlines() if dotenv_path.exists() else []
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith("SETTINGS_FERNET_KEY="):
            lines[i] = f"SETTINGS_FERNET_KEY={key}"
            replaced = True
            break
    if not replaced:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"SETTINGS_FERNET_KEY={key}")
    dotenv_path.write_text("\n".join(lines) + "\n")
    logger.warning("SETTINGS_FERNET_KEY missing; generated new master key and persisted to %s", dotenv_path)
    os.environ["SETTINGS_FERNET_KEY"] = key
    return Fernet(key.encode())


def encrypt_key(f: Fernet, plaintext: str) -> bytes:
    return f.encrypt(plaintext.encode())


def decrypt_key(f: Fernet, ciphertext: bytes) -> str:
    return f.decrypt(ciphertext).decode()


def mask_key(plaintext: str) -> str:
    if len(plaintext) <= 8:
        return "•" * len(plaintext)
    return f"{plaintext[:4]}…{plaintext[-4:]}"
