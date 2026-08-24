# Contributing

Thanks for considering a contribution! ThreatIntelHub is AGPL-3.0 — by opening a PR you
agree your contribution is licensed under AGPL-3.0 as well.

## Dev setup

```bash
# backend
cd backend
uv sync                       # creates .venv
.venv/bin/python -m pytest tests/ -q

# frontend
cd frontend
npm install
npm run build

# full stack
docker compose up -d --build
```

Python 3.12+, Node 20+.

## Code style

- Python: ruff-compatible, type-hinted, async-first. No comments unless they explain a deliberate simplification (`ponytail:` markers are used in this repo).
- TypeScript: strict mode, `'use client'` on interactive pages, Tailwind utility classes only (dark theme).
- Every non-trivial change ships with a test (`backend/tests/`, plain pytest, sqlite-shimmed, no network).

## Pull requests

1. Keep diffs focused — one feature or fix per PR.
2. Run `pytest` and `npm run build` before pushing; CI-clean PRs get reviewed first.
3. Describe what changed and why; link related issues.

## Reporting bugs / security issues

Bugs → GitHub Issues. Security → see [SECURITY.md](./SECURITY.md).
