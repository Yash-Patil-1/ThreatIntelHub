"""SQLAlchemy models — mirrors BACKEND_SCHEMA.md data model exactly."""
from datetime import date, datetime
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import BYTEA, INET, JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

UTC_NOW = text("now()")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=UTC_NOW)
    email: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Session(Base):
    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_expires_at", "expires_at"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=UTC_NOW)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"))
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


class FeedSource(Base):
    __tablename__ = "feed_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(Text, unique=True)
    display_name: Mapped[str] = mapped_column(Text)
    reliability_weight: Mapped[float] = mapped_column(Numeric(3, 2))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("true"))
    schedule_cron: Mapped[dict | None] = mapped_column(JSONB)
    cursor_state: Mapped[dict | None] = mapped_column(JSONB)


class FeedHealth(Base):
    __tablename__ = "feed_health"
    __table_args__ = (
        CheckConstraint(
            "last_status IN ('ok','degraded','quota_exhausted','error','disabled')",
            name="ck_feed_health_last_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_source_id: Mapped[int] = mapped_column(
        ForeignKey("feed_sources.id"), unique=True
    )
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str] = mapped_column(Text)
    last_error: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    items_last_run: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    duration_ms_last_run: Mapped[float | None] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


class QuotaUsage(Base):
    __tablename__ = "quota_usage"
    __table_args__ = (
        Index("uq_quota_usage_feed_day", "feed_source_id", "day", unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_source_id: Mapped[int] = mapped_column(ForeignKey("feed_sources.id"))
    day: Mapped[date] = mapped_column(Date)
    calls_made: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    calls_limit: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    quota_violations: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))


class Ioc(Base):
    __tablename__ = "iocs"
    __table_args__ = (
        CheckConstraint(
            "type IN ('ip','domain','url','sha256','sha1','md5')", name="ck_iocs_type"
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="ck_iocs_severity"
        ),
        Index("uq_iocs_type_value", "type", "value_norm", unique=True),
        Index("ix_iocs_tags", "tags", postgresql_using="gin"),
        Index("ix_iocs_is_stale", "is_stale", postgresql_where=text("is_stale")),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    type: Mapped[str] = mapped_column(Text)
    value_norm: Mapped[str] = mapped_column(Text)
    threat_score: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"))
    severity: Mapped[str] = mapped_column(Text, default="info", server_default=text("'info'"))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    tags: Mapped[list | None] = mapped_column(JSONB)
    score_computed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index("ix_iocs_severity_score_seen", Ioc.severity, Ioc.threat_score.desc(), Ioc.last_seen.desc())


class Sighting(Base):
    __tablename__ = "sightings"
    __table_args__ = (
        Index("uq_sightings_dedupe", "ioc_id", "feed_source_id", "external_ref", unique=True),
        Index("ix_sightings_seen_at", "seen_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))
    feed_source_id: Mapped[int] = mapped_column(ForeignKey("feed_sources.id"))
    external_ref: Mapped[str] = mapped_column(Text)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw: Mapped[dict | None] = mapped_column(JSONB)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


Index("ix_sightings_ioc_seen", Sighting.ioc_id, Sighting.seen_at.desc())


class Enrichment(Base):
    __tablename__ = "enrichments"
    __table_args__ = (
        Index("uq_enrichments_ioc_source", "ioc_id", "feed_source_id", unique=True),
        Index("ix_enrichments_expires_at", "expires_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))
    feed_source_id: Mapped[int] = mapped_column(ForeignKey("feed_sources.id"))
    data: Mapped[dict] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("kind IN ('daily','weekly','ondemand')", name="ck_reports_kind"),
        CheckConstraint(
            "status IN ('pending','generating','ready','failed')", name="ck_reports_status"
        ),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=UTC_NOW)
    kind: Mapped[str] = mapped_column(Text)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportItem(Base):
    __tablename__ = "report_items"
    __table_args__ = (
        CheckConstraint(
            "reason IN ('top_score','new_today','multi_source','watchlist')",
            name="ck_report_items_reason",
        ),
        Index("uq_report_items_report_ioc", "report_id", "ioc_id", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    report_id: Mapped[UUID] = mapped_column(ForeignKey("reports.id"))
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))
    reason: Mapped[str] = mapped_column(Text)
    score_at_generation: Mapped[int] = mapped_column(Integer)


class ReportArtifact(Base):
    __tablename__ = "report_artifacts"
    __table_args__ = (
        CheckConstraint("format IN ('pdf','json','csv','stix')", name="ck_report_artifacts_format"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    report_id: Mapped[UUID] = mapped_column(ForeignKey("reports.id"))
    format: Mapped[str] = mapped_column(Text)
    file_path: Mapped[str] = mapped_column(Text)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_source_id: Mapped[int] = mapped_column(ForeignKey("feed_sources.id"), unique=True)
    encrypted_key: Mapped[bytes] = mapped_column(BYTEA)
    key_hint: Mapped[str] = mapped_column(Text)
    is_configured: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=UTC_NOW)
    sha256: Mapped[str] = mapped_column(Text, unique=True)
    filename: Mapped[str | None] = mapped_column(Text)
    source_note: Mapped[str | None] = mapped_column(Text)
    strings_extracted: Mapped[list] = mapped_column(JSONB)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


class YaraRule(Base):
    __tablename__ = "yara_rules"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=UTC_NOW)
    sample_id: Mapped[UUID] = mapped_column(ForeignKey("samples.id"))
    name: Mapped[str] = mapped_column(Text, unique=True)
    rule_text: Mapped[str] = mapped_column(Text)
    compiled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    corpus_fp_free: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"))
    validation_report: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


class YaraRuleIoc(Base):
    __tablename__ = "yara_rule_iocs"
    __table_args__ = (
        CheckConstraint("role IN ('derived_from','related')", name="ck_yara_rule_iocs_role"),
        Index("uq_yara_rule_iocs_rule_ioc", "yara_rule_id", "ioc_id", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    yara_rule_id: Mapped[UUID] = mapped_column(ForeignKey("yara_rules.id"))
    ioc_id: Mapped[int] = mapped_column(ForeignKey("iocs.id"))
    role: Mapped[str] = mapped_column(Text)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    user_id: Mapped[UUID | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(Text)
    entity_type: Mapped[str | None] = mapped_column(Text)
    entity_id: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict | None] = mapped_column(JSONB)
    ip_address: Mapped[str | None] = mapped_column(INET)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=UTC_NOW)


Index("ix_audit_log_at", AuditLog.at.desc())


ALL_TABLES = [
    User,
    Session,
    FeedSource,
    FeedHealth,
    QuotaUsage,
    Ioc,
    Sighting,
    Enrichment,
    Report,
    ReportItem,
    ReportArtifact,
    ApiKey,
    Sample,
    YaraRule,
    YaraRuleIoc,
    AuditLog,
]
