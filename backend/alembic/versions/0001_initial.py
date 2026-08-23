"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-23

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
    )

    op.create_table(
        "sessions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", pg.UUID(as_uuid=False), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.Text(), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])

    op.create_table(
        "feed_sources",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("slug", sa.Text(), nullable=False, unique=True),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("reliability_weight", sa.Numeric(3, 2), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("schedule_cron", pg.JSONB()),
        sa.Column("cursor_state", pg.JSONB()),
    )

    op.create_table(
        "feed_health",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("feed_source_id", sa.Integer(), sa.ForeignKey("feed_sources.id"), nullable=False, unique=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True)),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("last_status", sa.Text(), nullable=False),
        sa.Column("last_error", sa.Text()),
        sa.Column("consecutive_failures", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("items_last_run", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("duration_ms_last_run", sa.Float()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "last_status IN ('ok','degraded','quota_exhausted','error','disabled')",
            name="ck_feed_health_last_status",
        ),
    )

    op.create_table(
        "quota_usage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("feed_source_id", sa.Integer(), sa.ForeignKey("feed_sources.id"), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("calls_made", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("calls_limit", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("quota_violations", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.create_index("uq_quota_usage_feed_day", "quota_usage", ["feed_source_id", "day"], unique=True)

    op.create_table(
        "iocs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("type", sa.Text(), nullable=False),
        sa.Column("value_norm", sa.Text(), nullable=False),
        sa.Column("threat_score", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("severity", sa.Text(), server_default=sa.text("'info'"), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_stale", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("tags", pg.JSONB()),
        sa.Column("score_computed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("type IN ('ip','domain','url','sha256','sha1','md5')", name="ck_iocs_type"),
        sa.CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="ck_iocs_severity"
        ),
    )
    op.create_index("uq_iocs_type_value", "iocs", ["type", "value_norm"], unique=True)
    op.create_index(
        "ix_iocs_severity_score_seen",
        "iocs",
        [sa.text("severity"), sa.text("threat_score DESC"), sa.text("last_seen DESC")],
    )
    op.create_index("ix_iocs_tags", "iocs", ["tags"], postgresql_using="gin")
    op.create_index("ix_iocs_is_stale", "iocs", ["is_stale"], postgresql_where=sa.text("is_stale"))

    op.create_table(
        "sightings",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ioc_id", sa.BigInteger(), sa.ForeignKey("iocs.id"), nullable=False),
        sa.Column("feed_source_id", sa.Integer(), sa.ForeignKey("feed_sources.id"), nullable=False),
        sa.Column("external_ref", sa.Text(), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("raw", pg.JSONB()),
        sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index(
        "uq_sightings_dedupe", "sightings", ["ioc_id", "feed_source_id", "external_ref"], unique=True
    )
    op.create_index(
        "ix_sightings_ioc_seen", "sightings", [sa.text("ioc_id"), sa.text("seen_at DESC")]
    )
    op.create_index("ix_sightings_seen_at", "sightings", ["seen_at"])

    op.create_table(
        "enrichments",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("ioc_id", sa.BigInteger(), sa.ForeignKey("iocs.id"), nullable=False),
        sa.Column("feed_source_id", sa.Integer(), sa.ForeignKey("feed_sources.id"), nullable=False),
        sa.Column("data", pg.JSONB(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("uq_enrichments_ioc_source", "enrichments", ["ioc_id", "feed_source_id"], unique=True)
    op.create_index("ix_enrichments_expires_at", "enrichments", ["expires_at"])

    op.create_table(
        "reports",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("kind IN ('daily','weekly','ondemand')", name="ck_reports_kind"),
        sa.CheckConstraint(
            "status IN ('pending','generating','ready','failed')", name="ck_reports_status"
        ),
    )

    op.create_table(
        "report_items",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("report_id", pg.UUID(as_uuid=True), sa.ForeignKey("reports.id"), nullable=False),
        sa.Column("ioc_id", sa.BigInteger(), sa.ForeignKey("iocs.id"), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("score_at_generation", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "reason IN ('top_score','new_today','multi_source','watchlist')",
            name="ck_report_items_reason",
        ),
    )
    op.create_index("uq_report_items_report_ioc", "report_items", ["report_id", "ioc_id"], unique=True)

    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("report_id", pg.UUID(as_uuid=True), sa.ForeignKey("reports.id"), nullable=False),
        sa.Column("format", sa.Text(), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint(
            "format IN ('pdf','json','csv','stix')", name="ck_report_artifacts_format"
        ),
    )

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("feed_source_id", sa.Integer(), sa.ForeignKey("feed_sources.id"), nullable=False, unique=True),
        sa.Column("encrypted_key", pg.BYTEA(), nullable=False),
        sa.Column("key_hint", sa.Text(), nullable=False),
        sa.Column("is_configured", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("validated_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "samples",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("sha256", sa.Text(), nullable=False, unique=True),
        sa.Column("filename", sa.Text()),
        sa.Column("source_note", sa.Text()),
        sa.Column("strings_extracted", pg.JSONB(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "yara_rules",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("sample_id", pg.UUID(as_uuid=True), sa.ForeignKey("samples.id"), nullable=False),
        sa.Column("name", sa.Text(), nullable=False, unique=True),
        sa.Column("rule_text", sa.Text(), nullable=False),
        sa.Column("compiled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("corpus_fp_free", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("validation_report", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "yara_rule_iocs",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("yara_rule_id", pg.UUID(as_uuid=True), sa.ForeignKey("yara_rules.id"), nullable=False),
        sa.Column("ioc_id", sa.BigInteger(), sa.ForeignKey("iocs.id"), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.CheckConstraint("role IN ('derived_from','related')", name="ck_yara_rule_iocs_role"),
    )
    op.create_index(
        "uq_yara_rule_iocs_rule_ioc", "yara_rule_iocs", ["yara_rule_id", "ioc_id"], unique=True
    )

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger(), primary_key=True),
        sa.Column("user_id", pg.UUID(as_uuid=False), sa.ForeignKey("users.id")),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("entity_type", sa.Text()),
        sa.Column("entity_id", sa.Text()),
        sa.Column("detail", pg.JSONB()),
        sa.Column("ip_address", pg.INET()),
        sa.Column("at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_audit_log_at", "audit_log", [sa.text("at DESC")])


def downgrade() -> None:
    for table in (
        "audit_log",
        "yara_rule_iocs",
        "yara_rules",
        "samples",
        "api_keys",
        "report_artifacts",
        "report_items",
        "reports",
        "enrichments",
        "sightings",
        "iocs",
        "quota_usage",
        "feed_health",
        "feed_sources",
        "sessions",
        "users",
    ):
        op.drop_table(table)
