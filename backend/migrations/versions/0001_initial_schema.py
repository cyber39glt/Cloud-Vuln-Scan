"""Initial schema: clients, connections, assessments, scan runs, findings.

Includes a trigger making stored scan runs and findings immutable (UPDATE is refused;
DELETE remains possible for data-retention purposes).

Revision ID: 0001
Revises:
Create Date: 2026-10-07 12:53:05.972104
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(trim(name)) > 0", name=op.f("ck_clients_client_name_not_blank")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_clients")),
        sa.UniqueConstraint("name", name=op.f("uq_clients_name")),
    )
    op.create_table(
        "cloud_connections",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column(
            "provider",
            sa.Enum(
                "aws",
                "azure",
                name="provider",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=1224), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id"],
            ["clients.id"],
            name=op.f("fk_cloud_connections_client_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cloud_connections")),
        sa.UniqueConstraint(
            "client_id",
            "provider",
            "account_id",
            name=op.f("uq_cloud_connections_client_id_provider_account_id"),
        ),
        sa.UniqueConstraint("external_id", name=op.f("uq_cloud_connections_external_id")),
        sa.UniqueConstraint("id", "client_id", name=op.f("uq_cloud_connections_id_client_id")),
    )
    op.create_table(
        "assessments",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("connection_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "draft",
                "in_review",
                "finalized",
                name="assessment_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(trim(name)) > 0", name=op.f("ck_assessments_assessment_name_not_blank")
        ),
        sa.ForeignKeyConstraint(
            ["connection_id", "client_id"],
            ["cloud_connections.id", "cloud_connections.client_id"],
            name=op.f("fk_assessments_connection_id_client_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assessments")),
        sa.UniqueConstraint("id", "client_id", name=op.f("uq_assessments_id_client_id")),
    )
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "completed",
                "failed",
                name="scan_status",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "provider",
            sa.Enum(
                "aws",
                "azure",
                name="provider",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column(
            "regions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "result",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.Column("result_sha256", sa.String(length=64), nullable=False),
        sa.CheckConstraint(
            "length(result_sha256) = 64", name=op.f("ck_scan_runs_scan_result_hash_length")
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            name=op.f("fk_scan_runs_assessment_id_client_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_runs")),
        sa.UniqueConstraint("id", "client_id", name=op.f("uq_scan_runs_id_client_id")),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("scan_run_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column(
            "severity",
            sa.Enum(
                "critical",
                "high",
                "medium",
                "low",
                "informational",
                name="severity",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "category",
            sa.Enum(
                "identity_access",
                "network",
                "storage",
                "exposure",
                "logging_monitoring",
                name="category",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column(
            "provider",
            sa.Enum(
                "aws",
                "azure",
                name="provider",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("account_id", sa.String(length=64), nullable=False),
        sa.Column("region", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=2048), nullable=True),
        sa.Column("resource_name", sa.String(length=512), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_run_id", "client_id"],
            ["scan_runs.id", "scan_runs.client_id"],
            name=op.f("fk_findings_scan_run_id_client_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "scan_run_id", "fingerprint", name=op.f("uq_findings_scan_run_id_fingerprint")
        ),
    )
    op.create_index(
        "ix_findings_client_severity", "findings", ["client_id", "severity"], unique=False
    )

    # Stored results are evidence: refuse any UPDATE at the database level, whatever
    # the application does. DELETE stays possible (data retention, client offboarding).
    op.execute(
        """
        CREATE FUNCTION refuse_update_of_stored_results() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'stored scan results are immutable (table %)', TG_TABLE_NAME;
        END;
        $$
        """
    )
    for table in ("scan_runs", "findings"):
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION refuse_update_of_stored_results()"
        )


def downgrade() -> None:
    for table in ("scan_runs", "findings"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_immutable ON {table}")
    op.execute("DROP FUNCTION IF EXISTS refuse_update_of_stored_results()")
    op.drop_index("ix_findings_client_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_table("scan_runs")
    op.drop_table("assessments")
    op.drop_table("cloud_connections")
    op.drop_table("clients")
