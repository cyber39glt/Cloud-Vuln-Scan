"""Scan job queue (M8).

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUSES = ("queued", "running", "succeeded", "failed")
_STAGES = ("waiting", "connecting", "collecting", "evaluating", "saving", "done")


def upgrade() -> None:
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.Uuid(), nullable=False),
        sa.Column("assessment_id", sa.Uuid(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                *_STATUSES, name="job_status", native_enum=False, create_constraint=True, length=32
            ),
            nullable=False,
        ),
        sa.Column(
            "stage",
            sa.Enum(
                *_STAGES, name="job_stage", native_enum=False, create_constraint=True, length=32
            ),
            nullable=False,
        ),
        sa.Column(
            "regions",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.String(length=1000), nullable=True),
        sa.Column("scan_run_id", sa.Uuid(), nullable=True),
        sa.CheckConstraint(
            "status <> 'succeeded' OR scan_run_id IS NOT NULL",
            name=op.f("ck_scan_jobs_succeeded_has_scan"),
        ),
        sa.ForeignKeyConstraint(
            ["assessment_id", "client_id"],
            ["assessments.id", "assessments.client_id"],
            name=op.f("fk_scan_jobs_assessment_id_client_id"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_run_id", "client_id"],
            ["scan_runs.id", "scan_runs.client_id"],
            name=op.f("fk_scan_jobs_scan_run_id_client_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_jobs")),
    )
    op.create_index(
        "uq_scan_jobs_one_active_per_assessment",
        "scan_jobs",
        ["assessment_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.create_index("ix_scan_jobs_queue", "scan_jobs", ["status", "requested_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_queue", table_name="scan_jobs")
    op.drop_index("uq_scan_jobs_one_active_per_assessment", table_name="scan_jobs")
    op.drop_table("scan_jobs")
