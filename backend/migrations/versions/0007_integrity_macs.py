"""Keyed integrity signatures on stored scans and finalized reports (ADR 0026).

Adds result_mac / report_mac: HMAC-SHA256 with a key derived from APP_SECRET_KEY over
each record's identity and content hash. Existing rows are signed here; the
"immutable" triggers are suspended for this one UPDATE (migrations run as the table
owner, which the application login is not).

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.storage.repository import integrity_mac

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_runs", sa.Column("result_mac", sa.String(length=64), nullable=True))
    op.add_column(
        "assessment_finalizations", sa.Column("report_mac", sa.String(length=64), nullable=True)
    )
    conn = op.get_bind()

    op.execute("ALTER TABLE scan_runs DISABLE TRIGGER scan_runs_immutable")
    for scan_id, client_id, digest in conn.execute(
        sa.text("SELECT id, client_id, result_sha256 FROM scan_runs")
    ):
        conn.execute(
            sa.text("UPDATE scan_runs SET result_mac = :mac WHERE id = :id"),
            {"mac": integrity_mac("scan_run", scan_id, client_id, digest), "id": scan_id},
        )
    op.execute("ALTER TABLE scan_runs ENABLE TRIGGER scan_runs_immutable")

    op.execute(
        "ALTER TABLE assessment_finalizations DISABLE TRIGGER assessment_finalizations_immutable"
    )
    rows = conn.execute(
        sa.text(
            "SELECT id, client_id, assessment_id, scan_run_id, report_sha256 "
            "FROM assessment_finalizations"
        )
    )
    for final_id, client_id, assessment_id, scan_run_id, digest in rows:
        mac = integrity_mac("finalization", final_id, client_id, assessment_id, scan_run_id, digest)
        conn.execute(
            sa.text("UPDATE assessment_finalizations SET report_mac = :mac WHERE id = :id"),
            {"mac": mac, "id": final_id},
        )
    op.execute(
        "ALTER TABLE assessment_finalizations ENABLE TRIGGER assessment_finalizations_immutable"
    )

    op.alter_column("scan_runs", "result_mac", nullable=False)
    op.alter_column("assessment_finalizations", "report_mac", nullable=False)
    op.create_check_constraint(
        op.f("ck_scan_runs_scan_result_mac_length"), "scan_runs", "length(result_mac) = 64"
    )
    op.create_check_constraint(
        op.f("ck_assessment_finalizations_final_report_mac_length"),
        "assessment_finalizations",
        "length(report_mac) = 64",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_assessment_finalizations_final_report_mac_length"),
        "assessment_finalizations",
        type_="check",
    )
    op.drop_constraint(op.f("ck_scan_runs_scan_result_mac_length"), "scan_runs", type_="check")
    op.drop_column("assessment_finalizations", "report_mac")
    op.drop_column("scan_runs", "result_mac")
