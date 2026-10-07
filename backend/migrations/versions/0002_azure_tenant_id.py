"""Azure connections: store the client's tenant ID.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("cloud_connections", sa.Column("tenant_id", sa.String(length=36), nullable=True))
    # Written by hand: Alembic's autogenerate does not detect CHECK constraints.
    op.create_check_constraint(
        op.f("ck_cloud_connections_azure_requires_tenant"),
        "cloud_connections",
        "provider <> 'azure' OR tenant_id IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_cloud_connections_azure_requires_tenant"), "cloud_connections", type_="check"
    )
    op.drop_column("cloud_connections", "tenant_id")
