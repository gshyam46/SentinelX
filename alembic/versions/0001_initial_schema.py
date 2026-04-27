"""Initial schema — users and scans tables

Revision ID: 0001
Revises:
Create Date: 2026-04-26
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("full_name", sa.String(255), nullable=True),
        sa.Column("tier", sa.String(20), nullable=False, server_default="free"),
        sa.Column("scan_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("is_active", sa.Boolean(), nullable=True, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("scan_type", sa.String(20), nullable=False, server_default="passive"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("progress", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("current_step", sa.String(200), nullable=True),
        sa.Column("results", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("high_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("info_count", sa.Integer(), nullable=True, server_default="0"),
        sa.Column("risk_score", sa.Float(), nullable=True, server_default="0.0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "authorization_confirmed",
            sa.Boolean(),
            nullable=True,
            server_default="false",
        ),
        sa.Column(
            "analyst_iteration",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=True,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])
    op.create_index("ix_scans_domain", "scans", ["domain"])


def downgrade() -> None:
    op.drop_index("ix_scans_domain", table_name="scans")
    op.drop_index("ix_scans_user_id", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
