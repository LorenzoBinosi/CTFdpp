"""Create dynamic_challenge table

Folds the former CTFd/plugins/dynamic_challenges plugin migrations into the main
migration history now that the dynamic challenge type lives in core
(CTFd/challenges/dynamic.py). On SQLite the table is created by create_all(); on
MySQL/Postgres this migration creates it.

Revision ID: d3f9a1c2e5b7
Revises: c12d4a5e7b91
Create Date: 2026-06-22 00:00:00.000000

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = "d3f9a1c2e5b7"
down_revision = "c12d4a5e7b91"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    # Skip if the table already exists (e.g. a deployment that previously ran
    # the dynamic_challenges plugin migrations).
    if "dynamic_challenge" in inspect(bind).get_table_names():
        return

    op.create_table(
        "dynamic_challenge",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("dynamic_initial", sa.Integer(), nullable=True),
        sa.Column("dynamic_minimum", sa.Integer(), nullable=True),
        sa.Column("dynamic_decay", sa.Integer(), nullable=True),
        sa.Column("dynamic_function", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(["id"], ["challenges.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    bind = op.get_bind()
    if "dynamic_challenge" in inspect(bind).get_table_names():
        op.drop_table("dynamic_challenge")
