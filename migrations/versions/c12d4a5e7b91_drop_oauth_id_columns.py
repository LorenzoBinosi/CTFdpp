"""Drop oauth_id columns from users and teams

Removes the MajorLeagueCyber OAuth integration columns.

Revision ID: c12d4a5e7b91
Revises: 48d8250d19bd
Create Date: 2026-06-22 00:00:00.000000

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c12d4a5e7b91"
down_revision = "48d8250d19bd"
branch_labels = None
depends_on = None


def upgrade():
    # batch_alter_table keeps this portable across SQLite (which cannot drop a
    # column referenced by an index without recreating the table) and
    # MySQL/Postgres (which emit a direct ALTER).
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("oauth_id")
    with op.batch_alter_table("teams") as batch_op:
        batch_op.drop_column("oauth_id")


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(sa.Column("oauth_id", sa.Integer(), nullable=True))
        batch_op.create_unique_constraint("uq_users_oauth_id", ["oauth_id"])
    with op.batch_alter_table("teams") as batch_op:
        batch_op.add_column(sa.Column("oauth_id", sa.Integer(), nullable=True))
        batch_op.create_unique_constraint("uq_teams_oauth_id", ["oauth_id"])
