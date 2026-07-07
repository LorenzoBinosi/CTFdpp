"""CTFd++ 1.0.0 initial schema

Baseline migration for CTFd++ 1.0.0. The inherited CTFd migration history has
been collapsed into this single revision, which builds the current schema
directly from the SQLAlchemy models via ``create_all`` -- the same path CTFd
already uses on SQLite. Because the schema is created in its final form there
is no add-then-drop churn (e.g. the removed MajorLeagueCyber ``oauth_id``
columns are simply never created).

Future CTFd++ releases add their migrations on top of this baseline.

Revision ID: ctfdpp_1_0_0
Revises:
Create Date: 2026-07-06 00:00:00.000000

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "ctfdpp_1_0_0"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # The models (including the built-in challenge/flag types) are imported by
    # create_app() before migrations run, so db.metadata is fully populated.
    from CTFdpp.models import db

    db.metadata.create_all(bind=op.get_bind())


def downgrade():
    from CTFdpp.models import db

    db.metadata.drop_all(bind=op.get_bind())
