"""${message}
"""
from alembic import op
import sqlalchemy as sa
${up_revision if up_revision else ""}
${down_revision if down_revision else ""}

def upgrade():
    ${upgrades if upgrades else "pass"}

def downgrade():
    ${downgrades if downgrades else "pass"}
