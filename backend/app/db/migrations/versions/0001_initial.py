"""Initial schema is generated from the SQLAlchemy metadata."""

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    from app.db.session import Base, engine

    Base.metadata.create_all(engine)


def downgrade():
    from app.db.session import Base, engine

    Base.metadata.drop_all(engine)
