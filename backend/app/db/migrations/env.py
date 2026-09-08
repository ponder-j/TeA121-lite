"""Minimal Alembic environment; runtime startup also supports create_all for demos."""

from app.db import models  # noqa: F401
from app.db.session import Base, engine

target_metadata = Base.metadata


def run_migrations_online():
    from alembic import context

    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
