from collections.abc import Generator

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, future=True)
if settings.database_url.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def _foreign_keys(dbapi_connection, _):
        dbapi_connection.execute("PRAGMA foreign_keys=ON")


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.db import models  # noqa: F401

    Base.metadata.create_all(engine)
    # ``create_all`` deliberately does not alter an existing development DB.
    # Add the one additive column needed by the richer CFG response so users
    # upgrading an existing checkout do not need to delete their data.
    columns = {column["name"] for column in inspect(engine).get_columns("cfg_nodes")}
    if "metadata_json" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE cfg_nodes ADD COLUMN metadata_json TEXT DEFAULT '{}'"))
