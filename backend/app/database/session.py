from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    pass


settings.ensure_dirs()
engine = create_engine(settings.db_url, connect_args={"check_same_thread": False}, future=True)


@event.listens_for(engine, "connect")
def _fk_on(dbapi_conn, _):  # SQLite needs foreign keys switched on per connection
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app.models import tables  # noqa: F401  (register models)

    Base.metadata.create_all(engine)
