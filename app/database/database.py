"""
SQLAlchemy Database Configuration & RLS Context Binding
Uses ContextVar to pass request-scoped tenant_id into PostgreSQL session variables.
"""
import os
from urllib.parse import quote_plus
from contextvars import ContextVar
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase, Session

tenant_context: ContextVar[str] = ContextVar("tenant_context", default="")

DB_USER = os.getenv("POSTGRES_USER", "app_user")
DB_PASS = os.getenv("POSTGRES_PASSWORD")

if not DB_PASS and not os.getenv("DATABASE_URL"):
    raise RuntimeError("CRITICAL: Database password or DATABASE_URL must be provided.")

DB_HOST = os.getenv("POSTGRES_HOST", "db")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")
DB_NAME = os.getenv("POSTGRES_DB", "zerotrust_api_db")

if DB_PASS:
    user_info = f"{quote_plus(DB_USER)}:{quote_plus(DB_PASS)}"
else:
    user_info = f"{quote_plus(DB_USER)}"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"postgresql://{user_info}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_recycle=1800
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db() -> Generator[Session, None, None]:
    """
    FastAPI Session Dependency.
    Binds the ContextVar tenant_id to PostgreSQL RLS session context,
    yields the session cleanly, and guarantees transaction teardown/cleanup.
    """
    db = SessionLocal()
    try:
        tenant_id = tenant_context.get()
        if tenant_id:
            db.execute(
                text("SELECT set_config('app.current_tenant', :tenant, true)"),
                {"tenant": tenant_id}
            )
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        try:
            db.execute(text("RESET app.current_tenant"))
        except Exception:
            pass
        db.close()
