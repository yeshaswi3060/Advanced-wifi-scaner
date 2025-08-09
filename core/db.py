from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from config import DB_URL
import os
os.makedirs("data", exist_ok=True)
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base = declarative_base()

def init_db():
    from core import models  # noqa
    Base.metadata.create_all(bind=engine)
    # simple migrations for v2 (add domains table if missing)
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS domains(
            id INTEGER PRIMARY KEY,
            ip TEXT,
            domain TEXT,
            ts TEXT
        );
        """))
