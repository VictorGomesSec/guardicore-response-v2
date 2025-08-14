import os
from pathlib import Path
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

default_db_path = Path(__file__).resolve().parents[2] / "ioc.db"
db_path = os.getenv("IOC_DB_PATH", default_db_path)
# print(db_path)
engine = create_engine(f"sqlite:///{db_path}")

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        yield db.close()


@contextmanager
def get_db_manager():
    db = SessionLocal()
    yield db
    db.close()
