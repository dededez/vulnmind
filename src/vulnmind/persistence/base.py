"""Database interface foundation; no automatic connection or schema creation."""
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
