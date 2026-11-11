"""Transaction boundaries without hidden commits in repositories."""
from collections.abc import Iterator
from contextlib import contextmanager
from sqlalchemy.orm import Session, sessionmaker


@contextmanager
def transaction(factory: sessionmaker[Session]) -> Iterator[Session]:
    with factory() as session:
        with session.begin():
            yield session
