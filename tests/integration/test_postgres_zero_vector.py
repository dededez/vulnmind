"""Check local pgvector cosine behavior against a dedicated test database."""
import math
import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url


@pytest.mark.skipif(not os.getenv("VULNMIND_TEST_DATABASE_URL"), reason="dedicated PostgreSQL test database not configured")
def test_zero_vector_cosine_distance_is_not_a_finite_score():
    url = make_url(os.environ["VULNMIND_TEST_DATABASE_URL"])
    if url.get_backend_name() != "postgresql":
        pytest.fail("VULNMIND_TEST_DATABASE_URL must be PostgreSQL")
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            value = connection.execute(text("SELECT '[0,0]'::vector <=> '[1,0]'::vector")).scalar_one()
            oversized = connection.execute(text("SELECT '[1e20,0]'::vector <=> '[1e20,0]'::vector")).scalar_one()
        assert value is not None and math.isnan(value)
        assert oversized is not None and math.isnan(oversized)
    finally:
        engine.dispose()
