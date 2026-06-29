import pytest
from app import db


@pytest.fixture(autouse=True)
def temp_db(tmp_path):
    db.set_db_path(str(tmp_path / "test.db"))
    db.init_db()
    yield
