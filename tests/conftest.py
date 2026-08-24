import pytest

from src import database


@pytest.fixture()
def isolated_database(tmp_path, monkeypatch):
    database_path = tmp_path / "mini-soc-test.db"
    monkeypatch.setattr(database, "DATABASE_PATH", database_path)
    database.create_tables()
    return database_path
