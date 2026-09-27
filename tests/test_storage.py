import sqlite3

import netwatch.storage as storage 


def test_clear_observations(tmp_path, monkeypatch):
    db_path = tmp_path / "test_storage.db"

    def test_connect():
        return sqlite3.connect(db_path)
    monkeypatch.setattr(storage, "connect_database", test_connect)

    storage.create_table()
    connection = storage.connect_database()


    storage.save_observation(
        connection,
        1000.0,
        "10.0.0.1",
        "10.0.0.2",
        "TCP",
        50000,
        443,
        100,
        "S"
    )

    connection.commit()

    cursor = connection.cursor()

    cursor.execute(""" 
        SELECT COUNT(*)
        FROM network_observations;""")


    count = cursor.fetchone()[0]

    assert count == 1

    storage.clear_observations()

    cursor.execute(""" 
        SELECT COUNT(*)
        FROM network_observations;""")

    count = cursor.fetchone()[0]

    assert count == 0


    