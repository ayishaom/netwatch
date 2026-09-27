import sqlite3

import netwatch.collector as collector


def test_collector_rolls_back_on_import_failure(tmp_path, monkeypatch):
    db_path = tmp_path / "test_collector.db"


    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE network_observations (
            id INTEGER PRIMARY KEY,
            timestamp REAL,
            source_ip TEXT,
            destination_ip TEXT,
            protocol TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            packet_size INTEGER,
            tcp_flags TEXT
        );
    """)

    cursor.execute("""
        INSERT INTO network_observations (
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        1000.0,
        "10.0.0.1",
        "10.0.0.2",
        "TCP",
        50000,
        443,
        100,
        "S",
    ))

    connection.commit()
    connection.close()

    # Make the collector use our temporary database.
    def test_connect():
        return sqlite3.connect(db_path)

    monkeypatch.setattr(collector, "connect_database", test_connect)

    monkeypatch.setattr(collector, "create_table", lambda: None)


    monkeypatch.setattr(
        collector,
        "read_pcapng",
        lambda filename: ["fake_packet"],
    )


    def failing_parser(packet):
        raise RuntimeError("Simulated packet parsing failure")

    monkeypatch.setattr(collector, "parse_packets", failing_parser)


    collector.main()


    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM network_observations;
    """)

    count = cursor.fetchone()[0]
    connection.close()

    assert count == 1