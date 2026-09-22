import sqlite3

import netwatch.analyzer as analyzer


def create_test_database(tmp_path):
    db_path = tmp_path / "test_netwatch.db"

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

    test_packets = [
        (1.0, "10.0.0.1", "10.0.0.2", "TCP", 5000, 443, 100, "S"),
        (2.0, "10.0.0.1", "10.0.0.2", "TCP", 5000, 443, 200, "A"),
        (3.0, "10.0.0.2", "10.0.0.1", "TCP", 443, 5000, 150, "A"),
        (4.0, "10.0.0.3", "10.0.0.1", "UDP", 5300, 53, 50, None),
    ]

    cursor.executemany("""
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
    """, test_packets)

    connection.commit()
    connection.close()

    return db_path


def test_traffic_summary(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        analyzer,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    result = analyzer.get_traffic_summary()

    assert result == (4, 500, 3, 2)

def test_flow_count(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        analyzer,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    result = analyzer.get_flow_count()

    assert result == 3


def test_network_flow_aggregation(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        analyzer,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    flows = analyzer.get_network_flows(1)

    assert len(flows) == 1

    flow = flows[0]

    assert flow == (
        "10.0.0.1",
        "10.0.0.2",
        5000,
        443,
        "TCP",
        2,
        300,
        1.0,
        2.0,
        1.0,
    )