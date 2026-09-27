import sqlite3

import netwatch.collector as collector


def test_collector_rolls_back_on_import_failure(tmp_path, monkeypatch):
    db_path = tmp_path / "test_collector.db"

    # Create a temporary database with one existing observation.
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

    # Make the collector use the temporary database.
    def test_connect():
        return sqlite3.connect(db_path)

    monkeypatch.setattr(
        collector,
        "connect_database",
        test_connect,
    )

    # The temporary table already exists.
    monkeypatch.setattr(
        collector,
        "create_table",
        lambda: None,
    )

    # Pretend a capture was successfully read.
    monkeypatch.setattr(
        collector,
        "read_capture",
        lambda filename: ["fake_packet"],
    )

    # Simulate a failure while processing the capture.
    def failing_parser(packet):
        raise RuntimeError("Simulated packet parsing failure")

    monkeypatch.setattr(
        collector,
        "parse_packets",
        failing_parser,
    )

    # Attempt the import.
    result = collector.import_capture(
        "fake_capture.pcapng"
    )

    # The collector should report that the import failed.
    assert result is False

    # The rollback should preserve the original observation.
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM network_observations;
    """)

    count = cursor.fetchone()[0]
    connection.close()

    assert count == 1


def test_collector_commits_successful_import(tmp_path, monkeypatch):
    db_path = tmp_path / "test_collector_success.db"

    # Create a temporary database with one old observation.
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
        "192.168.1.1",
        "192.168.1.2",
        "TCP",
        50000,
        443,
        100,
        "S",
    ))

    connection.commit()
    connection.close()

    # Make the collector use the temporary database.
    def test_connect():
        return sqlite3.connect(db_path)

    monkeypatch.setattr(
        collector,
        "connect_database",
        test_connect,
    )

    # The temporary table already exists.
    monkeypatch.setattr(
        collector,
        "create_table",
        lambda: None,
    )

    # Pretend the capture contains two packets.
    fake_packets = [
        "fake_packet_1",
        "fake_packet_2",
    ]

    monkeypatch.setattr(
        collector,
        "read_capture",
        lambda filename: fake_packets,
    )

    # Return predictable parsed observations.
    parsed_packets = {
        "fake_packet_1": (
            2000.0,
            "10.0.0.1",
            "10.0.0.2",
            "TCP",
            51000,
            80,
            150,
            "S",
        ),
        "fake_packet_2": (
            2001.0,
            "10.0.0.2",
            "10.0.0.1",
            "TCP",
            80,
            51000,
            200,
            "SA",
        ),
    }

    monkeypatch.setattr(
        collector,
        "parse_packets",
        lambda packet: parsed_packets[packet],
    )

    # Import the fake capture.
    result = collector.import_capture(
        "fake_capture.pcapng"
    )

    assert result is True

    # Verify that the old data was replaced and
    # the new observations were committed.
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            timestamp,
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            packet_size,
            tcp_flags
        FROM network_observations
        ORDER BY timestamp;
    """)

    observations = cursor.fetchall()
    connection.close()

    assert observations == [
        (
            2000.0,
            "10.0.0.1",
            "10.0.0.2",
            "TCP",
            51000,
            80,
            150,
            "S",
        ),
        (
            2001.0,
            "10.0.0.2",
            "10.0.0.1",
            "TCP",
            80,
            51000,
            200,
            "SA",
        ),
    ]