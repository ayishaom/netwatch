import sqlite3

import netwatch.detector as detector


def create_test_database(tmp_path):
    db_path = tmp_path / "test_detector.db"

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

    scan_packets = [
                (1.0, "10.0.0.50", "10.0.0.100", "TCP", 50000, 21, 60, "S"),
                (2.0, "10.0.0.50", "10.0.0.100", "TCP", 50000, 22, 60, "S"),
                (3.0, "10.0.0.50", "10.0.0.100", "TCP", 50000, 23, 60, "S"),
                (4.0, "10.0.0.50", "10.0.0.100", "TCP", 50000, 80, 60, "S"),
                (5.0, "10.0.0.50", "10.0.0.100", "TCP", 50000, 443, 60, "S"),
                ]

    sweep_packets = [
                (1.0, "10.0.0.60", "10.0.0.100", "TCP", 50000, 443, 60, "S"),
                (2.0, "10.0.0.60", "10.0.0.101", "TCP", 50000, 443, 60, "S"),
                (3.0, "10.0.0.60", "10.0.0.102", "TCP", 50000, 443, 60, "S"),
                (4.0, "10.0.0.60", "10.0.0.103", "TCP", 50000, 443, 60, "S"),
                (5.0, "10.0.0.60", "10.0.0.105", "TCP", 50000, 443, 60, "S"),]

    high_volume_packets =[
                    (1.0, "10.0.0.70", "10.0.0.80", "TCP", 51000, 443, 400, "A"),
                    (2.0, "10.0.0.70", "10.0.0.80", "TCP", 51000, 443, 400, "A"),
                    (3.0, "10.0.0.70", "10.0.0.80", "TCP", 51000, 443, 400, "A"),]

    excessive_syn_packets = [
                    (1.0, "10.0.0.90", "10.0.0.100", "TCP", 52000, 80, 60, "S"),
                    (2.0, "10.0.0.90", "10.0.0.100", "TCP", 52000, 80, 60, "S"),
                    (3.0, "10.0.0.90", "10.0.0.100", "TCP", 52000, 80, 60, "S"),
                    (4.0, "10.0.0.90", "10.0.0.100", "TCP", 52000, 80, 60, "S"),
                    (5.0, "10.0.0.90", "10.0.0.100", "TCP", 52000, 80, 60, "S") ]

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
        """, scan_packets + sweep_packets + high_volume_packets + excessive_syn_packets)


    connection.commit()
    connection.close()

    return db_path

def test_detect_port_scan(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        detector,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    result = detector.detect_port_scan(3)
    assert result == [
        ("10.0.0.50", "10.0.0.100", 5)
    ]

def test_detect_host_sweep(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        detector,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    result = detector.detect_host_sweep(3)
    assert result == [
        ("10.0.0.60", 5)
    ]


def test_detect_high_volume_flow(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        detector,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    result = detector.detect_high_volume_flow(1000)
    assert result == [
        (
            "10.0.0.70",
            "10.0.0.80",
            51000,
            443,
            "TCP",
            1200
        )
    ]


def test_detect_excessive_syn(tmp_path, monkeypatch):
    db_path = create_test_database(tmp_path)

    monkeypatch.setattr(
        detector,
        "connect_database",
        lambda: sqlite3.connect(db_path)
    )

    result = detector.detect_excessive_syn(3)
    assert result == [
        ("10.0.0.50", "10.0.0.100", 5),
        ("10.0.0.90", "10.0.0.100", 5)
    ]
