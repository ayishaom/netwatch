import sqlite3

def connect_database():
    connection = sqlite3.connect("data/netwatch.db")
    return connection

def create_table():
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS network_observations(
                   id INTEGER PRIMARY KEY, timestamp REAL, source_ip TEXT
                   , destination_ip TEXT, protocol TEXT
                   , source_port INTEGER, destination_port INTEGER
                   , packet_size INTEGER, tcp_flags TEXT
                    )''')
    
    connection.commit()
    connection.close()

def save_observation(
        timestamp,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        tcp_flags,
):
    connection = connect_database()
    cursor = connection.cursor()


    cursor.execute(
    "INSERT INTO network_observations (timestamp, source_ip, destination_ip, protocol, source_port, "
    "destination_port, packet_size, tcp_flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    (
        timestamp,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        tcp_flags,
    )
)

    connection.commit()
    connection.close()

