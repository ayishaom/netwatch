

from netwatch.storage import connect_database

def get_protocol_stats():
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("SELECT protocol, COUNT(*) " \
    "AS NumberOfProtocol " \
    "FROM network_observations GROUP BY protocol;")

    results = cursor.fetchall()


    connection.close()

    return results

def get_top_source_hosts(limit):
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("SELECT source_ip," \
    " COUNT(*) AS packet_count FROM network_observations " \
    "GROUP BY source_ip ORDER BY packet_count DESC LIMIT ?", (limit,))

    results = cursor.fetchall()

    connection.close()

    return results

def get_top_sources_by_bytes(limit):
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("SELECT source_ip, SUM(packet_size) " \
    "AS total_bytes FROM network_observations" \
    " GROUP BY source_ip ORDER BY total_bytes DESC LIMIT ?",  (limit, ))

    results = cursor.fetchall()

    connection.close()

    return results 


def get_network_flows(limit):
    connection = connect_database()
    cursor = connection.cursor()
    
    cursor.execute("SELECT source_ip, destination_ip, source_port," \
    " destination_port, protocol, COUNT(*) " \
    "AS packet_count, SUM(packet_size) " \
    "AS total_bytes," \
    "MIN(timestamp) AS start_time, " \
    "MAX(timestamp) AS end_time, " \
    "MAX(timestamp) - MIN(timestamp) AS duration " \
    "FROM network_observations " \
    "GROUP BY source_ip, destination_ip, source_port, " \
    "destination_port, protocol ORDER BY total_bytes DESC LIMIT ? ", (limit, ))


    results = cursor.fetchall()
    connection.close()
    return results

def get_traffic_summary():
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("SELECT COUNT(*) AS packet_count, " \
    "SUM(packet_size) AS total_bytes, " \
    "COUNT(DISTINCT source_ip) AS unique_sources, " \
    "COUNT(DISTINCT destination_ip) AS unique_destinations " \
    "FROM network_observations")

    results = cursor.fetchone()
    connection.close()
    return results



def get_flow_count():
    connection = connect_database()
    cursor = connection.cursor()
    
    cursor.execute(""" SELECT COUNT(*)
FROM (
    SELECT
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
    FROM network_observations
    GROUP BY
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        protocol
);""")

    results = cursor.fetchone()
    connection.close()
    return results[0]
