

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


