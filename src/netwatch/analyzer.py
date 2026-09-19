

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


