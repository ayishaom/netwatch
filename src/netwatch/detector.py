from netwatch.storage import connect_database


def detect_port_scan(threshold):
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            COUNT(DISTINCT destination_port) AS unique_ports
        FROM network_observations
        WHERE protocol = 'TCP'
            AND tcp_flags = 'S'
        GROUP BY
            source_ip,
            destination_ip
        HAVING COUNT(DISTINCT destination_port) > ?;
    """, (threshold,))

    results = cursor.fetchall()
    connection.close()

    return results

if __name__ == "__main__":
    results = detect_port_scan(10)

    for result in results:
        print(result)