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


def detect_host_sweep(threshold):
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute(""" 
        SELECT 
           source_ip,
           COUNT(DISTINCT destination_ip) AS unique_hosts
        FROM network_observations
        WHERE protocol = 'TCP'
            AND tcp_flags = 'S'
        GROUP BY
            source_ip
        HAVING COUNT(DISTINCT destination_ip) > ?;    
        """, (threshold,))

    results = cursor.fetchall()

    connection.close()

    return results


def detect_high_volume_flow(byte_threshold):
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute(""" 
        SELECT 
           source_ip,
           destination_ip,
           source_port,
           destination_port,
           protocol,
           SUM(packet_size) AS total_bytes
        FROM network_observations
        GROUP BY
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        HAVING total_bytes >= ?;
           """, (byte_threshold,))

    results = cursor.fetchall()

    connection.close()

    return results 


if __name__ == "__main__":
    results = detect_port_scan(10)

    for result in results:
        print(result)

