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


def detect_excessive_syn(threshold, window_seconds=10):
    connection = connect_database()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            source_ip,
            destination_ip,
            MAX(syn_count) AS syn_count
        FROM (
            SELECT
                a.source_ip AS source_ip,
                a.destination_ip AS destination_ip,
                COUNT(*) AS syn_count
            FROM network_observations AS a
            JOIN network_observations AS b
                ON a.source_ip = b.source_ip
                AND a.destination_ip = b.destination_ip
                AND b.timestamp >= a.timestamp
                AND b.timestamp <= a.timestamp + ?
            WHERE a.protocol = 'TCP'
                AND a.tcp_flags = 'S'
                AND b.protocol = 'TCP'
                AND b.tcp_flags = 'S'
            GROUP BY
                a.source_ip,
                a.destination_ip,
                a.timestamp
        )
        GROUP BY
            source_ip,
            destination_ip
        HAVING MAX(syn_count) > ?
        ORDER BY
            syn_count DESC,
            source_ip ASC;
    """, (window_seconds, threshold))

    results = cursor.fetchall()
    connection.close()

    return results



