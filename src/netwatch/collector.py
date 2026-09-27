import os

from scapy.all import rdpcap

from netwatch.parser import parse_packets
from netwatch.storage import (
    create_table, save_observation,
    connect_database, clear_observations
    )


filename = "data/sample.pcapng"


def read_capture(filename): 

    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' not found.")
        return 
    
    try:
        packets = rdpcap(filename) 
    except Exception as e:
        print(f"Error reading pcapng file: {e}")
        return 
    
    return packets

def import_capture(filename):
    packets = read_capture(filename)

    if packets is None:
        return False

    create_table()
    connection = connect_database()

    try:
        clear_observations(connection)

        for packet in packets:
            parsed = parse_packets(packet)

            if parsed is not None:
                save_observation(connection, *parsed)

        connection.commit()
        return True

    except Exception as e:
        connection.rollback()
        print(f"Error importing packets: {e}")
        return False

    finally:
        connection.close()


def main(): 
    import_capture(filename)


if __name__ == "__main__":
    main()

 

