import os

from scapy.all import rdpcap

from netwatch.parser import parse_packets
from netwatch.storage import (
    create_table, save_observation,
    connect_database, clear_observations
    )


filename = "data/sample.pcapng"


def read_pcapng(filename): 

    if not os.path.isfile(filename):
        print(f"Error: File '{filename}' not found.")
        return 
    
    try:
        packets = rdpcap(filename) 
    except Exception as e:
        print(f"Error reading pcapng file: {e}")
        return 
    
    return packets


def main(): 
    packets = read_pcapng(filename)
    if packets is None:
        return
    create_table()
    clear_observations()
    connection = connect_database()
    for packet in packets:
        parsed = parse_packets(packet)
        if parsed is not None:
            save_observation(connection, *parsed)
    connection.commit()

    connection.close()


if __name__ == "__main__":
    main()

 

