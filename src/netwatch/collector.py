from scapy.all import rdpcap, IP, TCP, UDP
import os

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

packets= read_pcapng(filename)
if packets is not None: 
    packet = packets[2]


    print(packet.haslayer(TCP))
    print(packet.haslayer(IP))
    print(packet.haslayer(UDP))
