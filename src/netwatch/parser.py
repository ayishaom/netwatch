from scapy.all import  IP, TCP, UDP, ICMP


# Handels one packet at a time. 
def parse_packets(packet):
    if not packet.haslayer(IP):
        return
    
     
    ip_layer = packet[IP]

    source_ip = ip_layer.src
    destination_ip = ip_layer.dst
    packet_size = len(packet)
    timestamp = float(packet.time)
    
    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flag = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        tcp_flag = None 
    
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        source_port = None
        destination_port = None
        tcp_flag = None
      
    else:
        protocol = "OTHER"
        source_port = None 
        destination_port = None
        tcp_flag = None

    return (
        timestamp,
        source_ip, 
        destination_ip,
        protocol,
        source_port,
        destination_port,
        packet_size,
        tcp_flag,
            )

