from scapy.all import  IP ,TCP, UDP, ICMP, Ether
from netwatch.parser import parse_packets


def test_parser_tcp_packet():
    packet = IP(
         src = "10.0.0.1",
         dst = "20.0.0.1"
        ) / TCP(
             sport = 5000,
             dport = 443,
             flags = "S",
)
    source_ip = "10.0.0.1"
    destination_ip = "20.0.0.1"
    protocol = "TCP"
    source_port = 5000
    destination_port = 443
    packet_size = len(packet)
    tcp_flag = "S"

    result = parse_packets(packet)
    
    assert result[0] == packet.time
    assert result[1] == source_ip
    assert result[2] == destination_ip
    assert result[3] == protocol
    assert result[4] == source_port
    assert result[5] == destination_port
    assert result[6] == packet_size
    assert str(result[7]) == tcp_flag

def test_parser_udp_packet():
    packet = IP(
         src = "10.0.0.1",
         dst = "20.0.0.1"
        ) / UDP(
             sport = 5000,
             dport = 443,
             
) 
    source_ip = "10.0.0.1"
    destination_ip = "20.0.0.1"
    protocol = "UDP"
    source_port = 5000
    destination_port = 443
    packet_size = len(packet)
    tcp_flag = None

    result = parse_packets(packet)
    
    assert result[0] == packet.time
    assert result[1] == source_ip
    assert result[2] == destination_ip
    assert result[3] == protocol
    assert result[4] == source_port
    assert result[5] == destination_port
    assert result[6] == packet_size
    assert result[7] == tcp_flag

  

def test_parser_icmp_packet():
    packet = IP(
         src = "10.0.0.1",
         dst = "20.0.0.1"
        ) / ICMP()
    
    source_ip = "10.0.0.1"
    destination_ip = "20.0.0.1"
    protocol = "ICMP"
    source_port = None
    destination_port = None
    packet_size = len(packet)
    tcp_flag = None

    result = parse_packets(packet)
    
    assert result[0] == packet.time
    assert result[1] == source_ip
    assert result[2] == destination_ip
    assert result[3] == protocol
    assert result[4] == source_port
    assert result[5] == destination_port
    assert result[6] == packet_size
    assert result[7] == tcp_flag


def test_parser_non_ip_packets():
    packet = Ether()

    result = parse_packets(packet)

    assert result is None