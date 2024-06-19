from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        
        # Check if the packet has a TCP layer
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP, Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}")
            print(f"Payload: {str(bytes(packet[TCP].payload))}")
        
        # Check if the packet has a UDP layer
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP, Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}")
            print(f"Payload: {str(bytes(packet[UDP].payload))}")

# Use Layer 3 socket for sniffing
conf.L3socket = conf.L3socket

# Start sniffing the packets
print("Starting packet sniffer...")
sniff(prn=packet_callback, store=0)