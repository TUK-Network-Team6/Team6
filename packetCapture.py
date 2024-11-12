from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
    if packet.haslayer(TCP):
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        print(f"Sequence Number: {packet[TCP].seq}")
        print(f"Acknowledgement Number: {packet[TCP].ack}")
    if packet.haslayer(UDP):
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")

sniff(iface="en0", prn=packet_callback, store=0)
