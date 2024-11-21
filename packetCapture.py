from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, conf
from utils import save_to_json, save_to_csv
from datetime import datetime

# DNS 쿼리 타입 매핑
DNS_QUERY_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    252: "AXFR",
    255: "ANY"
}

# 콜백 함수 - 패킷 정보 추출 및 실시간 출력
def packet_callback(packet):
    packet_data = {}

    # 현재 날짜와 시간 추가
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    packet_data['timestamp'] = timestamp

    if packet.haslayer(IP):
        packet_data['protocol'] = 'IP'
        packet_data['src_ip'] = packet[IP].src
        packet_data['dst_ip'] = packet[IP].dst

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags & 0x02:  # SYN 플래그
            packet_data['tcp_flags'] = 'SYN'
        elif flags & 0x12:  # SYN-ACK 플래그
            packet_data['tcp_flags'] = 'SYN-ACK'
        elif flags & 0x10:  # ACK 플래그
            packet_data['tcp_flags'] = 'ACK'

        packet_data['protocol'] = 'TCP'
        packet_data['src_port'] = packet[TCP].sport
        packet_data['dst_port'] = packet[TCP].dport
        packet_data['seq'] = packet[TCP].seq
        packet_data['ack'] = packet[TCP].ack

        if packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode(errors='ignore')
            if 'HTTP' in raw_data:
                print("[INFO] HTTP Packet Detected")
                packet_data['http_data'] = raw_data
                if raw_data.startswith(('GET', 'POST')):
                    try:
                        request_line = raw_data.splitlines()[0]
                        method, path, version = request_line.split()
                        packet_data['http_method'] = method
                        packet_data['http_path'] = path
                        packet_data['http_version'] = version
                    except ValueError as e:
                        print(f"[ERROR] Parsing HTTP Request Line Failed: {e}")

            # HTTP 응답 상태 추출
            if 'HTTP/' in raw_data:
                try:
                    status_line = raw_data.splitlines()[0]
                    if status_line.startswith('HTTP/'):
                        packet_data['http_status'] = status_line
                except IndexError:
                    print("[DEBUG] HTTP Status Line Parsing Failed")

    if packet.haslayer(UDP):
        packet_data['protocol'] = 'UDP'
        packet_data['src_port'] = packet[UDP].sport
        packet_data['dst_port'] = packet[UDP].dport

        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            packet_data['sub_protocol'] = 'DNS'
            if packet.haslayer(DNS):
                try:
                    dns_query = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else "Unknown"
                    dns_query_type = packet[DNS].qd.qtype if packet[DNS].qd else "Unknown"
                    query_type_name = DNS_QUERY_TYPES.get(dns_query_type, "Unknown")
                    packet_data['dns_query'] = dns_query
                    packet_data['dns_query_type'] = query_type_name
                except Exception as e:
                    print(f"[ERROR] DNS Parsing Failed: {e}")

    return packet_data

# 패킷 캡처 함수
def capture_packets(interface=None):
    packets = []

    if interface is None:
        interface = conf.iface

    print(f"[INFO] Capturing packets on interface: {interface}")

    def packet_handler(packet):
        packet_data = packet_callback(packet)
        if packet_data:  # 패킷 데이터가 비어있지 않으면 저장
            packets.append(packet_data)

    try:
        sniff(iface=interface, prn=packet_handler, store=0)
    except KeyboardInterrupt:
        print("\n[INFO] Packet capture stopped by user.")
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")

    # JSON과 CSV 파일로 저장
    if packets:
        save_to_json(packets, filename='captured_packets/captured_packets.json')
        save_to_csv(packets, filename='captured_packets/captured_packets.csv')
        print("[INFO] Packets saved successfully.")
    else:
        print("[WARNING] No packets captured.")

if __name__ == "__main__":
    capture_packets()
