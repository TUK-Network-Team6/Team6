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
    print(f"Time: {timestamp}")

    if packet.haslayer(IP):
        print("[INFO] IP Packet Detected")
        packet_data['protocol'] = 'IP'
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_data['src_ip'] = src_ip
        packet_data['dst_ip'] = dst_ip
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")

    if packet.haslayer(TCP):
        print("[INFO] TCP Packet Detected")
        flags = packet[TCP].flags
        if flags & 0x02:  # SYN 플래그
            packet_data['tcp_flags'] = 'SYN'
        elif flags & 0x12:  # SYN-ACK 플래그
            packet_data['tcp_flags'] = 'SYN-ACK'
        elif flags & 0x10:  # ACK 플래그
            packet_data['tcp_flags'] = 'ACK'

        packet_data['protocol'] = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        seq = packet[TCP].seq
        ack = packet[TCP].ack
        packet_data['src_port'] = src_port
        packet_data['dst_port'] = dst_port
        packet_data['seq'] = seq
        packet_data['ack'] = ack

        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")
        print(f"Sequence Number: {seq}")
        print(f"Acknowledgement Number: {ack}")

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

                        print(f"[HTTP] Method: {method}")
                        print(f"[HTTP] Version: {version}")
                        print(f"[HTTP] Data (Filtered): {path}")

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


        # SMTP 데이터 분석
        if packet[TCP].dport in [25, 465, 587] or packet[TCP].sport in [25, 465, 587]:
            print("[INFO] SMTP Data Detected")
            packet_data['sub_protocol'] = 'SMTP'
            # SMTP 데이터 분석
            if packet.haslayer(Raw):
                smtp_data = packet[Raw].load.decode(errors='ignore').strip()  # SMTP 데이터 불러오기
                packet_data['smtp_data'] = smtp_data  # 원본 데이터 저장
                mail_from = None
                rcpt_to = None

                # SMTP 명령 분석
                lines = smtp_data.splitlines()  # 줄 단위로 분리
                for line in lines:
                    if line.startswith("MAIL FROM:"):
                        mail_from = line.split("MAIL FROM:", 1)[1].strip()
                        packet_data['smtp_mail_from'] = mail_from
                    elif line.startswith("RCPT TO:"):
                        rcpt_to = line.split("RCPT TO:", 1)[1].strip()
                        packet_data['smtp_rcpt_to'] = rcpt_to
                    else:
                        # 나머지 데이터 출력
                        print(f"[SMTP] Data: {line}")

    if packet.haslayer(UDP):
        print("[INFO] UDP Packet Detected")
        packet_data['protocol'] = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        packet_data['src_port'] = packet[UDP].sport
        packet_data['dst_port'] = packet[UDP].dport
        print(f"Source Port: {src_port}")
        print(f"Destination Port: {dst_port}")

        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            print("[INFO] DNS Data Detected")
            packet_data['sub_protocol'] = 'DNS'
            if packet.haslayer(DNS):
                try:
                    dns_query = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else "Unknown"
                    dns_query_type = packet[DNS].qd.qtype if packet[DNS].qd else "Unknown"
                    query_type_name = DNS_QUERY_TYPES.get(dns_query_type, "Unknown")
                    packet_data['dns_query'] = dns_query
                    packet_data['dns_query_type'] = query_type_name
                    print(f"[DNS] Query: {dns_query}")
                    print(f"[DNS] Query Type: {query_type_name}")
                except Exception as e:
                    print(f"[ERROR] DNS Parsing Failed: {e}")

    print("\n" + "-" * 50 + "\n")
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
        sniff(iface=interface, filter="", prn=packet_handler, store=False)
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
