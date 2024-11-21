import json
from datetime import datetime

# JSON 파일에서 패킷 로드
def load_json(filename='captured_packets/captured_packets.json'):
    try:
        with open(filename, 'r') as json_file:
            return json.load(json_file)
    except FileNotFoundError:
        print(f"[ERROR] File {filename} not found.")
        return []
    except json.JSONDecodeError:
        print(f"[ERROR] Failed to decode JSON from {filename}.")
        return []

# HTTP 응답 시간 계산
def calculate_http_response_times(packet_log):
    request_times = {}
    response_times = []

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'TCP' and 'http_method' in packet:
            # HTTP 요청 기록
            seq = packet.get('seq')
            if seq:
                request_times[seq] = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')

        elif protocol == 'TCP' and 'http_data' in packet and 'HTTP' in packet['http_data']:
            # HTTP 응답 기록
            ack = packet.get('ack')
            if ack in request_times:
                response_time = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S') - request_times[ack]
                response_times.append(response_time.total_seconds())

    # 평균 응답 시간 계산
    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    return avg_response_time, response_times

# TCP 연결 성공률 계산
def calculate_tcp_success_rate(packet_log):
    syn_count = 0
    syn_ack_count = 0

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'TCP':
            flags = packet.get('tcp_flags', '').split(', ')

            # SYN 요청 카운트
            if 'SYN' in flags and 'ACK' not in flags:
                syn_count += 1
            
            # SYN-ACK 응답 카운트
            if 'SYN' in flags and 'ACK' in flags:
                syn_ack_count += 1

    # 연결 성공률 계산
    print(syn_ack_count, syn_count)
    success_rate = (syn_ack_count / syn_count) * 100 if syn_count > 0 else 0
    return round(success_rate, 2), syn_count, syn_ack_count

# TCP 지연 시간 계산
def calculate_tcp_delays(packet_log):
    syn_times = {}
    delays = []

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'TCP':
            flags = packet.get('tcp_flags', '')
            if 'SYN' in flags:
                seq = packet.get('seq')
                if seq:
                    syn_times[seq] = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
            elif 'SYN-ACK' in flags:
                ack = packet.get('ack')
                if ack in syn_times:
                    delay = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S') - syn_times[ack]
                    delays.append(delay.total_seconds())

    avg_delay = sum(delays) / len(delays) if delays else 0
    return avg_delay, delays

# UDP 응답 시간 계산
def calculate_udp_response_times(packet_log):
    request_times = {}
    response_times = []

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'UDP':
            if packet.get('dst_port') == 53:  # DNS 요청
                request_times[packet.get('src_port')] = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')
            elif packet.get('src_port') == 53:  # DNS 응답
                response_time = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S') - request_times.get(packet.get('dst_port'), datetime.min)
                response_times.append(response_time.total_seconds())

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    return avg_response_time, response_times

# 패킷 분석 실행
def analyze_packets():
    print("[INFO] Loading packets...")
    packets = load_json()

    if not packets:
        print("[ERROR] No packets to analyze.")
        return

    print("[INFO] Analyzing performance metrics...")

    # HTTP 응답 시간
    avg_http_time, _ = calculate_http_response_times(packets)
    print(f"Average HTTP Response Time: {avg_http_time:.2f} seconds")

    # TCP 연결 성공률
    tcp_success_rate, total_syn, total_ack = calculate_tcp_success_rate(packets)
    print(f"TCP Connection Success Rate: {tcp_success_rate:.2f}%")
    print(f"Total SYN Packets: {total_syn}, Total ACK Packets: {total_ack}")

    # TCP 지연 시간
    avg_tcp_delay, _ = calculate_tcp_delays(packets)
    print(f"Average TCP Delay: {avg_tcp_delay:.2f} seconds")

    # UDP 응답 시간
    avg_udp_time, _ = calculate_udp_response_times(packets)
    print(f"Average UDP Response Time: {avg_udp_time:.2f} seconds")

if __name__ == "__main__":
    analyze_packets()
