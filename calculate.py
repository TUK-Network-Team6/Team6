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
    request_times = {}  # 요청 시각 저장 {key: timestamp}
    response_times = []  # 응답 시간 저장

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'TCP':
            if 'http_method' in packet: # HTTP 요청
                seq = packet.get('seq')
                if seq:
                    request_key = (packet['src_ip'], packet['dst_ip'], packet['src_port'], packet['dst_port'], seq)
                    request_times[request_key] = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S')

            elif 'http_status' in packet:  # HTTP 응답
                ack = packet.get('ack')
                if ack:
                    response_key = (packet['dst_ip'], packet['src_ip'], packet['dst_port'], packet['src_port'], ack)

                    for response_key in request_times:
                        if (
                            response_key[:4] == request_key[:4] and  # src/dst IP와 Port가 일치
                            abs(response_key[4] - request_key[4]) <= 100  # seq와 ack 간 오차 허용
                        ):
                            response_time = datetime.strptime(packet.get('timestamp', ''), '%Y-%m-%d %H:%M:%S') - request_times[response_key]
                            response_times.append(response_time.total_seconds())
                            break

    avg_response_time = sum(response_times) / len(response_times) if response_times else 0

    return avg_response_time, response_times

# TCP 연결 성공률 계산
def calculate_tcp_success_rate(packet_log):
    syn_packets = set()  # SYN 요청 추적
    ack_packets = set()  # ACK 응답 추적

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'TCP':
            flags = packet.get('tcp_flags', [])
            if isinstance(flags, str):
                flags = flags.split(', ')  # 문자열 처리

            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            src_port = packet.get('src_port')
            dst_port = packet.get('dst_port')

            # SYN 요청 추적
            if 'SYN' in flags and 'ACK' not in flags:
                syn_packets.add((src_ip, dst_ip, src_port, dst_port))

            # ACK 응답 추적
            if 'ACK' in flags and 'SYN' not in flags:
                ack_packets.add((dst_ip, src_ip, dst_port, src_port))  # 반대 방향 매핑

    # 성공적으로 매핑된 ACK 응답
    matched_acks = len(syn_packets.intersection(ack_packets))
    syn_count = len(syn_packets)

    # TCP 성공률 계산
    success_rate = (matched_acks / syn_count) * 100 if syn_count > 0 else 0

    return round(success_rate, 2), syn_count, matched_acks

# TCP 지연 시간 계산
def calculate_tcp_delays(packet_log):
    syn_times = {}
    delays = []

    for packet in packet_log:
        protocol = packet.get('protocol')
        if protocol == 'TCP':
            flags = packet.get('tcp_flags', [])
            if isinstance(flags, str):
                flags = flags.split(', ')

            seq = packet.get('seq')
            if 'SYN' in flags and seq:
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
        timestamp = packet.get('timestamp', '')

        try:
            packet_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')  # 밀리초 포함 파싱
        except ValueError:
            packet_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')  # 초 단위 파싱

        if protocol == 'UDP':
            if packet.get('dst_port') == 53:  # DNS 요청
                request_times[packet.get('src_port')] = packet_time
            elif packet.get('src_port') == 53:  # DNS 응답
                request_time = request_times.get(packet.get('dst_port'))
                if request_time:
                    response_time = packet_time - request_time
                    response_times.append(response_time.total_seconds())
                else:
                    print(f"[DEBUG] No matching request for response: {packet}")

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
    print(f"Average UDP Response Time: {avg_udp_time:.3f} seconds")

if __name__ == "__main__":
    analyze_packets()
