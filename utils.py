import json
import csv
import os

# 필드 정의
ALL_FIELDNAMES = [
    "timestamp", "protocol", "src_ip", "dst_ip",
    "src_port", "dst_port", "seq", "ack",
    "sub_protocol", "http_data", "http_method", "http_path",
    "http_version", "http_host", "http_connection",
    "smtp_data", "smtp_mail_from", "smtp_rcpt_to",
    "dns_query", "dns_query_type"
]

# JSON 파일 저장 함수
def save_to_json(packet_list, filename='captured_packets/captured_packets.json'):
    """
    JSON 데이터를 임시 파일로 저장한 후 원본 파일로 교체하여 손상 방지
    """
    # 디렉토리 존재 확인
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    temp_filename = filename + ".tmp"

    try:
        # 기존 데이터를 복구 또는 읽기
        existing_data = []
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as json_file:
                try:
                    existing_data = json.load(json_file)
                except json.JSONDecodeError:
                    print("[ERROR] JSON file is corrupted. Attempting recovery...")
                    existing_data = recover_json(filename) or []

        # 존재 데이터 합치기
        combined_data = existing_data + packet_list

        # 임시 파일 저장
        with open(temp_filename, 'w', encoding='utf-8') as temp_file:
            json.dump(combined_data, temp_file, indent=4, ensure_ascii=False)

        # 임시 파일로 기존 파일 교체
        os.replace(temp_filename, filename)
        print(f"[INFO] Successfully saved JSON to {filename}")

    except Exception as e:
        print(f"[ERROR] Failed to save JSON: {e}")
        # 에러가 일어나면 임시 파일을 삭제
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

# JSON 파일 복구 함수
def recover_json(filename):
    """
    손상된 JSON 파일을 복구하는 함수
    """
    try:
        with open(filename, 'r', encoding='utf-8') as json_file:
            content = json_file.read()

        # 열 감싸 복구 시도
        content = content.strip()
        if not content.endswith("]"):
            content += "]"

        return json.loads(content)

    except Exception as e:
        print(f"[ERROR] Failed to recover JSON: {e}")
        return None

# CSV 파일 저장 함수
def save_to_csv(packet_list, filename='captured_packets/captured_packets.csv'):
    """
    패킷 데이터를 CSV 파일에 저장
    """
    # 디렉토리 존재 확인
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # CSV 파일이 존재하는지 확인
    file_exists = os.path.exists(filename)

    with open(filename, 'a', newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=ALL_FIELDNAMES)

        # 파일이 처음 생성되는 경우 헤더 추가
        if not file_exists:
            writer.writeheader()

        # 새로운 데이터를 추가
        for packet in packet_list:
            writer.writerow({field: packet.get(field, "") for field in ALL_FIELDNAMES})

# 테스트
if __name__ == "__main__":
    test_data = [
        {"timestamp": "2024-11-18 17:29:20", "protocol": "TCP", "src_ip": "192.168.43.32", "dst_ip": "210.93.48.59", "src_port": 53143, "dst_port": 443, "seq": 2139928379, "ack": 14072519},
        {"timestamp": "2024-11-18 17:29:21", "protocol": "UDP", "src_ip": "192.168.43.32", "dst_ip": "8.8.8.8", "src_port": 5353, "dst_port": 53, "dns_query": "example.com", "dns_query_type": 1},
    ]

    # JSON 저장 테스트
    save_to_json_safe(test_data)

    # CSV 저장 테스트
    save_to_csv(test_data)
