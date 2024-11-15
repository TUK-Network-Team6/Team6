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
    # Ensure the directory exists
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # 파일이 존재하면 기존 데이터를 읽어와서 추가
    existing_data = []
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as json_file:
            existing_data = json.load(json_file)

    # 새 데이터를 기존 데이터에 추가
    combined_data = existing_data + packet_list

    # 저장
    with open(filename, 'w', encoding='utf-8') as json_file:
        json.dump(combined_data, json_file, indent=4, ensure_ascii=False)

# CSV 파일 저장 함수
def save_to_csv(packet_list, filename='captured_packets/captured_packets.csv'):
    # Ensure the directory exists
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
