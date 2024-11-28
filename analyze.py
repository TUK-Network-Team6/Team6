import json
import csv

# JSON 파일 확인 함수
def analyze_json(filename='captured_packets/captured_packets.json'):
    with open(filename, 'r') as json_file:
        packets = json.load(json_file)
        for packet in packets:
            print(packet)

# CSV 파일 확인 함수
def analyze_csv(filename='captured_packets/captured_packets.csv'):
    with open(filename, 'r') as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            print(row)

if __name__ == "__main__":
    # JSON 확인 실행
    analyze_json()
    # CSV 확인 실행
    # analyze_csv()
