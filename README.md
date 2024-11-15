## 프로젝트 리드미

---

### **1. 프로젝트 구조**

```
Team6/
│
├── packetCapture.py   # 실시간 패킷 캡처 및 저장 기능
├── analyze.py         # 저장된 파일 분석 기능
├── utils.py           # 공통 파일 저장 함수 및 유틸리티
└── captured_packets/  # 패킷 저장 폴더 (json, csv)
```

---

### **2. 시작 가이드**

#### **필요 사항**
- Python 3.x 설치 (pip install python3)
- `scapy` 라이브러리 설치:
  ```bash
  pip install scapy
  ```

#### **Python 권한 설정 (Ubuntu 기준)**
1. Python 실행 파일 경로 확인:
   ```bash
   realpath $(which python3)
   ```
2. 권한 부여:
   ```bash
   sudo setcap cap_net_raw+ep /usr/bin/python3.10
   ```
   > `/usr/bin/python3.10`은 위에서 확인한 경로로 대체하세요.

---

#### **실행 방법**

1. **프로그램 실행**
   ```bash
   sudo python3 main.py
   ```
   > `sudo` 권한으로 실행해야 패킷 캡처가 가능합니다.

2. **메뉴 선택**
   - **1**: 실시간 패킷 캡처 시작
   - **2**: 저장된 파일 분석
   - **3**: 종료

3. **캡처 중 중지하기**
   - 실시간 캡처 도중 프로그램을 종료하려면 `Ctrl+C`를 누르세요.

---

### **예시 실행 화면**

```plaintext
[INFO] 프로그램 시작
1 - 캡처
2 - 분석
3 - 나가기
입력: 
``` 

---
