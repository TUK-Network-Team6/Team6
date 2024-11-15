import subprocess

def main():
    print("2024 Network Programming Team 6")
    print("Packet Capture and Analysis Tool")
    print("================================")
    print("1. Capture - Start packet capturing")
    print("2. Analyze - Analyze captured packets")
    print("3. Exit")

    choice = input("Enter your choice (1/2/3): ")

    if choice == '1':
        print("\nStarting packet capture...")
        subprocess.run(["python3", "packetCapture.py"])  # 캡처 실행

    elif choice == '2':
        print("\nStarting packet analysis...")
        subprocess.run(["python3", "analyze.py"])  # 분석 실행

    elif choice == '3':
        print("Exiting...")

    else:
        print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
