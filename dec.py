import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, help="AES 키 파일 경로")
    parser.add_argument(
        "--root",
        default=r"C:\Users\Alpha\Desktop",
        help="탐색 시작 폴더 (기본: 사용자 바탕화면)"
    )
    args = parser.parse_args()

    key_path = args.key
    root_path = args.root

    # 키 파일 읽기
    with open(key_path, "rb") as f:
        a = f.read()

    print(f"AES 키 파일 내용: {a.decode('utf-8')}")
    print(f"root 경로: {root_path}")

if __name__ == "__main__":
    main()
