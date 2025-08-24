import os
import argparse
from Crypto.Cipher import AES

def read_key_hex_or_raw(path):
    with open(path, "r", encoding="utf-8") as f:
        s = f.read()
        s = bytes.fromhex(s)
    return s


def decrypt_aes_gcm(data: bytes, key: bytes):
    if len(data) < 29:
        raise ValueError(".복호화 대상 X")
    nonce = data[:12]
    tag = data[-16:]
    ct = data[12:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True, help=".aes 키 파일 경로")
    ap.add_argument("--root", required=True, help="탐색 시작 폴더 (기본: 사용자 바탕화면)")
    args = ap.parse_args()

    key = read_key_hex_or_raw(args.key)
    root = args.root

    src = os.path.join(root, "FLAG.txt.ryk")
    dst = os.path.join(root, "FLAG.txt")

  
    with open(src, "rb") as f:
        data = f.read()
    pt = decrypt_aes_gcm(data, key)

    with open(dst, "wb") as f:
        f.write(pt)

    os.remove(src)

if __name__ == "__main__":
    main()
