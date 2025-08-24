import os
import sys
import argparse
import subprocess

# AES 모듈 준비 (없으면 설치)
try:
    from Crypto.Cipher import AES
except ImportError:
    print("pycryptodome 설치 필요, 설치 시작")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"])
    from Crypto.Cipher import AES

def read_key_hex_or_raw(path):
    import sys

    s = ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            s = f.read()
    except Exception:
        pass

    s = s.strip().replace(" ", "").replace("\n", "").replace("\r", "")
    
    # 형식 검증 (16진수, 64바이트인지)
    if len(s) != 64 or any(c not in "0123456789abcdefABCDEF" for c in s):
        print(".aes 파일이 올바르지 않습니다")
        sys.exit(1)

    try:
        key = bytes.fromhex(s)
    except Exception:
        print(".aes 파일이 올바르지 않습니다")
        sys.exit(1)

    if len(key) != 32:
        print(".aes 파일이 올바르지 않습니다")
        sys.exit(1)

    return key


def decrypt_aes_gcm(data, key):
    # 데이터 검증
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data는 bytes여야 함")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key는 bytes여야 함")
    if len(key) != 32:
        raise ValueError("키 길이 오류 (32바이트 아님)")

    # 최소 길이: 12바이트 nonce + 최소 1바이트 ct + 16바이트 tag
    if len(data) < 29:
        raise ValueError("복호화 대상 아님")

    nonce = data[:12]
    tag   = data[-16:]
    ct    = data[12:-16]

    try:
        cipher = AES.new(bytes(key), AES.MODE_GCM, nonce=nonce)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt
    except ValueError:
        raise ValueError("복호화 실패 (MAC 불일치/데이터 손상)")
    except Exception as e:
        raise RuntimeError("복호화 중 오류: {}".format(e))


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
