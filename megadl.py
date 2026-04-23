#!/usr/bin/env python3
"""
megadl.py — A CLI tool to download public files from MEGA.nz
Usage: python megadl.py <mega_link>
"""

import sys
import re
import json
import struct
import base64
import hashlib
import os
import requests
from Crypto.Cipher import AES
from tqdm import tqdm


# ─────────────────────────────────────────────
# Base64url helpers (MEGA uses url-safe base64
# without padding)
# ─────────────────────────────────────────────

def base64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = (4 - len(s) % 4) % 4
    return base64.b64decode(s + "=" * pad)


def base64url_encode(b: bytes) -> str:
    return base64.b64encode(b).decode().replace("+", "-").replace("/", "_").rstrip("=")


# ─────────────────────────────────────────────
# Parse the MEGA link
# ─────────────────────────────────────────────

def parse_mega_link(url: str):
    # New style: /file/FILEID#KEY
    m = re.search(r"mega\.nz/file/([^#]+)#(.+)", url)
    if m:
        return m.group(1), m.group(2)

    # Old style: /#!FILEID!KEY
    m = re.search(r"mega\.nz/#!([^!]+)!(.+)", url)
    if m:
        return m.group(1), m.group(2)

    raise ValueError(
        "Could not parse MEGA link. Expected format:\n"
        "  https://mega.nz/file/FILE_ID#KEY\n"
        "  https://mega.nz/#!FILE_ID!KEY"
    )


# ─────────────────────────────────────────────
# Key derivation
# MEGA stores a 256-bit composite key in the URL.
# The first 128 bits XOR'd with the last 128 bits
# gives the AES-128 file key.
# The last 128 bits (after XOR) split into:
#   [0..3]  = nonce (64 bits, stored in words 0-1)
#   [4..5]  = MAC IV start (we don't verify MAC here)
# ─────────────────────────────────────────────

def derive_key_and_iv(key_str: str):
    """
    Returns (aes_key: bytes[16], iv: bytes[16])
    for AES-128-CTR decryption.
    """
    raw = base64url_decode(key_str)   # 32 bytes

    # Unpack as 8 x uint32 big-endian
    k = struct.unpack(">8I", raw)

    # XOR fold: file key = k[0..3] XOR k[4..7]
    aes_key = struct.pack(">4I",
        k[0] ^ k[4],
        k[1] ^ k[5],
        k[2] ^ k[6],
        k[3] ^ k[7],
    )

    # IV = nonce from k[4], k[5], then 0, 0
    iv = struct.pack(">4I", k[4], k[5], 0, 0)

    return aes_key, iv


# ─────────────────────────────────────────────
# Decrypt file attributes (contains filename)
# ─────────────────────────────────────────────

def decrypt_attributes(at_b64: str, aes_key: bytes) -> dict:
    """
    Attributes are AES-128-CBC encrypted with a zero IV.
    Returns parsed JSON dict, e.g. {"n": "filename.ext"}
    """
    raw = base64url_decode(at_b64)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b"\x00" * 16)
    decrypted = cipher.decrypt(raw)

    # Strip "MEGA" prefix and null padding
    text = decrypted.decode("utf-8", errors="ignore")
    if text.startswith("MEGA"):
        text = text[4:]

    # Find the JSON object
    text = text.strip("\x00").strip()
    end = text.rfind("}") + 1
    return json.loads(text[:end])


# ─────────────────────────────────────────────
# Query MEGA API for file metadata + download URL
# ─────────────────────────────────────────────

def get_file_info(file_id: str) -> dict:
    url = "https://g.api.mega.co.nz/cs"
    payload = [{"a": "g", "g": 1, "p": file_id}]
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, list):
        data = data[0]

    if isinstance(data, int):
        raise RuntimeError(f"MEGA API error code: {data}")

    return data


# ─────────────────────────────────────────────
# AES-128-CTR stream decryptor
# (pycryptodome's CTR mode with MEGA's counter)
# ─────────────────────────────────────────────

def make_ctr_cipher(aes_key: bytes, iv: bytes):
    """
    MEGA uses AES-CTR where the counter is the IV
    with the last 8 bytes as a 64-bit big-endian counter.
    """
    from Crypto.Util import Counter
    # iv is 16 bytes; first 8 are nonce, last 8 are counter start (0)
    nonce_int = int.from_bytes(iv[:8], "big")
    # Full 128-bit initial value: nonce in upper 64 bits
    initial_value = nonce_int << 64

    ctr = Counter.new(128, initial_value=initial_value, little_endian=False)
    return AES.new(aes_key, AES.MODE_CTR, counter=ctr)


# ─────────────────────────────────────────────
# Download + decrypt
# ─────────────────────────────────────────────

def download_and_decrypt(download_url: str, aes_key: bytes, iv: bytes,
                          filename: str, file_size: int):
    print(f"\n📥  Downloading: {filename}")
    print(f"📦  Size: {file_size / (1024*1024):.2f} MB\n")

    cipher = make_ctr_cipher(aes_key, iv)

    resp = requests.get(download_url, stream=True, timeout=60)
    resp.raise_for_status()

    chunk_size = 1024 * 128  # 128 KB chunks

    with open(filename, "wb") as f, tqdm(
        total=file_size,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        desc=filename,
        ncols=80,
    ) as bar:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                decrypted_chunk = cipher.decrypt(chunk)
                f.write(decrypted_chunk)
                bar.update(len(chunk))

    print(f"\n✅  Saved to: {os.path.abspath(filename)}")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python megadl.py <mega_link>")
        print("Example:")
        print("  python megadl.py 'https://mega.nz/file/ABC123#secretkey'")
        sys.exit(1)

    mega_url = sys.argv[1]

    print("🔍  Parsing MEGA link...")
    try:
        file_id, key_str = parse_mega_link(mega_url)
    except ValueError as e:
        print(f"❌  {e}")
        sys.exit(1)

    print(f"    File ID : {file_id}")
    print(f"    Key     : {key_str[:10]}...  (truncated)")

    print("\n🌐  Fetching file info from MEGA API...")
    try:
        info = get_file_info(file_id)
    except Exception as e:
        print(f"❌  API error: {e}")
        sys.exit(1)

    download_url = info.get("g")
    file_size    = info.get("s", 0)
    at_b64       = info.get("at", "")

    if not download_url:
        print("❌  No download URL returned. The link may be expired or invalid.")
        sys.exit(1)

    # Derive AES key + IV from the URL key string
    aes_key, iv = derive_key_and_iv(key_str)

    # Decrypt attributes to get filename
    filename = file_id  # fallback
    if at_b64:
        try:
            attrs = decrypt_attributes(at_b64, aes_key)
            filename = attrs.get("n", file_id)
        except Exception:
            print("⚠️   Could not decrypt filename, using file ID as name.")

    download_and_decrypt(download_url, aes_key, iv, filename, file_size)


if __name__ == "__main__":
    main()
