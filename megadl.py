#!/usr/bin/env python3
"""
megadl.py v1.1 — CLI tool to download public files from MEGA.nz

Usage:
  python megadl.py <mega_link> [options]

Options:
  --output <folder>       Folder to save the file (default: current directory)
  --output-name <name>    Rename the downloaded file
  --no-resume             Force restart even if a partial file exists
  --version               Show version
  --help                  Show this help message
"""

import sys
import re
import json
import struct
import base64
import os
import argparse
import requests
from Crypto.Cipher import AES
from Crypto.Util import Counter
from tqdm import tqdm


VERSION = "1.1.0"

# ─────────────────────────────────────────────
# MEGA API error code meanings
# ─────────────────────────────────────────────

MEGA_ERRORS = {
    -1:  "Internal server error. Try again later.",
    -2:  "Invalid argument in the request.",
    -3:  "Request failed, please retry.",
    -4:  "Rate limit exceeded. Too many requests — wait a moment and try again.",
    -5:  "Upload failed.",
    -6:  "Too many concurrent connections or transfers.",
    -7:  "No data available (not enough quota or file unavailable).",
    -8:  "File or folder not found. The link may be invalid or the file was deleted.",
    -9:  "Access denied. This file is private or you lack permission.",
    -10: "Key not found.",
    -11: "Invalid email.",
    -12: "Resource already exists.",
    -13: "Incomplete request.",
    -14: "Cryptographic error.",
    -15: "Bad session ID.",
    -16: "User not found.",
    -17: "Request blocked (possible abuse detection).",
    -18: "Resource temporarily unavailable.",
    -19: "Too many requests from your IP. Wait and retry.",
    -25: "Account suspended.",
}


# ─────────────────────────────────────────────
# Base64url helpers
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
    """
    Supports both link formats:
      New: https://mega.nz/file/FILE_ID#KEY
      Old: https://mega.nz/#!FILE_ID!KEY
    Returns (file_id, key_str)
    """
    m = re.search(r"mega\.nz/file/([^#]+)#(.+)", url)
    if m:
        return m.group(1), m.group(2)

    m = re.search(r"mega\.nz/#!([^!]+)!(.+)", url)
    if m:
        return m.group(1), m.group(2)

    raise ValueError(
        "Could not parse MEGA link.\n"
        "  Expected: https://mega.nz/file/FILE_ID#KEY\n"
        "        or: https://mega.nz/#!FILE_ID!KEY\n\n"
        "  Make sure you copied the full link including the part after # or !"
    )


# ─────────────────────────────────────────────
# Key derivation
# ─────────────────────────────────────────────

def derive_key_and_iv(key_str: str):
    """
    XOR-folds the 256-bit URL key into a 128-bit AES key + 128-bit CTR IV.
    Returns (aes_key: bytes[16], iv: bytes[16])
    """
    raw = base64url_decode(key_str)
    if len(raw) != 32:
        raise ValueError(
            f"Invalid key length ({len(raw)} bytes). "
            "The key in the link may be truncated or corrupted."
        )

    k = struct.unpack(">8I", raw)

    aes_key = struct.pack(">4I",
        k[0] ^ k[4],
        k[1] ^ k[5],
        k[2] ^ k[6],
        k[3] ^ k[7],
    )

    iv = struct.pack(">4I", k[4], k[5], 0, 0)
    return aes_key, iv


# ─────────────────────────────────────────────
# Decrypt file attributes
# ─────────────────────────────────────────────

def decrypt_attributes(at_b64: str, aes_key: bytes) -> dict:
    raw = base64url_decode(at_b64)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=b"\x00" * 16)
    decrypted = cipher.decrypt(raw)

    text = decrypted.decode("utf-8", errors="ignore")
    if text.startswith("MEGA"):
        text = text[4:]

    text = text.strip("\x00").strip()
    end = text.rfind("}") + 1
    return json.loads(text[:end])


# ─────────────────────────────────────────────
# MEGA API
# ─────────────────────────────────────────────

def get_file_info(file_id: str) -> dict:
    url = "https://g.api.mega.co.nz/cs"
    payload = [{"a": "g", "g": 1, "p": file_id}]

    try:
        resp = requests.post(url, json=payload, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Could not connect to MEGA's API. Check your internet connection."
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(
            "MEGA API request timed out. Try again in a moment."
        )
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"MEGA API returned HTTP error: {e}")

    data = resp.json()
    if isinstance(data, list):
        data = data[0]

    if isinstance(data, int):
        msg = MEGA_ERRORS.get(data, f"Unknown error code {data}")
        raise RuntimeError(f"MEGA API error {data}: {msg}")

    return data


# ─────────────────────────────────────────────
# AES-128-CTR cipher (resume-aware)
# ─────────────────────────────────────────────

def make_ctr_cipher(aes_key: bytes, iv: bytes, offset_bytes: int = 0):
    """
    Returns an AES-CTR cipher seeked to `offset_bytes` into the stream.
    Allows resuming a partial download correctly.
    """
    nonce_int = int.from_bytes(iv[:8], "big")
    block_offset = offset_bytes // 16
    initial_value = (nonce_int << 64) + block_offset

    ctr = Counter.new(128, initial_value=initial_value, little_endian=False)
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

    # Burn through any partial block at the start
    partial = offset_bytes % 16
    if partial:
        cipher.decrypt(b"\x00" * partial)

    return cipher


# ─────────────────────────────────────────────
# Download + decrypt (with resume support)
# ─────────────────────────────────────────────

def download_and_decrypt(
    download_url: str,
    aes_key: bytes,
    iv: bytes,
    filepath: str,
    file_size: int,
    resume: bool = True,
):
    filename = os.path.basename(filepath)
    existing_bytes = 0

    if resume and os.path.exists(filepath):
        existing_bytes = os.path.getsize(filepath)
        if existing_bytes >= file_size:
            print(f"✅  File already fully downloaded: {filepath}")
            return
        print(f"\n⏩  Partial file found — resuming from "
              f"{existing_bytes / (1024*1024):.2f} MB "
              f"of {file_size / (1024*1024):.2f} MB\n")
    else:
        print(f"\n📥  Downloading : {filename}")
        print(f"📦  Size        : {file_size / (1024*1024):.2f} MB\n")

    headers = {}
    if existing_bytes > 0:
        headers["Range"] = f"bytes={existing_bytes}-"

    try:
        resp = requests.get(download_url, stream=True, timeout=60, headers=headers)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Lost connection while downloading.\n"
            "  Run the same command again to resume."
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(
            "Download timed out.\n"
            "  Run the same command again to resume."
        )

    if resp.status_code == 416:
        print("✅  File already fully downloaded.")
        return

    if resp.status_code not in (200, 206):
        raise RuntimeError(
            f"Download server returned HTTP {resp.status_code}.\n"
            "  The download URL may have expired — run the command again to get a fresh one."
        )

    cipher = make_ctr_cipher(aes_key, iv, offset_bytes=existing_bytes)
    chunk_size = 1024 * 128  # 128 KB

    mode = "ab" if existing_bytes > 0 else "wb"

    with open(filepath, mode) as f, tqdm(
        total=file_size,
        initial=existing_bytes,
        unit="B",
        unit_scale=True,
        unit_divisor=1024,
        desc=filename,
        ncols=80,
    ) as bar:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(cipher.decrypt(chunk))
                bar.update(len(chunk))

    print(f"\n✅  Saved to: {os.path.abspath(filepath)}")


# ─────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="megadl",
        description="Download public MEGA.nz files from your terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key'\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key' --output ~/Downloads\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key' --output-name myvideo.mp4\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key' --no-resume\n"
        )
    )
    parser.add_argument("link", help="Public MEGA.nz file link")
    parser.add_argument(
        "--output", "-o",
        metavar="FOLDER",
        default=".",
        help="Folder to save the file (default: current directory)"
    )
    parser.add_argument(
        "--output-name", "-n",
        metavar="NAME",
        default=None,
        help="Rename the downloaded file"
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Force a fresh download even if a partial file exists"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"megadl v{VERSION}"
    )
    return parser


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    print(f"⚡  megadl v{VERSION}\n")

    # ── Step 1: Parse link ──
    print("🔍  Parsing MEGA link...")
    try:
        file_id, key_str = parse_mega_link(args.link)
    except ValueError as e:
        print(f"\n❌  Invalid link:\n    {e}")
        sys.exit(1)

    print(f"    File ID : {file_id}")
    print(f"    Key     : {key_str[:10]}...  (truncated for safety)")

    # ── Step 2: Fetch file metadata ──
    print("\n🌐  Fetching file info from MEGA API...")
    try:
        info = get_file_info(file_id)
    except RuntimeError as e:
        print(f"\n❌  {e}")
        sys.exit(1)

    download_url = info.get("g")
    file_size    = info.get("s", 0)
    at_b64       = info.get("at", "")

    if not download_url:
        print(
            "\n❌  MEGA did not return a download URL.\n"
            "    Possible reasons:\n"
            "      • The file was deleted by the owner\n"
            "      • The link has expired\n"
            "      • MEGA is rate-limiting your IP (try again in a few minutes)"
        )
        sys.exit(1)

    # ── Step 3: Derive crypto keys ──
    try:
        aes_key, iv = derive_key_and_iv(key_str)
    except ValueError as e:
        print(f"\n❌  Key error: {e}")
        sys.exit(1)

    # ── Step 4: Decrypt filename ──
    filename = file_id  # fallback
    if at_b64:
        try:
            attrs = decrypt_attributes(at_b64, aes_key)
            filename = attrs.get("n", file_id)
        except Exception:
            print("⚠️   Could not decrypt filename — using file ID as filename.")

    # ── Step 5: Apply --output-name and --output ──
    if args.output_name:
        filename = args.output_name

    output_dir = os.path.expanduser(args.output)
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            print(f"📁  Created output folder: {output_dir}")
        except OSError as e:
            print(f"\n❌  Could not create output folder '{output_dir}': {e}")
            sys.exit(1)

    filepath = os.path.join(output_dir, filename)

    # ── Step 6: Download + decrypt ──
    try:
        download_and_decrypt(
            download_url=download_url,
            aes_key=aes_key,
            iv=iv,
            filepath=filepath,
            file_size=file_size,
            resume=not args.no_resume,
        )
    except RuntimeError as e:
        print(f"\n❌  Download failed:\n    {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(
            "\n\n⚠️   Download interrupted.\n"
            "     Run the same command again to resume where you left off."
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
