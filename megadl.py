#!/usr/bin/env python3
"""
megadl.py v1.2 — CLI tool to download public files and folders from MEGA.nz

Usage:
  python megadl.py <mega_link> [options]

Options:
  --output <folder>    Folder to save the file(s) (default: current directory)
  --output-name <n>    Rename the downloaded file (single file only)
  --no-resume          Force restart even if a partial file exists
  --version            Show version
  --help               Show this help message
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


VERSION = "1.2.0"

# ─────────────────────────────────────────────
# MEGA API error codes
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
# Parse MEGA link — file or folder
# ─────────────────────────────────────────────

def parse_mega_link(url: str):
    """
    Returns (link_type, id, key_str)
    link_type is "file" or "folder"

    Supported formats:
      File   (new): https://mega.nz/file/FILE_ID#KEY
      File   (old): https://mega.nz/#!FILE_ID!KEY
      Folder (new): https://mega.nz/folder/FOLDER_ID#KEY
      Folder (old): https://mega.nz/#F!FOLDER_ID!KEY
    """
    m = re.search(r"mega\.nz/folder/([^#]+)#(.+)", url)
    if m:
        return "folder", m.group(1), m.group(2)

    m = re.search(r"mega\.nz/#F!([^!]+)!(.+)", url)
    if m:
        return "folder", m.group(1), m.group(2)

    m = re.search(r"mega\.nz/file/([^#]+)#(.+)", url)
    if m:
        return "file", m.group(1), m.group(2)

    m = re.search(r"mega\.nz/#!([^!]+)!(.+)", url)
    if m:
        return "file", m.group(1), m.group(2)

    raise ValueError(
        "Could not parse MEGA link.\n"
        "  File:   https://mega.nz/file/FILE_ID#KEY\n"
        "  Folder: https://mega.nz/folder/FOLDER_ID#KEY\n\n"
        "  Make sure you copied the full link including the part after #"
    )


# ─────────────────────────────────────────────
# Key derivation
# ─────────────────────────────────────────────

def derive_key_and_iv(key_str: str):
    """
    XOR-folds the 256-bit URL key into a 128-bit AES key + 128-bit CTR IV.
    Returns (aes_key, iv)
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


def derive_folder_key(key_str: str) -> bytes:
    """Folder master key is simply base64url-decoded (16 bytes)."""
    raw = base64url_decode(key_str)
    if len(raw) != 16:
        raise ValueError(f"Invalid folder key length ({len(raw)} bytes).")
    return raw


def decrypt_node_key(encrypted_key_b64: str, folder_master_key: bytes) -> bytes:
    """
    Each file inside a folder has its own key encrypted with the folder master key.
    Decrypt it using AES-128-ECB.
    """
    raw = base64url_decode(encrypted_key_b64)
    cipher = AES.new(folder_master_key, AES.MODE_ECB)
    return cipher.decrypt(raw)


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
# MEGA API helpers
# ─────────────────────────────────────────────

def api_request(payload: list, params: dict = None) -> list:
    url = "https://g.api.mega.co.nz/cs"
    try:
        resp = requests.post(url, json=payload, params=params, timeout=30)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError("Could not connect to MEGA's API. Check your internet connection.")
    except requests.exceptions.Timeout:
        raise RuntimeError("MEGA API request timed out. Try again in a moment.")
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"MEGA API returned HTTP error: {e}")

    data = resp.json()
    if isinstance(data, int):
        msg = MEGA_ERRORS.get(data, f"Unknown error code {data}")
        raise RuntimeError(f"MEGA API error {data}: {msg}")

    return data


def get_file_info(file_id: str) -> dict:
    data = api_request([{"a": "g", "g": 1, "p": file_id}])
    result = data[0] if isinstance(data, list) else data
    if isinstance(result, int):
        msg = MEGA_ERRORS.get(result, f"Unknown error code {result}")
        raise RuntimeError(f"MEGA API error {result}: {msg}")
    return result


def get_folder_nodes(folder_id: str) -> list:
    """Fetches all nodes (files + subfolders) inside a public folder."""
    data = api_request([{"a": "f", "c": 1, "r": 1}], params={"n": folder_id})
    result = data[0] if isinstance(data, list) else data
    if isinstance(result, int):
        msg = MEGA_ERRORS.get(result, f"Unknown error code {result}")
        raise RuntimeError(f"MEGA API error {result}: {msg}")
    return result.get("f", [])


def get_folder_file_url(node_id: str, folder_id: str) -> dict:
    """Gets the download URL for a specific file node inside a folder."""
    data = api_request([{"a": "g", "g": 1, "n": node_id}], params={"n": folder_id})
    result = data[0] if isinstance(data, list) else data
    if isinstance(result, int):
        msg = MEGA_ERRORS.get(result, f"Unknown error code {result}")
        raise RuntimeError(f"MEGA API error {result}: {msg}")
    return result


# ─────────────────────────────────────────────
# AES-128-CTR cipher (resume-aware)
# ─────────────────────────────────────────────

def make_ctr_cipher(aes_key: bytes, iv: bytes, offset_bytes: int = 0):
    nonce_int = int.from_bytes(iv[:8], "big")
    block_offset = offset_bytes // 16
    initial_value = (nonce_int << 64) + block_offset

    ctr = Counter.new(128, initial_value=initial_value, little_endian=False)
    cipher = AES.new(aes_key, AES.MODE_CTR, counter=ctr)

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
            print(f"  ✅  Already complete: {filename}")
            return
        print(f"  ⏩  Resuming from {existing_bytes / (1024*1024):.2f} MB "
              f"of {file_size / (1024*1024):.2f} MB")
    else:
        print(f"  📥  {filename}  ({file_size / (1024*1024):.2f} MB)")

    headers = {}
    if existing_bytes > 0:
        headers["Range"] = f"bytes={existing_bytes}-"

    try:
        resp = requests.get(download_url, stream=True, timeout=60, headers=headers)
    except requests.exceptions.ConnectionError:
        raise RuntimeError("Lost connection. Run the same command again to resume.")
    except requests.exceptions.Timeout:
        raise RuntimeError("Download timed out. Run the same command again to resume.")

    if resp.status_code == 416:
        print(f"  ✅  Already complete: {filename}")
        return

    if resp.status_code not in (200, 206):
        raise RuntimeError(
            f"Download server returned HTTP {resp.status_code}. "
            "The URL may have expired — run the command again."
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
        desc=f"  {filename[:40]}",
        ncols=80,
        leave=True,
    ) as bar:
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                f.write(cipher.decrypt(chunk))
                bar.update(len(chunk))


# ─────────────────────────────────────────────
# Build folder tree from flat node list
# ─────────────────────────────────────────────

def build_folder_tree(nodes: list, folder_master_key: bytes):
    """
    Takes the raw flat node list from the MEGA API and returns:
      - node_map: dict of node_id -> node info (with decrypted name + key)
      - root_id:  the top-level folder node id
    """
    node_map = {}
    all_ids = {n.get("h") for n in nodes}
    root_id = None

    for node in nodes:
        ntype    = node.get("t")
        node_id  = node.get("h")
        parent_id = node.get("p")
        at_b64   = node.get("a", "")
        key_b64  = node.get("k", "")

        # Key field can be "userhandle:keydata" — take the key part only
        if ":" in key_b64:
            key_b64 = key_b64.split(":")[-1]

        name     = node_id  # fallback
        node_key = None

        if key_b64 and folder_master_key:
            try:
                raw_key = decrypt_node_key(key_b64, folder_master_key)
                node_key = raw_key

                # File nodes have a 32-byte key that must be XOR-folded to get
                # the real 16-byte AES key (same as derive_key_and_iv does).
                # Folder nodes have a 16-byte key used as-is.
                if len(raw_key) == 32:
                    k = struct.unpack(">8I", raw_key)
                    attr_key = struct.pack(">4I",
                        k[0] ^ k[4],
                        k[1] ^ k[5],
                        k[2] ^ k[6],
                        k[3] ^ k[7],
                    )
                else:
                    attr_key = raw_key[:16]

                if at_b64:
                    attrs = decrypt_attributes(at_b64, attr_key)
                    name = attrs.get("n", node_id)
            except Exception:
                pass

        # Root = a folder node whose parent is not in this node set
        if ntype == 1 and parent_id not in all_ids:
            root_id = node_id

        node_map[node_id] = {
            "id":     node_id,
            "parent": parent_id,
            "type":   ntype,   # 0=file, 1=folder
            "name":   name,
            "key":    node_key,
            "size":   node.get("s", 0),
        }

    return node_map, root_id


def collect_files(node_map: dict, root_id: str):
    """
    Walks the folder tree and yields (relative_path, node)
    for every file node, preserving subfolder structure.
    """
    def walk(node_id, path_parts):
        node = node_map.get(node_id)
        if not node:
            return
        if node["type"] == 0:  # file
            yield os.path.join(*path_parts, node["name"]) if path_parts else node["name"], node
        elif node["type"] == 1:  # folder
            sub = path_parts + [node["name"]]
            for child in node_map.values():
                if child["parent"] == node_id:
                    yield from walk(child["id"], sub)

    for child in node_map.values():
        if child["parent"] == root_id:
            yield from walk(child["id"], [])


# ─────────────────────────────────────────────
# Single file download flow
# ─────────────────────────────────────────────

def handle_file(args, link_id: str, key_str: str):
    print("\n🌐  Fetching file info from MEGA API...")
    try:
        info = get_file_info(link_id)
    except RuntimeError as e:
        print(f"\n❌  {e}")
        sys.exit(1)

    download_url = info.get("g")
    file_size    = info.get("s", 0)
    at_b64       = info.get("at", "")

    if not download_url:
        print(
            "\n❌  MEGA did not return a download URL.\n"
            "    • The file may have been deleted\n"
            "    • The link may have expired\n"
            "    • MEGA may be rate-limiting your IP (try again in a few minutes)"
        )
        sys.exit(1)

    try:
        aes_key, iv = derive_key_and_iv(key_str)
    except ValueError as e:
        print(f"\n❌  Key error: {e}")
        sys.exit(1)

    filename = link_id
    if at_b64:
        try:
            attrs = decrypt_attributes(at_b64, aes_key)
            filename = attrs.get("n", link_id)
        except Exception:
            print("⚠️   Could not decrypt filename — using file ID as filename.")

    if args.output_name:
        filename = args.output_name

    output_dir = os.path.expanduser(args.output)
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    print(f"\n{'─'*50}")
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
        print(f"\n❌  {e}")
        sys.exit(1)

    print(f"\n✅  Done → {os.path.abspath(filepath)}")


# ─────────────────────────────────────────────
# Folder download flow
# ─────────────────────────────────────────────

def handle_folder(args, folder_id: str, key_str: str):
    if args.output_name:
        print("⚠️   --output-name is ignored for folder downloads.")

    print("\n🌐  Fetching folder contents from MEGA API...")
    try:
        folder_master_key = derive_folder_key(key_str)
        nodes = get_folder_nodes(folder_id)
    except RuntimeError as e:
        print(f"\n❌  {e}")
        sys.exit(1)

    if not nodes:
        print("❌  No files found in this folder. It may be empty or the link is invalid.")
        sys.exit(1)

    node_map, root_id = build_folder_tree(nodes, folder_master_key)

    # Fallback root detection
    if not root_id:
        for n in node_map.values():
            if n["type"] == 1:
                root_id = n["id"]
                break

    files = list(collect_files(node_map, root_id))

    if not files:
        print("❌  No downloadable files found in this folder.")
        sys.exit(1)

    root_name  = node_map.get(root_id, {}).get("name", folder_id)
    output_dir = os.path.expanduser(args.output)
    base_dir   = os.path.join(output_dir, root_name)
    total_size = sum(n["size"] for _, n in files)

    print(f"📂  Folder   : {root_name}")
    print(f"📄  Files    : {len(files)}")
    print(f"📦  Total    : {total_size / (1024*1024):.2f} MB")
    print(f"💾  Saving to: {os.path.abspath(base_dir)}\n")

    failed = []

    for i, (rel_path, node) in enumerate(files, 1):
        filepath = os.path.join(base_dir, rel_path)
        os.makedirs(os.path.dirname(filepath) or base_dir, exist_ok=True)

        print(f"[{i}/{len(files)}]")

        node_key = node.get("key")
        if not node_key or len(node_key) < 32:
            print(f"  ⚠️   Skipping — could not decrypt node key.")
            failed.append(rel_path)
            print()
            continue

        try:
            aes_key, iv = derive_key_and_iv(base64url_encode(node_key))
        except Exception as e:
            print(f"  ⚠️   Skipping — key error: {e}")
            failed.append(rel_path)
            print()
            continue

        try:
            dl_info = get_folder_file_url(node["id"], folder_id)
        except RuntimeError as e:
            print(f"  ⚠️   Skipping — API error: {e}")
            failed.append(rel_path)
            print()
            continue

        download_url = dl_info.get("g")
        if not download_url:
            print(f"  ⚠️   Skipping — no download URL returned.")
            failed.append(rel_path)
            print()
            continue

        try:
            download_and_decrypt(
                download_url=download_url,
                aes_key=aes_key,
                iv=iv,
                filepath=filepath,
                file_size=node["size"],
                resume=not args.no_resume,
            )
        except RuntimeError as e:
            print(f"  ❌  {e}")
            failed.append(rel_path)
        except KeyboardInterrupt:
            print("\n\n⚠️   Interrupted. Run the same command to resume.")
            sys.exit(0)

        print()

    # Summary
    succeeded = len(files) - len(failed)
    print(f"{'─'*50}")
    print(f"✅  {succeeded}/{len(files)} files downloaded → {os.path.abspath(base_dir)}")
    if failed:
        print(f"❌  {len(failed)} file(s) failed:")
        for f in failed:
            print(f"     • {f}")


# ─────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="megadl",
        description="Download public MEGA.nz files and folders from your terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key'\n"
            "  python megadl.py 'https://mega.nz/folder/ABC123#key'\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key' --output ~/Downloads\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key' --output-name myvideo.mp4\n"
            "  python megadl.py 'https://mega.nz/file/ABC123#key' --no-resume\n"
        )
    )
    parser.add_argument("link", help="Public MEGA.nz file or folder link")
    parser.add_argument(
        "--output", "-o",
        metavar="FOLDER",
        default=".",
        help="Folder to save file(s) (default: current directory)"
    )
    parser.add_argument(
        "--output-name", "-n",
        metavar="NAME",
        default=None,
        help="Rename the downloaded file (single file only)"
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

    print("🔍  Parsing MEGA link...")
    try:
        link_type, link_id, key_str = parse_mega_link(args.link)
    except ValueError as e:
        print(f"\n❌  Invalid link:\n    {e}")
        sys.exit(1)

    print(f"    Type    : {link_type}")
    print(f"    ID      : {link_id}")
    print(f"    Key     : {key_str[:10]}...  (truncated for safety)")

    try:
        if link_type == "file":
            handle_file(args, link_id, key_str)
        else:
            handle_folder(args, link_id, key_str)
    except KeyboardInterrupt:
        print(
            "\n\n⚠️   Interrupted.\n"
            "     Run the same command again to resume where you left off."
        )
        sys.exit(0)


if __name__ == "__main__":
    main()
