# Megadl 🔽

A simple, no-nonsense CLI tool to download public files and folders from MEGA.nz — no browser, no ads, no BS.

## Features

- Works with both old and new MEGA link formats
- Download single files **and entire folders**
- Folder downloads preserve the original subfolder structure
- **Bulk download queue** — pass a `.txt` file with one link per line
- **Auto-retry** — failed downloads are retried twice automatically before skipping
- **Resume interrupted downloads** — just run the same command again
- Lightweight — just Python + 3 small dependencies

## Requirements

- Python 3.7+
- pip

## Installation

```bash
# Clone the repo
git clone https://github.com/rajchaudhary-dev/mega-downloader.git
cd megadl

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python megadl.py '<mega_link>' [options]
python megadl.py '<txt_file>' [options]
```

### Options

| Flag | Short | Description |
|---|---|---|
| `--output <folder>` | `-o` | Folder to save the file(s) (default: current directory) |
| `--output-name <n>` | `-n` | Rename the downloaded file (single file only) |
| `--no-resume` | | Force a fresh download, ignore partial files |
| `--version` | `-v` | Show version |
| `--help` | `-h` | Show help |

### Examples

```bash
# Download a single file
python megadl.py '<mega_file_link>'

# Download an entire folder
python megadl.py '<mega_folder_link>'

# Bulk download from a txt file
python megadl.py links.txt

# Bulk download to a specific folder
python megadl.py links.txt -o ~/Downloads

# Save to a specific folder
python megadl.py '<mega_link>' -o ~/Downloads

# Rename the file
python megadl.py '<mega_link>' -n myvideo.mp4

# Save to folder AND rename
python megadl.py '<mega_link>' -o ~/Downloads -n myvideo.mp4
```

### Bulk queue download

Create a `links.txt` file with one MEGA link per line. Blank lines and lines starting with `#` are ignored:

```
# My downloads
https://mega.nz/file/ABC12345#key1
https://mega.nz/folder/XYZ56789#key2
https://mega.nz/file/DEF00000#key3

```

Then run:

```bash
python megadl.py links.txt
```

megadl downloads each link one by one and prints a summary at the end:

```
══════════════════════════════════════════════════
📊  Queue complete: 3/4 succeeded

❌  Failed (1):
     • Line 3: https://mega.nz/file/DEF00000#key3
               Reason: Download failed
══════════════════════════════════════════════════
```

### Auto-retry

If a download fails (network blip, timeout, etc.), megadl automatically retries it twice before moving on. No flags needed — it just works silently.

```
  ⚠️   Failed (attempt 1/3): Lost connection.
  🔄  Retrying in 3s...
```

### Resume downloads

If a download is interrupted (Ctrl+C, lost connection, etc.), just run the exact same command again — megadl will detect the partial file and pick up where it left off. Works for single files, folders, and queues.

```
⏩  Partial file found — resuming from 512.00 MB of 2048.00 MB
```

## Supported Link Formats

| Format | Example |
|---|---|
| New file | `https://mega.nz/file/ID#KEY` |
| Old file | `https://mega.nz/#!ID!KEY` |
| New folder | `https://mega.nz/folder/ID#KEY` |
| Old folder | `https://mega.nz/#F!ID!KEY` |

## How It Works

MEGA encrypts all files client-side. The decryption key is embedded directly in the share link (after the `#`), which means MEGA's servers never see it — but neither does anyone else unless you share the full link.

**File downloads follow 3 steps:**

1. **Fetch metadata** — calls the MEGA API with the file ID to get the download URL, file size, and encrypted attributes
2. **Download** — streams the raw encrypted file from MEGA's storage servers in chunks
3. **Decrypt** — decrypts on the fly using AES-128-CTR with the key derived from the link

**Folder downloads follow the same steps, plus:**

1. Fetches all nodes (files + subfolders) from the MEGA API
2. Decrypts each node's key using the folder master key (AES-128-ECB)
3. Decrypts each node's attributes to recover the original filename
4. Downloads and decrypts each file individually, preserving folder structure

### Key Derivation

The 256-bit key in the URL is XOR-folded into a 128-bit AES key and a 64-bit nonce (used as the CTR IV). The filename is recovered by decrypting the `at` (attributes) field using AES-128-CBC.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python not found` | Try `python3` instead |
| `pip not found` | Try `pip3` |
| `No module named 'Crypto'` | Run `pip install pycryptodome` (not `pycrypto`) |
| `API error -8` | File/folder not found — the link may be expired or deleted |
| `API error -9` | Access denied — this file is private |
| `API error -4` or `-19` | Rate limited — wait a minute and try again |
| No download URL returned | The link expired or MEGA is rate-limiting your IP — try again |
| Files downloaded with random names | Make sure you copied the full folder link including the key after `#` |
| Queue file not found | Make sure the path to your `.txt` file is correct |

## Disclaimer

This tool is intended for downloading files you own or have permission to download. Do not use it to download copyrighted material without authorization.

## License

MIT — free to use, modify, and distribute.
