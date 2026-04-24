# Megadl 🔽

A simple, no-nonsense CLI tool to download public files from MEGA.nz — no browser, no ads, no BS.

## Features

- Works with both old and new MEGA link formats
- Decrypts files on the fly using the key embedded in the link
- **Resume interrupted downloads** — just run the same command again
- Real-time progress bar
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
```

### Options
| Flag | Short | Description |
|---|---|---|
| `--output <folder>` | `-o` | Folder to save the file (default: current directory) |
| `--output-name <name>` | `-n` | Rename the downloaded file |
| `--help` | `-h` | Show help |

### Examples

```bash
# Basic download
python megadl.py '<mega_link>'

# Save to a specific folder
python megadl.py '<mega_link>' -o ~/Downloads

# Rename the file
python megadl.py '<mega_link>' -n myvideo.mp4

# Save to folder AND rename
python megadl.py '<mega_link>' -o ~/Downloads -n myvideo.mp4
```

### Resume downloads

If a download is interrupted (Ctrl+C, lost connection, etc.), just run the exact same command again — megadl will detect the partial file and pick up where it left off.

```
⏩  Partial file found — resuming from 512.00 MB of 2048.00 MB
```

## How It Works

MEGA encrypts all files client-side. The decryption key is embedded directly in the share link (after the `#`), which means MEGA's servers never see it — but neither does anyone else unless you share the full link.

This tool follows 3 steps:

1. **Fetch metadata** — calls the MEGA API with the file ID to get the download URL, file size, and encrypted attributes
2. **Download** — streams the raw encrypted file from MEGA's storage servers in chunks
3. **Decrypt** — decrypts on the fly using AES-128-CTR with the key derived from the link

### Key Derivation

The 256-bit key in the URL is XOR-folded into a 128-bit AES key and a 64-bit nonce (used as the CTR IV). The filename is recovered by decrypting the `at` (attributes) field using AES-128-CBC.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python not found` | Try `python3` instead |
| `pip not found` | Try `pip3` |
| `No module named 'Crypto'` | Run `pip install pycryptodome` (not `pycrypto`) |
| `API error -8` | File not found — the link may be expired or the file was deleted |
| `API error -9` | Access denied — this file is private |
| `API error -4` or `-19` | Rate limited — wait a minute and try again |
| No download URL returned | The link expired or MEGA is rate-limiting your IP — try again |

## Disclaimer

This tool is intended for downloading files you own or have permission to download. Do not use it to download copyrighted material without authorization.

## License

MIT — free to use, modify, and distribute.
