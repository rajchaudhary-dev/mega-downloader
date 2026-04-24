# Megadl 🔽

A simple, no-nonsense CLI tool to download public files from MEGA.nz — no browser, no ads, no BS.

## Features

- Works with both old and new MEGA link formats
- Decrypts files on the fly using the key embedded in the link
- Shows a real-time download progress bar
- Saves the file with its original filename
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
python megadl.py '<your_mega_link>'
```

### Examples

```bash
# New-style link
python megadl.py 'https://mega.nz/file/ABC12345#secretkeyhere'

# Old-style link
python megadl.py 'https://mega.nz/#!ABC12345!secretkeyhere'
```

The file will be saved in your current directory with its original filename.

## How It Works

MEGA encrypts all files client-side. The decryption key is embedded directly in the share link (after the `#`), which means MEGA's servers never see it — but neither does anyone else unless you share the full link.

This tool follows 3 steps:

1. **Fetch metadata** — calls the MEGA API with the file ID to get the download URL, file size, and encrypted attributes
2. **Download** — streams the raw encrypted file from MEGA's storage servers
3. **Decrypt** — decrypts on the fly using AES-128-CTR with the key derived from the link

### Key Derivation

The 256-bit key in the URL is XOR-folded into a 128-bit AES key and a 64-bit nonce (used as the CTR IV). The filename is recovered by decrypting the `at` (attributes) field using AES-128-CBC.

## Troubleshooting

| Problem | Fix |
|---|---|
| `python not found` | Try `python3` instead of `python` |
| `pip not found` | Try `pip3` |
| `API error` | The link may be expired or the file was removed |
| `No module named 'Crypto'` | Run `pip install pycryptodome` (not `pycrypto`) |

## Disclaimer

This tool is intended for downloading files you own or have permission to download. Do not use it to download copyrighted material without authorization.

## License

MIT — free to use, modify, and distribute.
