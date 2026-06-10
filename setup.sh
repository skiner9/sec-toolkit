#!/bin/bash
echo "[*] Setting up sec-toolkit..."

# Create wordlists directory if it doesn't exist
mkdir -p tools/passaudit/wordlists

echo "[*] Downloading crackstation-human wordlist (~246MB)..."
curl -L "https://download.g0tmi1k.com/wordlists/large/crackstation-human-only.txt.gz" \
  -o tools/passaudit/wordlists/crackstation-human.txt.gz

echo "[*] Extracting..."
gunzip tools/passaudit/wordlists/crackstation-human.txt.gz

echo "[+] Done! Run the tool with:"
echo "    python3 tools/passaudit/passaudit.py --mode crack --hash <hash>"
