#!/usr/bin/env bash
set -e
echo "[*] Running bootstrap: install system deps + pip requirements"

# Debian/Ubuntu instructions (edit for your distro)
if [ -x "$(command -v apt-get)" ]; then
  sudo apt-get update
  sudo apt-get install -y build-essential libssl-dev libffi-dev python3-dev \
    libxml2-dev libxslt-dev zlib1g-dev graphviz wkhtmltopdf curl
fi

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip setuptools wheel

# Install Python deps. If playwright fails, install without it and instruct user.
if pip install -r requirements.txt; then
  echo "[*] pip install succeeded"
else
  echo "[!] pip install had issues. Trying again without playwright..."
  grep -v "playwright" requirements.txt > requirements.noplay.txt
  pip install -r requirements.noplay.txt
  echo "[*] installed without playwright. If you want screenshots via Playwright, run:"
  echo "    .venv/bin/pip install playwright && .venv/bin/playwright install"
fi

echo "[*] If you want Playwright browsers, run: .venv/bin/playwright install"
echo "[*] Bootstrap done. Activate venv with: source .venv/bin/activate"

