#!/bin/bash
# BurpNext Installation — Kali Linux
echo ""
echo "  ██████╗ ██╗   ██╗██████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗████████╗"
echo "  Installing BurpNext WAPT Platform..."
echo ""

pip install aiohttp typer rich --break-system-packages -q
echo "[✓] Dependencies installed"

echo ""
echo "  Add to your cybercli/main.py (after other add_typer calls):"
echo "  ─────────────────────────────────────────────────────────────"
cat ADD_TO_MAIN.py
echo ""
echo "  ─────────────────────────────────────────────────────────────"
echo ""
echo "  Then run:"
echo "    cybercli burp scan --target https://testphp.vulnweb.com"
echo "    cybercli burp scan --target https://example.com --timeout 30"
echo "    cybercli burp scan --target https://example.com --ai-provider groq --ai-key gsk_..."
echo ""
