# One-man-army (cybercli)

This is a reconnaissance CLI skeleton (educational / authorized testing only).
It performs passive and basic active recon: whois, DNS, crt.sh, HTTP probing,
quick TCP connect scan, optional nmap, screenshots, basic dir brute, secret scans,
asset graph and a single-file HTML report.

**Run example**:
  python3 -m cybercli.main recon start example.com --osint --deep --screens --tra --graph --report --verbose --vibes

**Important**: Only run against assets you are authorized to test.

See `bootstrap.sh` for required system deps.

