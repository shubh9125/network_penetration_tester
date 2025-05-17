# Network Penetration Testing System

A simple Python GUI application for basic network penetration testing tasks including:

- IP range scanning
- Port scanning
- Banner grabbing and vulnerability checking
- Password strength analysis
- Optional C-based port scanner integration

## Features

- **Port Scanning**: Scans ports 1–1024 for a given subnet.
- **Banner Grabbing**: Retrieves and analyzes service banners.
- **Vulnerability Detection**: Checks banners against known CVEs.
- **Password Checker**: Identifies weak passwords.
- **C Integration**: Runs a compiled C scanner if present.

## Requirements

- Python 3.x
- Tkinter (usually included)
- Compatible with Unix/Windows

## Setup

```bash
git clone https://github.com/yourusername/network-pentest-tool.git
cd network-pentest-tool
pip install -r requirements.txt
python shubh91.py
```

If using the C scanner, compile it first:

```bash
gcc portscanner.c -o portscanner
```

## License

[MIT](LICENSE)
