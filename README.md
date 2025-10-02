# Identify & Remove Suspicious Browser Extensions

## What I Did
Maine apne browser ke extensions ko check kiya aur dekha ki koi suspicious extension to nahi hai. Ye do tarike se kiya:  
1. Manual check via `chrome://extensions/` (Developer mode) — permissions aur unknown extensions ko dekha.  
2. Automated scan using `scan_extensions.py` — ye script suspicious permissions aur JS patterns ko flag karta hai.  

## Environment
- OS: Linux (Ubuntu/Kali)
- Browser: Chrome / Chromium
- Python: 3.x

## How to Run the Scanner
```bash
python3 scan_extensions.py
# output milega -> ./analysis/findings.md aur ./analysis/report.json


