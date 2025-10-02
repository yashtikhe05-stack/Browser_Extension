## Objective
The goal of this project is to identify and remove potentially malicious or privacy-invading browser extensions, and to document the findings for security awareness.

## Methodology
The browser extensions were analyzed using two approaches:
1. **Manual Inspection**: Accessed `chrome://extensions/` (Developer mode) to review installed extensions, their permissions, and identify any unknown or suspicious extensions.
2. **Automated Scan**: Utilized the `scan_extensions.py` script to detect extensions with potentially risky permissions and suspicious JavaScript patterns.


