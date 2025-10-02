# scan_extensions.py
# Simple heuristic scanner for Chrome/Chromium/Edge extension folders.
# Usage: python3 scan_extensions.py
import os, json, re, platform, argparse
from pathlib import Path

SUSPICIOUS_PERMS = {
    "cookies","history","management","nativeMessaging","webRequest",
    "<all_urls>","downloads","browsingData","sockets","clipboardWrite"
}
JS_PATTERNS = [
    (r"eval\s*\(", "eval("),
    (r"new\s+Function\s*\(", "new Function"),
    (r"atob\s*\(", "atob"),
    (r"unescape\s*\(", "unescape"),
    (r"fromCharCode\s*\(", "fromCharCode"),
    (r"XMLHttpRequest", "XMLHttpRequest"),
    (r"\.fetch\s*\(", "fetch("),
    (r"WebSocket\s*\(", "WebSocket"),
    (r"chrome\.runtime\.connectNative", "native messaging"),
    (r"chrome\.management", "chrome.management"),
    (r"document\.write\s*\(", "document.write"),
]
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")

def possible_chrome_paths():
    home = Path.home()
    sys = platform.system()
    paths = []
    if sys == "Windows":
        local = os.getenv("LOCALAPPDATA") or ""
        paths += [
            Path(local) / "Google" / "Chrome" / "User Data",
            Path(local) / "Microsoft" / "Edge" / "User Data"
        ]
    elif sys == "Darwin":
        paths += [
            home / "Library" / "Application Support" / "Google" / "Chrome",
            home / "Library" / "Application Support" / "Microsoft Edge"
        ]
    else:
        paths += [
            home / ".config" / "google-chrome",
            home / ".config" / "chromium",
        ]
    return [p for p in paths if p.exists()]

def scan_extensions(outdir="analysis"):
    out = Path(outdir); out.mkdir(exist_ok=True)
    findings = []
    for base in possible_chrome_paths():
        for profile in base.iterdir():
            ext_dir = profile / "Extensions"
            if not ext_dir.exists(): continue
            for ext_id in ext_dir.iterdir():
                if not ext_id.is_dir(): continue
                # Each extension has version folders
                for version in ext_id.iterdir():
                    manifest_path = version / "manifest.json"
                    if not manifest_path.exists(): continue
                    try:
                        m = json.load(manifest_path.open(encoding="utf-8", errors="ignore"))
                    except Exception as e:
                        continue
                    name = m.get("name", "<unknown>")
                    perms = set(m.get("permissions", []) + m.get("host_permissions", []))
                    flagged_perms = list(perms & SUSPICIOUS_PERMS)
                    suspicious_hits = []
                    # scan JS files
                    for root,_,files in os.walk(version):
                        for f in files:
                            if f.endswith(".js") or f.endswith(".html"):
                                fp = Path(root)/f
                                try:
                                    text = fp.read_text(encoding="utf-8", errors="ignore")
                                except:
                                    continue
                                for pat,desc in JS_PATTERNS:
                                    if re.search(pat, text):
                                        suspicious_hits.append({"file":str(fp.relative_to(version)), "pattern":desc})
                                if BASE64_RE.search(text):
                                    suspicious_hits.append({"file":str(fp.relative_to(version)), "pattern":"long_base64_blob"})
                    findings.append({
                        "profile": str(profile.name),
                        "ext_id": ext_id.name,
                        "version": version.name,
                        "name": name,
                        "flagged_permissions": flagged_perms,
                        "suspicious_hits": suspicious_hits,
                        "manifest": {"path": str(manifest_path), "raw": m}
                    })
    # write outputs
    with open(out/"report.json","w",encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    # human readable
    md = ["# Extension scan findings\n"]
    for item in findings:
        md.append(f"## {item['name']}  — {item['ext_id']} (profile: {item['profile']}, version: {item['version']})")
        md.append(f"- Flagged permissions: {', '.join(item['flagged_permissions']) or 'None'}")
        if item['suspicious_hits']:
            md.append("- Suspicious hits:")
            for h in item['suspicious_hits'][:10]:
                md.append(f"  - {h['file']}: {h['pattern']}")
        else:
            md.append("- Suspicious hits: None")
        md.append("\n")
    (out/"findings.md").write_text("\n".join(md), encoding="utf-8")
    print("Scan complete. Outputs in ./analysis (findings.md, report.json)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="analysis", help="output folder")
    args = parser.parse_args()
    scan_extensions(args.out)

