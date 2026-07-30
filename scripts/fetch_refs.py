"""Fetch and parse the awesome-ics-writeups README into a vendor-keyed JSON file.

Run from the repo root:
    python scripts/fetch_refs.py

Output: src/data/references.json

Re-run anytime to pull updates from the upstream repo.
Source: https://github.com/neutrinoguy/awesome-ics-writeups
"""
from __future__ import annotations

import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

README_URL = (
    "https://raw.githubusercontent.com/neutrinoguy/awesome-ics-writeups/main/README.md"
)
OUT_PATH = Path(__file__).resolve().parent.parent / "src" / "data" / "references.json"

# Keyword rules: vendor slug -> list of lowercase substrings to match against title+url.
# Earlier entries win (first match wins per entry).
VENDOR_RULES: list[tuple[str, list[str]]] = [
    ("malware",    ["triton", "trisis", "industroyer", "pipedream", "chernovite",
                    "cosmicenergy", "havex", "fuxnet", "iocontrol", "acidrain",
                    "powerdrop", "greyenergy", "crashoverride", "blackjack"]),
    ("beckhoff",   ["beckhoff", "twincat", "ads-protocol"]),
    ("siemens",    ["siemens", "/s7-", "-s7-", "s7comm", "scalance", "sinec",
                    "simatic", "step-7", "tia-portal", "profinet", "sinamics",
                    "siemens-discovery"]),
    ("schneider",  ["schneider", "modicon", "m340", "m580", "ecostruxure", "umas",
                    "m221", "quantum-plc", "premium-plc", "unity-pro"]),
    ("rockwell",   ["rockwell", "allen-bradley", "factorytalk", "rslogix",
                    "compactlogix", "controllogix", "micrologix", "logix-"]),
    ("mitsubishi", ["mitsubishi", "melsec", "slmp", "gx-works", "mxcomponent"]),
    ("omron",      ["omron", "sysmac", "cx-programmer", "fins-"]),
    ("phoenix",    ["phoenix-contact", "proconos", "plcnext"]),
    ("ewon",       ["ewon", "hms-networks"]),
    ("modbus",     ["modbus"]),
    ("iec104",     ["iec-104", "iec104", "iec60870", "60870-5-104",
                    "industroyer2-nozomi"]),
    ("enip",       ["ethernet-ip", "ethernetip", "enip", "cip-protocol"]),
    ("snmp",       ["snmp"]),
    ("ics-general", ["scada", "industrial-control", "-plc-", "plc-hacking",
                     "ics-tool", "ot-iot", "ot-security", "dnp3",
                     "iec-61850", "opc-ua", "profibus", "hack-the-port",
                     "incontroller", "ics-historian"]),
]


def classify(title: str, url: str) -> str:
    text = (title + " " + url).lower()
    for slug, keywords in VENDOR_RULES:
        if any(kw in text for kw in keywords):
            return slug
    return "general"


def title_from_url(url: str) -> str:
    """Derive a human-readable title from a URL slug."""
    parsed = urllib.parse.urlparse(url)
    # Use the last non-empty path component
    parts = [p for p in parsed.path.split("/") if p]
    if not parts:
        return parsed.netloc
    slug = parts[-1]
    # Strip common suffixes
    slug = re.sub(r"\.(pdf|html?|aspx?)$", "", slug, flags=re.IGNORECASE)
    # Hyphens and underscores → spaces, title case
    slug = slug.replace("-", " ").replace("_", " ")
    # Collapse multiple spaces
    slug = re.sub(r"\s+", " ", slug).strip()
    return slug.title() if slug else parsed.netloc


def looks_like_nav_link(url: str) -> bool:
    """Skip in-page anchor links and image/badge URLs."""
    if "#" in url and "github.com/neutrinoguy" in url:
        return True
    if "sindresorhus/awesome" in url:
        return True
    if "img.shields.io" in url:
        return True
    if "cdn.rawgit.com" in url:
        return True
    return False


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "scadaver-refs/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")


def parse(readme: str) -> list[dict]:
    entries: list[dict] = []
    current_source = "Unknown"

    # Match bare URL list items (with optional trailing annotations like [Malware])
    bare_url_re = re.compile(r"^\s*-\s+(https?://\S+)")
    # Match markdown links [Title](url) — NOT image links (no ! prefix)
    md_link_re = re.compile(r"(?<!!)\[([^\]]+)\]\((https?://[^\)]+)\)")

    for line in readme.splitlines():
        # Section headings → source firm name
        m = re.match(r"^###\s+(.+)", line)
        if m:
            current_source = m.group(1).strip()
            continue

        # Try bare URL first
        m = bare_url_re.match(line)
        if m:
            url = m.group(1).rstrip("/ ")
            # Some URLs have trailing emoji/badges — strip
            url = re.split(r"\s", url)[0].rstrip("/ ")
            if not looks_like_nav_link(url):
                title = title_from_url(url)
                vendor = classify(title, url)
                entries.append({
                    "vendor": vendor,
                    "title": title,
                    "url": url,
                    "source": current_source,
                })
            continue

        # Try markdown links (covers image-link header rows, but filter those out)
        for title, url in md_link_re.findall(line):
            url = url.strip().rstrip("/ ")
            title = title.strip()
            if not title or looks_like_nav_link(url):
                continue
            vendor = classify(title, url)
            entries.append({
                "vendor": vendor,
                "title": title,
                "url": url,
                "source": current_source,
            })

    return entries


def main() -> None:
    print(f"Fetching {README_URL} ...")
    try:
        readme = fetch(README_URL)
    except Exception as exc:
        print(f"Error fetching README: {exc}", file=sys.stderr)
        sys.exit(1)

    entries = parse(readme)

    # Deduplicate by URL
    seen_urls: set[str] = set()
    unique: list[dict] = []
    for e in entries:
        if e["url"] not in seen_urls:
            seen_urls.add(e["url"])
            unique.append(e)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(
        json.dumps(unique, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    by_vendor: dict[str, int] = {}
    for e in unique:
        by_vendor[e["vendor"]] = by_vendor.get(e["vendor"], 0) + 1

    print(f"Wrote {len(unique)} references to {OUT_PATH}")
    for vendor, count in sorted(by_vendor.items(), key=lambda x: -x[1]):
        print(f"  {vendor:<16} {count}")


if __name__ == "__main__":
    main()
