#!/usr/bin/env python3
"""
extract_iocs.py - Pull indicators of compromise out of a suspicious email.

Usage:
    python3 extract_iocs.py suspicious.eml
    python3 extract_iocs.py suspicious.eml --json > iocs.json

Works on raw .eml files (or any text file). Uses only the Python standard
library, so it runs on any analyst workstation without installs.

What it extracts:
  - Key headers (From, Reply-To, Return-Path, Subject, Message-ID)
  - Authentication results (SPF / DKIM / DMARC verdicts)
  - Received hops (the path the email took)
  - URLs, domains, IPv4 addresses, email addresses
  - Attachments with MD5 / SHA-256 hashes (ready for VirusTotal lookups)

Defanged output (hxxp, [.]) is printed by default so IOCs can be pasted
safely into tickets and chat without becoming clickable.
"""

import argparse
import email
import hashlib
import json
import re
import sys
from email import policy

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
DOMAIN_FROM_URL_RE = re.compile(r"https?://([^/:?#\s]+)", re.IGNORECASE)

PRIVATE_PREFIXES = ("10.", "127.", "192.168.", "169.254.", "0.") + tuple(
    f"172.{i}." for i in range(16, 32)
)


def defang(value: str) -> str:
    return value.replace("http", "hxxp").replace(".", "[.]")


def get_bodies(msg):
    """Return all text/plain and text/html parts as one string."""
    chunks = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() in ("text/plain", "text/html"):
            try:
                chunks.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                payload = part.get_payload(decode=True) or b""
                chunks.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(chunks)


def get_attachments(msg):
    attachments = []
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        data = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return attachments


def parse_auth_results(msg):
    raw = " ".join(msg.get_all("Authentication-Results", []) or [])
    verdicts = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", raw, re.IGNORECASE)
        verdicts[mech] = m.group(1).lower() if m else "not found"
    return verdicts


def analyze(path):
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=policy.default)

    headers = {h: str(msg.get(h, "")) for h in
               ("From", "Reply-To", "Return-Path", "To", "Subject", "Date", "Message-ID")}
    received = [str(r) for r in (msg.get_all("Received", []) or [])]

    body = get_bodies(msg)
    header_blob = "\n".join(received)

    urls = sorted(set(u.rstrip(".,;") for u in URL_RE.findall(body)))
    domains = sorted(set(d.lower() for d in DOMAIN_FROM_URL_RE.findall(" ".join(urls))))
    ips = sorted(set(ip for ip in IPV4_RE.findall(header_blob + "\n" + body)
                     if not ip.startswith(PRIVATE_PREFIXES)))
    emails = sorted(set(EMAIL_RE.findall(body + " " + " ".join(headers.values()))))

    return {
        "headers": headers,
        "authentication": parse_auth_results(msg),
        "received_hops": len(received),
        "urls": urls,
        "domains": domains,
        "public_ips": ips,
        "email_addresses": emails,
        "attachments": get_attachments(msg),
    }


def red_flags(report):
    flags = []
    h = report["headers"]
    auth = report["authentication"]
    from_dom = h["From"].split("@")[-1].strip("> ").lower() if "@" in h["From"] else ""
    reply_dom = h["Reply-To"].split("@")[-1].strip("> ").lower() if "@" in h["Reply-To"] else ""
    if reply_dom and from_dom and reply_dom != from_dom:
        flags.append(f"Reply-To domain ({reply_dom}) differs from From domain ({from_dom})")
    for mech, verdict in auth.items():
        if verdict not in ("pass", "not found"):
            flags.append(f"{mech.upper()} result is '{verdict}'")
    risky_ext = (".exe", ".js", ".vbs", ".scr", ".iso", ".img", ".hta", ".docm", ".xlsm", ".lnk", ".html", ".htm")
    for att in report["attachments"]:
        if att["filename"].lower().endswith(risky_ext):
            flags.append(f"High-risk attachment type: {att['filename']}")
    for d in report["domains"]:
        if d.count("-") >= 2 or d.startswith("xn--") or any(t in d for t in ("login", "verify", "secure", "account")):
            flags.append(f"Suspicious-looking domain: {d}")
    return flags


def print_report(report):
    print("=" * 60)
    print(" PHISHING TRIAGE - IOC EXTRACTION REPORT")
    print("=" * 60)
    for k, v in report["headers"].items():
        print(f"{k:<12}: {v}")
    print(f"\nAuth results : {report['authentication']}")
    print(f"Received hops: {report['received_hops']}")
    sections = [("URLs", report["urls"]), ("Domains", report["domains"]),
                ("Public IPs", report["public_ips"]), ("Email addresses", report["email_addresses"])]
    for title, items in sections:
        print(f"\n[{title}] ({len(items)})")
        for item in items:
            print(f"  - {defang(item) if title in ('URLs', 'Domains', 'Public IPs') else item}")
    print(f"\n[Attachments] ({len(report['attachments'])})")
    for a in report["attachments"]:
        print(f"  - {a['filename']} ({a['content_type']}, {a['size_bytes']} bytes)")
        print(f"      MD5   : {a['md5']}")
        print(f"      SHA256: {a['sha256']}")
    flags = red_flags(report)
    print(f"\n[Red flags] ({len(flags)})")
    for f in flags:
        print(f"  ! {f}")
    print("\nNext step: check the hashes, domains and IPs in VirusTotal / AbuseIPDB / URLScan.")


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from a suspicious email (.eml)")
    parser.add_argument("eml", help="path to the .eml file")
    parser.add_argument("--json", action="store_true", help="output JSON instead of a text report")
    args = parser.parse_args()
    try:
        report = analyze(args.eml)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.eml}")
    if args.json:
        report["red_flags"] = red_flags(report)
        print(json.dumps(report, indent=2))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
