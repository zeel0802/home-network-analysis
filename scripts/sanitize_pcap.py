#!/usr/bin/env python3
# scripts/sanitize_pcap.py

import sys
import os
import hashlib
from scapy.all import rdpcap, wrpcap, IP, Raw

def mask_ip(ip):
    # keep private RFC1918 as-is for readability; mask public IPs
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return ip
    h = hashlib.sha1(ip.encode()).hexdigest()[:8]
    return f"REDACTED-{h}"

def sanitize(infile, outfile):
    pkts = rdpcap(infile)
    for pkt in pkts:
        if IP in pkt:
            pkt[IP].src = mask_ip(pkt[IP].src)
            pkt[IP].dst = mask_ip(pkt[IP].dst)
        # remove application payloads if present
        if Raw in pkt:
            # replace with empty bytes
            pkt[Raw].load = b""
            # drop Raw layer entirely if desired:
            try:
                pkt.remove_payload()
            except Exception:
                pass

    outdir = os.path.dirname(outfile) or "."
    os.makedirs(outdir, exist_ok=True)
    wrpcap(outfile, pkts)
    print("✅ Sanitized pcap written to", outfile)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: sanitize_pcap.py <input.pcap> <output.pcap>")
        raise SystemExit(1)
    sanitize(sys.argv[1], sys.argv[2])
