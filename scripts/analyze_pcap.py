from scapy.all import rdpcap, IP, TCP, UDP, DNS
import json
from collections import Counter
import sys, os

def analyze_pcap(pcap_file, out_folder):
    packets = rdpcap(pcap_file)
    src_ips = Counter()
    dst_ips = Counter()
    protocols = Counter()
    dns_queries = Counter()

    for pkt in packets:
        if IP in pkt:
            src_ips[pkt[IP].src] += 1
            dst_ips[pkt[IP].dst] += 1
            if TCP in pkt:
                protocols["TCP"] += 1
            elif UDP in pkt:
                protocols["UDP"] += 1
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qd:
            dns_queries[pkt.getlayer(DNS).qd.qname.decode(errors="ignore")] += 1

    summary = {
        "top_src": src_ips.most_common(5),
        "top_dst": dst_ips.most_common(5),
        "protocols": protocols.most_common(),
        "top_dns": dns_queries.most_common(5),
        "suspicious": []
    }

    out_path = os.path.join(out_folder, "summary.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"✅ Analysis complete. Saved summary to {out_path}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze_pcap.py <input.pcap> <output_folder>")
        sys.exit(1)
    analyze_pcap(sys.argv[1], sys.argv[2])
