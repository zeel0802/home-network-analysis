# Home Network Traffic Analysis & Threat Report
**Live Dashboard:** [https://zeel0802.github.io/home-network-analysis/report.html]

**Brief:** capture and analyze local network traffic (PCAP). Automatically extract top-talkers, protocol distribution, DNS queries, and suspicious connection heuristics. Generates a static interactive report (`docs/report.html`) that can be hosted on GitHub Pages.

## What’s included
- `scripts/analyze_pcap.py` — PCAP analyzer (Python, Scapy). CLI usage.
- `scripts/sanitize_pcap.py` — sanitize PCAP before publishing (removes payloads, redacts external IPs).
- `pcaps/` — example/sanitized PCAP(s) (do not publish raw private captures).
- `docs/report.html` — interactive report (Chart.js) that reads `docs/summary.json`.
- `docs/summary.json` — output from the analyzer.

## Quick start (assumes `.venv` activated)

```bash
# 1) Install dependencies (inside your venv)
python -m pip install scapy

# 2) Sanitize a capture (only if you intend to publish)
python scripts/sanitize_pcap.py pcaps/raw.pcap pcaps/home-sample-sanitized.pcap

# 3) Analyze (generate docs/summary.json and docs/report.md/html)
python scripts/analyze_pcap.py -i pcaps/home-sample-sanitized.pcap -o docs/

# 4) Serve the report locally
python -m http.server 8000
# then open: http://localhost:8000/docs/report.html
