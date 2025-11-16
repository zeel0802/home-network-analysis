# SANITIZE.md

This repository only publishes sanitized packet captures. Steps taken before publishing any PCAP:

1. Remove application-layer payloads (HTTP bodies, form data) to avoid leaking credentials.
2. Replace public IP addresses with hashed placeholders (consistent across the capture).
3. Verify no hostnames, emails, or other PII remain.
4. Capture only traffic from devices/networks owned by the author.

Use `scripts/sanitize_pcap.py` to sanitize a raw capture before committing to this repo.
