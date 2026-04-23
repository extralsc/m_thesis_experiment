#!/bin/bash
# Apply network emulation before starting the gateway.
# Simulates Raspberry Pi 4 LAN conditions: 50ms round-trip delay, 10ms jitter.
# Backed by: Diab et al. (arXiv 2512.02272), IoTSim-Edge (2020).
#
# Requires: iproute2 package + NET_ADMIN capability (set in docker-compose.yml).
tc qdisc add dev eth0 root netem delay 50ms 10ms 2>/dev/null || true
exec python src/gateway.py
