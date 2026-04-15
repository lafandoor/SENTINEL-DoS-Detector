#!/usr/bin/env python3
"""
DoS Detection System - Alert Cooldown Enabled
Author: Youssef Moataz
"""

import sys
import time
import signal
from collections import defaultdict
from datetime import datetime

from scapy.all import sniff, IP, TCP, ICMP, UDP

# Config
INTERFACE = "lo"
TIME_WINDOW = 5

SYN_THRESHOLD = 100
ICMP_THRESHOLD = 50
UDP_THRESHOLD = 200
PORT_SCAN_THRESHOLD = 20
ALERT_COOLDOWN = 5

LOG_FILE = "dos_detection_log.txt"

# State Tracking
syn_count = defaultdict(int)
icmp_count = defaultdict(int)
udp_count = defaultdict(int)
port_targets = defaultdict(set)
last_alert_time = defaultdict(float)

total_packets = 0
alert_log = []
window_start = time.time()

# Logging
def log_alert(message):
    timestamp = datetime.now().strftime('%H:%M:%S')
    msg = f"[{timestamp}] [ALERT] {message}"
    print(msg)
    alert_log.append(msg)
    with open(LOG_FILE, "a") as f:
        f.write(msg + "\n")

def reset_counters():
    global window_start
    syn_count.clear()
    icmp_count.clear()
    udp_count.clear()
    port_targets.clear()
    window_start = time.time()

def check_thresholds(ip):
    current_time = time.time()

    if syn_count[ip] >= SYN_THRESHOLD and (current_time - last_alert_time[ip] > ALERT_COOLDOWN):
        log_alert(f"SYN FLOOD detected from {ip} ({syn_count[ip]} packets)")
        last_alert_time[ip] = current_time

    if icmp_count[ip] >= ICMP_THRESHOLD and (current_time - last_alert_time[ip] > ALERT_COOLDOWN):
        log_alert(f"ICMP FLOOD detected from {ip} ({icmp_count[ip]} packets)")
        last_alert_time[ip] = current_time

    if udp_count[ip] >= UDP_THRESHOLD and (current_time - last_alert_time[ip] > ALERT_COOLDOWN):
        log_alert(f"UDP FLOOD detected from {ip} ({udp_count[ip]} packets)")
        last_alert_time[ip] = current_time

    if len(port_targets[ip]) >= PORT_SCAN_THRESHOLD and (current_time - last_alert_time[ip] > ALERT_COOLDOWN):
        log_alert(f"PORT SCAN detected from {ip} ({len(port_targets[ip])} ports)")
        last_alert_time[ip] = current_time

# Packet Handler
def packet_handler(packet):
    global total_packets, window_start

    if time.time() - window_start >= TIME_WINDOW:
        reset_counters()

    if not packet.haslayer(IP):
        return

    total_packets += 1
    src = packet[IP].src

    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if flags & 0x02 and not flags & 0x10:
            syn_count[src] += 1
        port_targets[src].add(packet[TCP].dport)

    elif packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            icmp_count[src] += 1

    elif packet.haslayer(UDP):
        udp_count[src] += 1
        port_targets[src].add(packet[UDP].dport)

    check_thresholds(src)

def final_report():
    print("\n--- FINAL REPORT ---")
    print(f"Total packets processed: {total_packets}")
    print(f"Total alerts generated: {len(alert_log)}")
    print("--------------------")

def stop(sig, frame):
    print("\nStopping detector...")
    final_report()
    sys.exit(0)

def main():
    import os
    if os.geteuid() != 0:
        print("[ERROR] Please run with sudo")
        sys.exit(1)

    signal.signal(signal.SIGINT, stop)

    print(f"[*] Starting Sentinel DoS Monitor on interface {INTERFACE}...")
    print(f"[*] Window: {TIME_WINDOW}s | Cooldown: {ALERT_COOLDOWN}s")
    print("[*] Press Ctrl+C to stop.\n")

    sniff(iface=INTERFACE, prn=packet_handler, store=False)

if __name__ == "__main__":
    main()