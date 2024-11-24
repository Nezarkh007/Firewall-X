import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

# Configuration
THRESHOLD = 40  # Packets per second
BLOCK_DURATION = 300  # Duration to block IPs in seconds

print(f"Threshold: {THRESHOLD} packets/second")

# Global variables
packet_count = defaultdict(int)
start_time = [time.time()]
blocked_ips = {}  # Tracks blocked IPs with their block time

def block_ip(ip):
    """Blocks the specified IP using iptables."""
    print(f"Blocking IP: {ip}")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips[ip] = time.time()

def unblock_ips():
    """Unblocks IPs that have been blocked longer than BLOCK_DURATION."""
    current_time = time.time()
    to_unblock = [ip for ip, block_time in blocked_ips.items() if current_time - block_time > BLOCK_DURATION]

    for ip in to_unblock:
        print(f"Unblocking IP: {ip}")
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
        del blocked_ips[ip]

def packet_callback(packet):
    """Callback function to process each packet."""
    # Validate packet
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    # Check time interval
    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:  # Evaluate every second
        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                block_ip(ip)

        packet_count.clear()
        start_time[0] = current_time

        # Unblock expired IPs
        unblock_ips()

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    print("Monitoring network traffic...")
    try:
        sniff(filter="ip", prn=packet_callback)
    except KeyboardInterrupt:
        print("Exiting...")
        # Optional cleanup for blocked IPs
        for ip in list(blocked_ips.keys()):
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
