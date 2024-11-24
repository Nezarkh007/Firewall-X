import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

# Configuration
THRESHOLD = 40  # Maximum allowed packets per second per IP
BLOCK_DURATION = 300  # Block IPs for 5 minutes

# Initialize global data
packet_count = defaultdict(int)
start_time = time.time()
blocked_ips = {}  # Tracks blocked IPs with their block times


def read_ip_file(filename):
    """Reads and returns a set of IPs from a file."""
    try:
        with open(filename, "r") as file:
            return set(line.strip() for line in file)
    except FileNotFoundError:
        print(f"Warning: {filename} not found.")
        return set()


def is_nimda_worm(packet):
    """Checks if the packet contains a Nimda worm signature."""
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
        return "GET /scripts/root.exe" in payload
    return False


def log_event(message):
    """Logs events to a single log file."""
    log_file = "firewall_log.txt"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(log_file, "a") as file:
        file.write(f"[{timestamp}] {message}\n")


def block_ip(ip):
    """Blocks an IP using iptables and logs the event."""
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips[ip] = time.time()
    log_event(f"Blocked IP: {ip}")


def unblock_expired_ips():
    """Unblocks IPs that have been blocked longer than BLOCK_DURATION."""
    current_time = time.time()
    for ip, block_time in list(blocked_ips.items()):
        if current_time - block_time > BLOCK_DURATION:
            os.system(f"iptables -D INPUT -s {ip} -j DROP")
            log_event(f"Unblocked IP: {ip}")
            del blocked_ips[ip]


def packet_callback(packet):
    """Processes each packet and applies firewall rules."""
    if not packet.haslayer(IP):
        return  # Skip non-IP packets

    src_ip = packet[IP].src

    # Skip whitelisted IPs
    if src_ip in whitelist_ips:
        return

    # Block blacklisted IPs immediately
    if src_ip in blacklist_ips and src_ip not in blocked_ips:
        block_ip(src_ip)
        return

    # Block IPs with Nimda worm signature
    if is_nimda_worm(packet):
        if src_ip not in blocked_ips:
            block_ip(src_ip)
        return

    # Track packet rates
    packet_count[src_ip] += 1
    current_time = time.time()

    # Check and block IPs exceeding the threshold
    if current_time - start_time >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / (current_time - start_time)
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                block_ip(ip)

        packet_count.clear()
        start_time = current_time

        # Unblock expired IPs
        unblock_expired_ips()


if __name__ == "__main__":
    # Ensure the script is run as root
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    # Load whitelist and blacklist
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)
