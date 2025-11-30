# DNS Spoofer & ARP Poisoner (Educational)

> **Disclaimer:**  
> This project is for **educational use only** in controlled lab environments that you own or have explicit permission to test.  
> Do **not** use this tool on networks, machines, or domains you do not control. Misuse may be illegal.

This repository contains a Python script that performs **ARP poisoning** to establish a man-in-the-middle position between a victim and the gateway, and then **spoofs DNS responses** so that DNS queries are resolved to the attacker's IP address.  

The script was built as a mini-project to practice low-level networking and Python with Scapy, and to demonstrate how DNS spoofing works at the packet level.

---

## Features

- **ARP Poisoning**
  - Continuously poisons ARP caches of both the victim and the gateway
  - Establishes a man-in-the-middle (MITM) position

- **DNS Spoofing**
  - Listens for DNS requests (`UDP/53`)
  - Spoofs DNS responses so queried domains resolve to the attacker's IP (`my_ip`)

---

## How It Works (High-Level)

1. The script:
   - Asks for the victim’s IP address.
   - Automatically discovers the gateway IP using the system routing table.
   - Resolves the MAC addresses of the victim and the gateway.

2. Two background threads perform **ARP poisoning**:
   - One poisons the victim, pretending to be the gateway.
   - One poisons the gateway, pretending to be the victim.

3. While poisoning runs, the main thread:
   - Sniffs DNS traffic on `udp port 53`
   - For each DNS query:
     - Extracts the requested domain
     - Crafts and sends a spoofed DNS response with `rdata` set to the attacker’s IP

---

## Requirements

- **Python**: 3.8+
- **OS**: Linux (tested on Kali-like setups)
- **Root privileges** (for Scapy / raw sockets / ARP poisoning)
- Network interface named `eth0` (or update the script to match your interface)

---

## Installation

```bash
git clone https://github.com/Sammy-Alawar/scapy-dns-spoofer.git
cd scapy-dns-spoofer
