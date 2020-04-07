#!/usr/bin/env python
import netfilterqueue
import sys   #Only in python 2

packets_count = 0
def process_packet(packet):
    global packets_count
    packets_count = packets_count + 1
    packet.drop()
    print("\r[+] Packets Dropped: " + str(packets_count)),
    sys.stdout.flush()
    #Python 3
    #print("\r[+] Packets sent: " + str(sent_packets_count), end="")

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[*] Detected CTRL + C ....... Quitting.")