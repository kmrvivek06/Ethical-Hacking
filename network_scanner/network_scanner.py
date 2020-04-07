#!/usr/bin/env python

import scapy.all as scapy
#import optparse #Depricated
import argparse

#Using depricated Opt parse#########################################################
#
#def get_argument():
#    parser = optparse.OptionParser()
#    parser.add_option("-t", "--target", dest="target", help="Target ip to scan")
#    (options, arguments) = parser.parse_args()
#    return options
#
#####################################################################################

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target ip to scan")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-]Please specify a target or a range of target.")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=8, verbose=False)[0]
    
    clients_list = []
    for element in answered_list:
        client_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(result_list):
    print("IP\t\t\tMAC\n---------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])
        

options = get_argument()
scan_result = scan(options.target)
print_result(scan_result)