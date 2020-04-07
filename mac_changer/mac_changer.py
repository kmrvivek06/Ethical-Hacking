#!/usr/bin/env python

import subprocess
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC Address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New Mac Address")
    (values, arguments) = parser.parse_args()
    if not values.interface:
        parser.error("[-] Please specify an interface to change MAC")
    elif not values.new_mac:
        parser.error("[-] Please enter a new MAC")
    return values


def change_mac(interface, new_mac):
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])
    print("[+] Changed MAC of " + interface + " to " + new_mac)


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface])
    search_result = re.search(r"(\w{2}:){5}\w{2}", str(ifconfig_result))
    if search_result:
        return search_result.group(0)
    else:
        print("[-] Could not read current MAC Address")


options = get_arguments()
current_mac = get_current_mac(options.interface)
print("[*] Current MAC : " + str(current_mac))
if current_mac:
    change_mac(options.interface, options.new_mac)
    current_mac = get_current_mac(options.interface)
    if current_mac == options.new_mac:
        print("[+] MAC Address was successfully changed to " + current_mac)
    else:
        print("[-] Unable to change MAC Address")
