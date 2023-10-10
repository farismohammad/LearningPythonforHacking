# Date : October 10th 2023
# Original Author : Zaid Sabih , Zsecurity
# Edited by : Faris Mohammad 
# Revision : 2
# Note :  This program can be run as a command in a terminal.

# Description : This program changes scans the network and returns the connected devices IP and MAC.


import scapy.all as scapy
import argparse
 
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    options = parser.parse_args()
    return options
 
def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
 
    clients_list = []
    for element in answered:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwrc}
        clients_list.append(client_dict)
    return clients_list
 
def print_result(result_list):
    print("IP\t\tMAC Address\n--------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["MAC"])
 
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)