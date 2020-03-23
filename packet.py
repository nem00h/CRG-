from scapy.all import *
def showPacket(packet):
    
    srcMAC = packet[0][0].src
    dstMAC = packet[0][0].dst
    srcIp = packet[0][1].src
    dstIp = packet[0][1].dst
    print("-----------------------------------------------------------------------")
    print("[+]source      MAC address/IP address = {}/{}".format(srcMAC,srcIp))
    print("[+]destination MAC address/IP address = {}/{}".format(dstMAC,dstIp))
    print("-----------------------------------------------------------------------\n")
def sniffing(filter):
    print("[*]Start Sniffing...\n")
    while True:
        sniff(filter = filter, prn = showPacket)


if __name__ == "__main__":
    filter = 'ip'
    sniffing(filter)