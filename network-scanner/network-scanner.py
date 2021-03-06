import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()
    return options

def makeArppacket(ip, mac):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst=mac)
    return broadcast/arp_request

def sendpacketAndGetAnswered(packet):
    return scapy.srp(packet, timeout=1, verbose=False)[0]

def formatAnswers(answers):
    scan_result = {}
    for answered_packet in answers:
        answer = answered_packet[1]
        scan_result[answer.psrc] = answer.hwsrc
    return scan_result

def printAnswersInTable(answer_dict, key, value):
    print(key, '\t'*3, value, '\n' + '-'*45)
    for i in answer_dict:
        print(i, '\t'*2, answer_dict[i])

options = get_arguments()
pkg = makeArppacket(options.target, 'ff:ff:ff:ff:ff:ff')
answer = sendpacketAndGetAnswered(pkg)
answer_dict = formatAnswers(answer)
printAnswersInTable(answer_dict, 'IP', 'MAC ADDRESS')