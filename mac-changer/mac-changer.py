import argparse
import subprocess
import sys
import re

def run_terminal_command(commands_array):
    try:
        result = subprocess.check_output(commands_array, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        error_message = e.output.decode("utf-8") 
        if "Operation not permitted" in error_message:
            print("[Permission] You should run this as root or with sudo")
        elif "No such device" in error_message:
            print("[Interface] Specified interface is invalid")
        else:
            print(error_message)
        sys.exit()
    else:
        return result
        

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="interface to change the mac")
    parser.add_argument("-m", "--mac", dest="mac", help="mac to use in the new interface")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info")
    if not options.mac:
        parser.error("[-] Please specify a mac, use --help for more info")
    return options

def change_mac(interface, new_mac):
    print("> turning off network card")
    run_terminal_command(["ifconfig", interface, "down"])
    print("> changing mac...")
    run_terminal_command(["ifconfig", interface, "hw", "ether", new_mac])
    print("> turning on network card")
    run_terminal_command(["ifconfig", interface, "up"])

def get_current_mac(interface):
    ifconfig_result = run_terminal_command(["ifconfig", interface])
    mac_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

    if mac_search_result:
        return mac_search_result.group(0)
    else:
        print("[-] Could not find mac adress for verification")
        return None

def compare_macs(argument_mac, actual_mac):
    if actual_mac is None:
        return
    if actual_mac == argument_mac:
        print("> success, mac changed!")
    else:
        print("> error changing mac to new one")


arguments = get_arguments()
change_mac(arguments.interface, arguments.mac)
print("> verifying change...")
actual_mac = get_current_mac(arguments.interface)
compare_macs(arguments.mac, actual_mac)