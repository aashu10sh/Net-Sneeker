import scapy.all as scapy
import optparse
import subprocess
import os
from colorama import Fore, Back, Style
cow = 98;
import terminal_banner
banner_txt = "Net-Sneeker"
usebanner = terminal_banner.Banner(banner_txt)



def checkRootandInstall(): # check if the script is running as root and install scapy and terminal_banner
    rootval = os.getuid()
    if  str(rootval) != "0":
        print(Fore.RED+"Please use this script as root, Permission Denied")
    else:
        print("Installing Scapy module via pip3,make sure you have pip3 installed")
        outp = subprocess.check_output(["pip3","install","scapy","terminal_banner"]).decode("utf-8")
        if "already" in outp:
            print(Fore.GREEN+"Scapy seems to have already been installed!!")
        else:
            print(Fore.YELLOW+"Module should be installed now,if it did not install, please manually install it")




def scan(ip): #scapy.arping()>> using scapy to find devices in the netmask
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcastReq = broadcast/arpRequest
    (answered_list, unanswered_list) = scapy.srp(broadcastReq,timeout=2,verbose=0)
    return answered_list



def parser(): #parsing the input
    parser = optparse.OptionParser()
    parser.add_option("-i","--ip-range",dest="ipRange",help="Use this to specify an ip address or a netmask,use --help for more info")
    (options,arguments)=parser.parse_args()
    if options.ipRange==None:
        print(Fore.RED+"Please specify an ip address or netmask, use --help for more info")
        exit()
    return options.ipRange;
    pass

def printResults(answered_list,usebanner): #printing the results
    print(Fore.MAGENTA+str(usebanner))
    print("Dropping Mac Addresses and their Corresponding IP Addresses")
    for element in answered_list:
        print(Fore.RED+"-------------------------------------------------------------------------------")
        print(Fore.GREEN+"MAC Address:: "+str(element[1].hwsrc))
        print(Fore.CYAN+"IP Address:: "+str(element[1].psrc))
        print(Fore.RED+"-------------------------------------------------------------------------------")
    print(Fore.BLUE+"Made with <3, by A5H")


#calling necessary functions
checkRootandInstall()
ip = parser()
answered_list = scan(ip)
printResults(answered_list, usebanner)

