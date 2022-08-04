import scapy.all as scapy
from tqdm import tqdm
import ipaddress as ipaddr
import os
import sys


def in_sudo_mode():
    """If the user doesn't run the program with super user privileges, don't allow them to continue."""
    if not 'SUDO_UID' in os.environ.keys():
        print("You are not root!\nTry running this program with sudo privileges.")
        exit()



def get_cmd_arguments():
    """ This function validates the command line arguments supplied when running the program"""
    Args = None
    # Ensure that the user has specified 5 arguments
    if len(sys.argv) != 5:
        print("Error!!!!! You specified less or more than 5 arguments")
        return Args
    elif sys.argv[1]=='-n' and sys.argv[3]=='-p':
        try:
            L = []
            L.append(sys.argv[2])
            L.append(sys.argv[4])
            Args = L
        except:
            print("Invalid command-line arguments check the documentation")
            
    return Args


def get_host_list(IP,PREFIX_LENGTH):
    network = ipaddr.IPv4Network(IP +'/'+ PREFIX_LENGTH)
    Hosts_list = [str(ip) for ip in network]
    return Hosts_list   


#Logo and signature                               
print(r""" ||    _                                      _
           ||   //                                     ||
           || //    _____       _____            ___   ||
           ||\\    /  _  \  __ /  _  \ -     -  / _  \ ||
           ||  \\ /  (_|  ||/    (_)$  |     | | (_|  ||||____  
           ||   \\\_______||   \_____/ ||___|| \_____/||  _   \   __
                                                      || |_).  |//__)
                                                  _____|_\_____/||___ .01lig""")
print("\n****************************************************\n")
print("********Copyright of gilles karougbe, jully 2022********")
print("*********http://www.github.com/gilleskarougbe***********")
print("***********https://twiter.com/01karougbe****************")
print("***linkedin.com/in/essognim-gilles-karougbe-015979223***")
print("\n****************************************************\n")


#Sending ICMP echo-request to broadcast to get live hosts
def scanner(Hosts_list):
    clients = list()
    a = scapy.Ether()
    c = scapy.ICMP()
    ip = scapy.get_if_addr(scapy.conf.iface)

    for target in tqdm(Hosts_list):
        b = scapy.IP(src=ip,dst= target,proto='icmp')
        pkt = a/b/c
        result = scapy.srp(pkt,verbose = 0)

        try:
            Qanswer = result[0][0]
            #Qanswer[0] -----> request
            #Qanswer[1] -----> reply
            MAC = Qanswer[1].src
            Host = dict()
            Host['ip'] = target
            Host['mac'] = MAC
            clients.append(Host)
        except:
            pass
        
    return clients


#check sudo privleges
in_sudo_mode()

#get command line arguments
Args = get_cmd_arguments()

#hosts list
Hosts_list = get_host_list(Args[0],Args[1])

#scanning
live_hosts = scanner(Hosts_list)
print(live_hosts)