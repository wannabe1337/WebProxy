# place block site in a file "blockedSites.txt"
import socket

def isBlock(host):
    try:
        ip_addr=socket.gethostbyname(host)
    except:
        return -1
    # print(ip_addr)
    blockedSites=open('blockedSites.txt','r')
    lists=blockedSites.read().splitlines()
    # print(lists)
    if(host in lists or ip_addr in lists):
        return True
    else:
        return False