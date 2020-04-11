#!/usr/bin/python3.7m
from scapy.all import srp, Ether, ARP, conf
import socket
import fcntl
import struct
import pyroute2
import requests
from time import sleep
import argparse
from csvmac import search_mac

def parse():
    parser = argparse.ArgumentParser(prog="ArpScan", description="Local network scan")
    parser.add_argument("-o", "--offline", action="store_true", dest="OfflineMode", help="Offline mode (Mac vendors won't be searched)")
    parser.add_argument("-t", "--timeout", type=float, default=1,  help="Time waiting for ARP response in seconds (Default=1)") 
    parser.add_argument("-i", "--interface", dest="iface", help="Network interface used (The default one is the one used by scapy)")
    parser.add_argument("-r", "--retries", type=int, default=2, help="Number of retries before give up with a host that is not responding (Default=2)")
    
    return parser.parse_args()
    

def get_netmask(iface):
    ip = pyroute2.IPDB()
    IpInfo = ip.interfaces[iface].ipaddr[0]
    netmask = "{}/{}".format (IpInfo['local'], IpInfo['prefixlen'])
    ip.release()
    return netmask

def get_mac_vendor(mac):
    APIURL = "https://api.macvendors.com/"
    """APIURL = "https://macvendors.com/query"
    mac=mac[0:8].replace(":", "")"""
    r = requests.get("{}/{}".format(APIURL, mac))
    if r.status_code == requests.codes.ok:
        return r.text
    elif r.status_code == requests.codes.too_many:
        time.sleep(1.3)
        r = requests.get("{}/{}".format(APIURL, mac))
        r.raise_for_status()
        return r.text
    else:
        r.raise_for_status()

def print_row(A, B, C):
    print ("{: <15} {: <17}  {: <20}".format(A, B, C))

def print_format (packet):
    ip = packet["ARP"].psrc
    mac = packet["ARP"].hwsrc
    vendor = search_mac(mac)
    
    print_row(ip, mac, vendor)

print_row("IP", "MAC", "Vendor")

args = parse()
if args.iface is None:
    iface = conf.iface
else:
    iface = args.iface
ans, unans = srp (Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(psrc="0.0.0.0", pdst=get_netmask(iface), hwdst="ff:ff:ff:ff:ff:ff"), timeout=args.timeout, retry=args.retries, verbose=0, store_unanswered = 0)
ipSet = set()
for i in ans:
	ip = i[1][ARP].psrc
	if not i[1][ARP].psrc in ipSet:
		ipSet.add(i[1][ARP].psrc)
		print_format (i[1])

