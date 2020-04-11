#!/usr/bin/python3.7m
import python_arptable

class _ArpTable():
    def __init__(self):
        self._arp_table = {x['IP address']: x['HW address'] for x in python_arptable.get_arp_table()}
    def findMac(self, ip):
        return self._arp_table.get(ip)
    def addMac(self, ip, mac):
        self._arp_table[ip] = mac

ArpTable = _ArpTable()

