#!/usr/bin/python3.7m
import csv

def search_mac (mac):
    mac=mac[0:8].replace(":", "").upper()
    with open ("oui.csv") as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if mac == row[1]:
                return row[2]
    return "Unknown"
                
