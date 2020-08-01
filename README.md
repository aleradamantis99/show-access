# show-access
This tool performs a MITM attack and tries to provide information about what websites or apps are being used in the target system.
Two methods can be used:
1. **DNS sniffing**: The easiest method. DNS queries are captured and the qd/qname field (where the domain name is sent) is printed. This method assumes DNS traffic is sent through the port 53, which is the usual case.
2. **Reverse-DNS**: This one is a bit trickier. It is usual to find the PTR register (used mainly for reverse DNS lookups) have weird names that do not give you any hint about the actual website (eg. google.com have at this moment the ip 172.217.164.142 associated, but when you performe de reverse DNS Lookup, it returns iad30s24-in-f14.1e100.net). I suspect this is mostly due to Load Balancing, but in this case it also increase the security. This method shoul only be used if you suspect DNS Lookups are being encrypted, in which case the first method won't work).

My own ArpScan is also included in case you want to discover the IP of the target device.
If you're facing a new device, you might want to update the *oui.csv* by downloading a new version from http://standards-oui.ieee.org/oui/oui.csv
