# -*- coding=utf-8 -*-
from scapy.all import *
import hexdump
import re

my_str = b""

def reset_tcp(pkt):
    try:
        source_mac = pkt[Ether].fields["src"]
        destination_mac = pkt[Ether].fields["dst"]
        source_ip = pkt[IP].fields['src']
        destination_ip = pkt[IP].fields['dst']
        source_port = pkt[TCP].fields['sport']
        destination_port = pkt[TCP].fields['dport']
        seq_sn = pkt[TCP].fields["seq"]
        ack_sn = pkt[TCP].fields["ack"]
        print(pkt.summary())
        a = Ether(src=source_mac, dst=destination_mac) \
            / IP(src=source_ip, dst=destination_ip) \
            / TCP(dport=destination_port, sport=source_port, flags=4, seq=seq_sn)

        b = Ether(src=destination_mac, dst=source_mac) \
            / IP(src=destination_ip, dst=source_ip) \
            / TCP(dport=source_port, sport=destination_port, flags=4, seq=seq_sn)

        sendp(a, iface=ifname, verbose=False)
        sendp(b, iface=ifname, verbose=False)
        # print(a.summary())
        # print(b.summary(), "\n")
    except Exception as e:
        pass


def myhexdump(src, length=16):  # 每16字节提取一次，进行16进制decode
    for i in range(0, len(src), length):
        s = src[i: i + length]
        hexdump.hexdump(s)


def telnet_monitor_back(pkt):
    global my_str
    try:
        if pkt.getlayer(TCP).fields['dport'] == 23 and pkt.getlayer(Raw).fields["load"].decode():
            my_str = my_str + pkt.getlayer(Raw).fields["load"]  # 提取telnet中的数据，比进行拼?
    except Exception:
        pass
    print(my_str)
    if re.match(b'.*\r\x00.*sh.*\s+ver.*', my_str):
        reset_tcp(pkt)


def telnet_monitor(src_ip, dst_ip, dst_port, ifname):
    match = " net " + src_ip + " or ip dst " + dst_ip + " and tcp port " + dst_port
    ptks = sniff(prn=telnet_monitor_back, filter=match, store=0, iface=ifname)
    # wrpcap("telnet.pcap", ptks)  # 将捕获的数据包到文件
#    myhexdump(my_str)  # 解码展示


if __name__ == "__main__":
    src_ip = "52.1.1.129"
    dst_ip = "52.1.1.67"
    dst_port = "23"
    ifname = "en0"
    telnet_monitor(src_ip, dst_ip, dst_port, ifname)