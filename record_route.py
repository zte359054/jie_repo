import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # 清除报错
from scapy.all import *
import time
import struct
import random
import sys
import re
import optparse


def ping_rr(dst, src):  # 需要填写目的IP地址，出口源IP地址
    # 出口源IP地址需要二进制写入IP选项
    ip_sec = src.split('.')  # 首先把IP地址通过'.'分为四段
    sec_1 = struct.pack('>B', int(ip_sec[0]))  # 每一段写成一个字节的二进制数
    sec_2 = struct.pack('>B', int(ip_sec[1]))
    sec_3 = struct.pack('>B', int(ip_sec[2]))
    sec_4 = struct.pack('>B', int(ip_sec[3]))

    ip_options = b'\x07\x27\x08' + sec_1 + sec_2 + sec_3 + sec_4 + b'\x00' * 33
    # '\x07'表示源站路由选项，\x27为长度（10进制的39），\x08表示指针，紧接着是4个字节IP地址，然后补齐IP选项的40个字节
    pkt = IP(dst=dst, options=IPOption(ip_options)) / ICMP(type=8, code=0)

    result = sr1(pkt, timeout=1, verbose=False)
    for router in result.getlayer(IP).options[0].fields['routers']:
        print(router)
    # 打印路径记录的IP地址


if __name__ == '__main__':
    parser = optparse.OptionParser('用法：\n python3 route_record.py --destIP 目标IP --sourIP 源IP')
    parser.add_option('--dst', dest='destIP', type='string', help='目标IP')
    parser.add_option('--src', dest='sourIP', type='string', help='源IP')
    (options, args) = parser.parse_args()
    destIP = options.destIP
    sourIP = options.sourIP

    if sourIP == None or destIP == None:
        print(parser.usage)
    else:
        ping_rr(destIP, sourIP)
