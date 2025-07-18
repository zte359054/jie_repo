import sys

import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # 清除报错
from scapy.all import *
import time
import struct
import random
import sys
import re


def ping_df(dst, mtu):
    pyload = b'v' * (int(mtu) - 28)  # 28为20字节IP头部和8字节ICMP头部的长度
    ping_one_reply = sr1(IP(dst=dst, flags='DF') / ICMP() / pyload, timeout=1, verbose=False)
    # 发送DF位的数据包
    try:
        if ping_one_reply.getlayer(ICMP).type == 3 and ping_one_reply.getlayer(ICMP).code == 4:
            # 如果返回ICMP不可达信息，就返回1和当前的mtu
            mtu = ping_one_reply.getlayer(ICMP).nexthopmtu
            return 1, mtu
        elif ping_one_reply.getlayer(ICMP).type == 0 and ping_one_reply.getlayer(ICMP).code == 0:
            # 如果返回ICMP echo reply，就返回2和当前的mtu
            return 2, mtu
    except Exception as e:
        if re.match('.*NoneType.*', str(e)):
            return None  # 如果测试失败，就返回None


def discover_path_mtu(dst):
    mtu = 1500  # mtu从1500开始向下减
    while True:
        Result = ping_df(dst, mtu)
        if Result == None:  # 如果测试失败就打印信息，并且跳出循环
            print('目标: ' + dst + '不可达！')
            break
        elif Result[0] == 2:  # 如果PING测试成功，就打印信息，并且跳出循环
            print('目标: ' + dst + '的Path MTU为: ' + str(Result[1]))
            break
        elif Result[0] == 1:  # 如果得到不可达信息，就较少MTU，打印消息，并且继续循环
            print('MTU: ' + str(mtu) + '测试不通过')
            mtu = mtu - 1
        time.sleep(1)


if __name__ == '__main__':
    destination = sys.argv[1]
    discover_path_mtu(destination)
