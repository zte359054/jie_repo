
import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#清除报错
from scapy.all import *
import time
import struct
import random
import sys
import re

##############################手动制造Fragment################################
#严重注意ICMP的校验和是整ICMP头部和数据部分一起计算的！！！
#frag的数量乘以8，才是真正的偏移量字节数！
send(IP(flags=1,frag=0,id=1,dst='4.2.2.2')/ICMP(chksum=0xab79)/b'welcome to qytang!!!!!!!')
send(IP(flags=1,frag=4,id=1,proto=1,dst='4.2.2.2')/(b'second welcome to qytang!!!!!!!!'))
send(IP(flags=0,frag=8,id=1,proto=1,dst='4.2.2.2')/(b'third welcome to qytang!!!!!!!!'))

##############################自动制造Fragment################################
#frags = fragment(IP(dst='202.100.1.3')/ICMP()/(b"qytang"*1000))
#产生每一个分片，可以对分片就行修改！！！！

#send(frags)

#正常发包，系统会自动进行分片处理！！！！
#send(IP(dst='202.100.1.3')/ICMP()/(b"qytang"*1000))