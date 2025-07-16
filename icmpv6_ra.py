

from scapy.all import *

a=IPv6(src='2001:2::1851:2945:18ed:25a7', dst='ff02::1:ff00:1')
b=ICMPv6ND_NS(tgt='2001:2::1')
c=ICMPv6NDOptSrcLLAddr(lladdr='a4:83:e7:3e:36:2f')
d=ICMPv6NDOptMTU()
e=ICMPv6NDOptPrefixInfo(prefix='2001:2::', prefixlen=64)

send(a/b/c/d/e)