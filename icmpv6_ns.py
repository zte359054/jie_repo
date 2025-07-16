from scapy.all import *
from mactoipv6linklocal import *
from Get_MAC import *

def icmpv6_ns(host, ifname):
    ll_mac = GET_MAC(ifname)
    eth = Ether(src=ll_mac, dst=ipv6tomac(host))
    packet = eth/IPv6(src=mac_to_ipv6_linklocal(ll_mac), dst = Solicited_node_multicast_address(host)) / ICMPv6ND_NS(tgt=host) / ICMPv6NDOptSrcLLAddr(lladdr=ll_mac)
    result = srp1(packet, timeout=2, verbose=False ,iface=ifname)
    # print(result.show())
    return result.getlayer("ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address").fields['lladdr']


