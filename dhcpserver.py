#!/usr/bin/python3.4
# -*- coding=utf-8 -*-
#鏈剼鐢变簛棰愬爞鐜颁换鏄庢暀鏁欎富缂栧啓锛岀敤浜庝咕棰愮浘Python璇剧▼锛
#鏁欎富QQ:605658506
#浜侀鍫傚畼缃憌ww.qytang.com
#涔鹃鐩炬槸鐢变簛棰愬爞鐜颁换鏄庢暀鏁欎富寮€鍙戠殑缁煎悎鎬у畨鍏ㄨ绋
#鍖呮嫭浼犵粺缃戠粶瀹夊叏锛堥槻鐏锛孖PS...锛変笌Python璇█鍜岄粦瀹㈡笚閫忚绋嬶紒
import sys

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)#娓呴櫎鎶ラ敊
from scapy.all import *
#from PyQYT.Network.Tools.GET_MAC import GET_MAC
#from PyQYT.Network.Tools.GET_IP import get_ip_address

from random import randint
import optparse
from time import sleep

class DHCPServer:
        def __init__(self, pool):
                self.server_mac = "c4:41:1e:74:e3:a4 "
                self.server_ip = "52.1.1.66"
                print("AAA", self.server_ip)
                self.subnet_mask = '255.255.255.0'
                self.pool = pool


        def generateClientIP(self, pool):
                parts = self.pool.split('.')
                clientip = parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + str(randint(1,255))
                self.client_ip = clientip
                return clientip


        #DHCP leases
        def detect_dhcp(self, pkt):
                """
                #鎵撳嵃鍑簊erver鍙戦€佺殑BOOTP涓殑option
                if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 2:
                        print("\n鏀跺埌Offer銆)
                        print(pkt.getlayer(DHCP).fields)
                        print(pkt.getlayer(BOOTP).fields)
                if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 5:
                        print("\n鏀跺埌Ack銆)
                        print(pkt.getlayer(DHCP).fields)
                        print(pkt.getlayer(BOOTP).fields)
                """
                #Send DHCP Offer if DHCP Discovered Detected.
                print(pkt.getlayer(DHCP))
                if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1] == 1:
                        print("\n鏀跺埌Discover銆")

                        for option in pkt.getlayer(DHCP).options:
                                print('option ---> ', option)
                        #print(pkt.getlayer(DHCP).fields)
                        sendp(
                                Ether(src=self.server_mac,dst="ff:ff:ff:ff:ff:ff")/
                                IP(src=self.server_ip,dst="255.255.255.255")/
                                UDP(sport=67,dport=68)/
                                BOOTP(
                                        op=2,
                                        xid=pkt.getlayer(BOOTP).fields['xid'],
                                        yiaddr=self.generateClientIP(self.pool),
                                        chaddr=pkt.getlayer(BOOTP).fields['chaddr']+b'\x00'*10,
                                        options=b'c\x82Sc')/
                                DHCP(options=[('message-type', 2), ('subnet_mask', '255.255.255.0'), ('server_id', self.server_ip), 'end']),iface="en8")
                        print("鍙戦€丱ffer.\n")
                sleep(0.5)

                #Send DHCP Ack if DHCP Request Detected.
                if pkt.getlayer(DHCP) and pkt.getlayer(DHCP).fields['options'][0][1]== 3:
                        print("\n鏀跺埌Request銆")
                        sendp(
                                Ether(src=self.server_mac,dst="ff:ff:ff:ff:ff:ff")/
                                IP(src=self.server_ip,dst="255.255.255.255")/
                                UDP(sport=67,dport=68)/
                                BOOTP(
                                        op=2,
                                        xid=pkt.getlayer(BOOTP).fields['xid'],
                                        yiaddr=pkt.getlayer(DHCP).fields['options'][4][1],
                                        chaddr=pkt.getlayer(BOOTP).fields['chaddr']+b'\x00'*10,
                                        options=b'c\x82Sc')/
                                DHCP(options=[('message-type', 5), ('renewal_time', 345600), ('rebinding_time', 604800), ('lease_time', 691200), ('server_id', self.server_ip), ('subnet_mask', '255.255.255.0'), (81, b'\x00\xff\xff'), ('domain', b'cjd.com\x00'), ('router', '52.1.1.122'), 'end', 'pad', 'pad', 'pad', 'pad', 'pad'])
                               ,iface="en8")
                        print("Sending Ack.\n\nCtrl+C閫€鍑恒€俓n")
                sleep(0.5)

        def start(self):
                sniff(prn=self.detect_dhcp, store=0,  iface="en8")

def main():
        parser = optparse.OptionParser('python3 dhcpServerScapy.py -i 宸ヤ綔鎺ュ彛 -p 鍦板潃姹閮芥槸24浣 -g 缃戝叧 -d DNS鏈嶅姟鍣')
        parser.add_option('-p', dest = 'IPPool', type = 'string', help = '鎸囧畾IP鍦板潃姹狅紙鎺╃爜闀垮害缁熶竴涓4浣嶏級')
        (options, args) = parser.parse_args()

        # if intf == None or ippool == None or gateway == None or dnsserver == None:
        #         print(parser.usage)
        #         exit(0)
        ippool = "52.1.1.0"
        server = DHCPServer(ippool)
        server.start()


def client_ip(pool="52.1.1.0"):
        parts = pool.split('.')
        clientip = parts[0] + '.' + parts[1] + '.' + parts[2] + '.' + str(randint(1, 255))
        return clientip

if __name__ == '__main__':
        main()