from scapy.all import *

interface = "en0"
clientMAC = {}

def sniffProbe(p):
    if p.haslayer(Dot11ProbeReq):
        netName = p.getlayer(Dot11ProbeReq).info.decode()
        clientmac = p.getlayer(Dot11).addr2
        if netName == "": return
        if clientMAC.get(clientmac) == None:
            clientMAC[clientmac] = []
            clientMAC[clientmac].append(netName)
            print('[+] 客户端MAC地址为: '+ clientmac + ", 该机器连过这些无线网络")
            print('------------------', clientMAC[clientmac], "\n")
        else:
            if netName not in clientMAC[clientmac]:
                clientMAC[clientmac].append(netName)
                print('[+] 客户端MAC地址为: ' + clientmac + ", 该机器连过这些无线网络")
                print('------------------', clientMAC[clientmac], "\n")


sniff(iface=interface, prn=sniffProbe)
