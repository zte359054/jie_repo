from scapy.all import *


def decapmdns(pkt):
    sntomac = {}
    snlist = []
    for i in pkt:
        if i[Ether].src.startswith("b4:40:a4") and i[DNS].haslayer("DNS SRV Resource Record") and i[DNS].qr == 1:
            if i[DNS].getlayer("DNS SRV Resource Record").type == 33:  # 解析设备回应mdns的srv记录
                sntomac[i[DNS].getlayer("DNS SRV Resource Record").rrname.decode()[:12]] = i[Ether].src
        elif i[Ether].src.startswith("b4:40:a4") and i[DNS].haslayer("DNS Resource Record") and i[DNS].qr == 1:
            if i[DNS].getlayer("DNS Resource Record").type == 16:  # 解析设备回应mdns的txt记录
                sntomac[i[DNS].getlayer("DNS Resource Record").rrname.decode()[:12]] = i[Ether].src
        elif i[Ether].src.startswith("b4:40:a4") and i[DNS].haslayer("DNS Resource Record") and i[DNS].qr == 1:
            if i[DNS].getlayer("DNS Resource Record").type == 12:  # 解析设备回应mdns的PTR记录
                sntomac[i[DNS].getlayer("DNS Resource Record").rdata.decode()[:12]] = i[Ether].src
    for sn, macaddr in sntomac.items():
        snlist.append(sn)
    return snlist


if __name__ == "__main__":
    filename = r"/Users/zhuqian/PycharmProjects/Python3_Jie/mdns1.pcap"
    mdns_packets = rdpcap(filename)
    print(decapmdns(mdns_packets))
