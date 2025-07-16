from scapy.all import DHCP_am
from scapy.base_classes import Net

dhcp_server = DHCP_am(iface='en8', domain='example.com',
                      pool=Net('52.1.1.0/24'),
                      network='52.1.1.0/24',
                      gw='52.1.1.1',
                      renewal_time=600, lease_time=3600)
dhcp_server()