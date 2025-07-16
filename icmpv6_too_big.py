#########################################################################################
# ICMPv6 Packet Too Big Error message
#
# The script is used to generate fragments in which a destination option header is
# added after the IPv6 Fragment Header
#
# The following lines need to be executed only once in the scapy console.
#########################################################################################
from scapy.all import *
sip = "2001::1"
dip = '2001::c194:16c9:c14c:21e3'
import time
#########################################################################################
# The code below generates the ICMPv6 Packet Too Big message
#########################################################################################
def main():
# Create the outer IP Payload & ICMP Header
    outerIPPayload = IPv6(src=sip, dst=dip) / ICMPv6PacketTooBig(mtu=1480)

    # Create the inner IP header which caused the error
    innerIPPayload  = IPv6(src=dip, dst=sip) / ICMPv6EchoRequest(data='A'*1000)

    # Generate the ICMP Packet
    packet = outerIPPayload/innerIPPayload

    # Send out the packet
    send(packet)

if __name__ == "__main__":
    while True:
        main()
        time.sleep(1)