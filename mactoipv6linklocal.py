import re

def full_ipv6(ipv6):
    ipv6_section = ipv6.split(":")
    ipv6_section_len = len(ipv6.split(":"))
    if ipv6_section.index(''):
        null_location = ipv6_section.index('')
        ipv6_section.pop(null_location)
        add_section = 8 - ipv6_section_len + 1
        for x in range(add_section):
            ipv6_section.insert(null_location, "0000")
        new_ipv6 = []
        for s in ipv6_section:
            if len(s) < 4:
                new_ipv6.append((4 - len(s)) * "0" + s)
            else:
                new_ipv6.append(s)
        return ":".join(new_ipv6)
    else:
        return ipv6_section


def mac2ipv6(mac):
    # only accept MACs separated by a colon
    parts = mac.split(":")
    # modify parts to match IPv6 value
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    print(int(parts[0], 16) ^ 2)
    parts[0] = "%x" % (int(parts[0], 16) ^ 2)
    print(parts)
    # format output
    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
        print(ipv6Parts)
    ipv6 = "fe80::%s/64" % (":".join(ipv6Parts))
    return ipv6


def Solicited_node_multicast_address(ipv6):
    return "FF02::1:FF" + full_ipv6(ipv6)[-7:]


def ipv6tomac(ipv6):
    ipv6_address = full_ipv6(ipv6)
    last_4_sections = ipv6_address.split(":")[-4:]
    mac_1 = int(last_4_sections[0][:2], 16) ^ 0x02
    mac_2 = int(last_4_sections[0][2:], 16)
    mac_3 = int(last_4_sections[1][:2], 16)
    mac_4 = int(last_4_sections[2][2:], 16)
    mac_5 = int(last_4_sections[3][:2], 16)
    mac_6 = int(last_4_sections[3][2:], 16)
    return '33:33:ff:00:{:02x}:{:02x}'.format(mac_4,mac_5,mac_6)


def mac_to_ipv6_linklocal(mac):
    mac_value = int(re.sub('[ :.-]', '', mac), 16)
    high2 = mac_value >> 32 & 0xffff ^ 0x0200
    high1 = mac_value >> 24 & 0xff
    low1 = mac_value >> 16 & 0xff
    low2 = mac_value & 0xffff
    return 'fe80::{:04x}:{:02x}ff:fe{:02x}:{:04x}'.format(high2, high1, low1, low2)


if __name__ == "__main__":
    mac = "06:b2:4a:00:00:9f"
    ipv6 = mac_to_ipv6_linklocal(mac)
    print(ipv6)
    print(mac2ipv6(mac))
    print(Solicited_node_multicast_address("fe80::04b2:4aff:fe00:009f"))

