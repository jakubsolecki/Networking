import sys
from numpy import uint8
from tabulate import tabulate


def analyze_ip(ip_addr):
    ip_addr, mask_prefix = ip_addr.split("/")
    ip_addr = ip_addr.split(".")
    ip_addr = [uint8(elem) for elem in ip_addr]
    mask_prefix = int(mask_prefix)
    mask_bin = "1"*mask_prefix + "0"*(32 - mask_prefix)
    host_count = 2**(32 - mask_prefix) - 2
    table = []

    if 1 <= ip_addr[0] <= 127:
        table.append(["Class", "A"])
        ip_addr_str = str(ip_addr[0])
        table.append(["Network address", ip_addr_str + ".0"*3])
        table.append(["Directed broadcast", ip_addr_str + ".255"*3])
    elif 128 <= ip_addr[0] <= 191:
        table.append(["Class", "B"])
        ip_addr_str = ".".join(str(ip_addr[i]) for i in range(2))
        table.append(["Network address", ip_addr_str + ".0"*2])
        table.append(["Directed broadcast", ip_addr_str + ".255"*2])
    elif 192 <= ip_addr[0] <= 223:
        table.append(["Class", "C"])
        ip_addr_str = ".".join(str(ip_addr[i]) for i in range(3))
        table.append(["Network address", ip_addr_str + ".0"])
        table.append(["Directed broadcast", ip_addr_str + ".255"])
    elif 224 <= ip_addr[0] <= 239:
        print("Class: D - Multicast")
        sys.exit(0)
    elif 240 <= ip_addr[0] <= 255:
        print("Class: E - Reserved")
        sys.exit(0)

    chunks, chunk_size = len(mask_bin), len(mask_bin)//4
    mask = [uint8(int(mask_bin[i:i + chunk_size], base=2)) for i in range(0, chunks, chunk_size)]
    mask_str = ".".join(str(elem) for elem in mask)
    table.append(["Subnet mask", mask_str])

    subnet_address = [uint8(mask[i] & ip_addr[i]) for i in range(4)]
    subnet_address_str = ".".join([str(elem) for elem in subnet_address])
    table.append(["Subnet address", subnet_address_str])

    # host_address = [(~ mask[i]) & ip_addr[i] for i in range(4)]
    # host_address_str = ".".join([str(elem) for elem in host_address])
    # table.append(["Host ???", host_address_str])

    subnet_broadcast_address = [subnet_address[i] ^ (~ mask[i]) for i in range(4)]
    subnet_broadcast_address_str = ".".join([str(elem) for elem in subnet_broadcast_address])
    table.append(["Subnet broadcast", subnet_broadcast_address_str])

    host_range_str = ".".join(str(elem) for elem in subnet_address) + " - " + \
                     ".".join(str(elem) for elem in subnet_broadcast_address[:3]) + "." + \
                     (str(subnet_broadcast_address[3] - 1))

    table.append(["Host address range", host_range_str])

    table.append(["Possible hosts", host_count])

    print(tabulate(table))


if __name__ == "__main__":
    ip_addr = ""

    while True:
        ip_addr = input("\nProvide an IPv4 address with mask <a.b.c.d/m> or 'quit' to exit:\n")
        if ip_addr == "quit":
            sys.exit(0)
        analyze_ip(ip_addr)
