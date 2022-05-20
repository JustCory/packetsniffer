import socket
import os
import sys
import binascii

output_file = open("./output.txt", "w")

class header_results:
    def __init__(self, version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, time_to_live, protocol, header_checksum, source_ip, destination_ip, options):
        self.version = version
        self.ihl = ihl
        self.dscp = dscp
        self.ecn  = ecn
        self.total_length = total_length 
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset 
        self.time_to_live = time_to_live
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.options = options

def hex_to_mac(dest_hex_value, src_hex_value):
    dest_mac_pieces = map('{:02x}'.format, dest_hex_value)
    src_mac_pieces = map('{:02x}'.format, src_hex_value)
    return ':'.join(dest_mac_pieces).upper(), ':'.join(src_mac_pieces).upper()

def ipv4(raw_data, raw_binary_data):
    version = int(raw_binary_data[0] + raw_binary_data[2:5], 2) # 'b', i assume from the bytes type, is left in the binary, i wonkly skip over it with this, this should always be 4 for ipv4
    ihl = int(raw_binary_data[5:9], 2) * 4 # internet header length: minimum valuoe of 20 bytes, max value of 60 bytes
    dscp = int(raw_binary_data[9:15], 2) # differentiated services code point
    ecn = int(raw_binary_data[15:17], 2) # explicit congestion notification
    total_length = int(raw_binary_data[17:33], 2) * 4 # minimum size is 20 bytes (just a header), maximum size is 65535 bytes
    identification = int(raw_binary_data[33:49], 2) 
    flags = raw_binary_data[49:52] # a set of 3 values, a reserved bit, a don't fragment bit and more fragments bit, usually outputs 000
    fragment_offset = int(raw_binary_data[52:65], 2) 
    time_to_live = int(raw_binary_data[65:73], 2) # a hop count, each router that the packet goes through decrments this value, when it gets to 0 a time out signal is sent
    protocol = int(raw_binary_data[73:81], 2) # 1 = icmp, 2 = igmp, 6 = tcp, 17 = udp, 41 = encap, 89 = ospf, 132 = sctp, other = broken for ipv4
    header_checksum = raw_binary_data[81:97] # error checking
    source_ip = '.'.join(map(str, raw_data[12:16])) # formated ipv4 source ip address
    destination_ip = '.'.join(map(str, raw_data[16:20]))# formated ipv4 destination ip address
    options = raw_data[20:]
    
    return header_results(version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, time_to_live, protocol, header_checksum, source_ip, destination_ip, options)

# the data for each of these is after the header length, header.ihl
def icmp(raw_data, raw_binary_data, header):
    icmp_type = int(raw_binary_data[header.ihl:header.ihl+8], 2)
    icmp_code = int(raw_binary_data[header.ihl+8:header.ihl+16], 2)
    icmp_checksum = raw_binary_data[header.ihl+16:header.ihl+32]
    icmp_header = raw_data[(header.ihl+32)//8:(header.ihl+64)//8]
    icmp_data = raw_data[(header.ihl+64)//8:]

    print("ICMP Packet")
    print("Type:", icmp_type, "   Code:", icmp_code, "   Checksum:", icmp_checksum)
    print("Other ICMP Header Info:", icmp_header)
    print("ICMP Data:", icmp_data)

    next_to_write_icmp = "\n\nICMP Packet" + "\nType:" + str(icmp_type) + "   Code:" + str(icmp_code) + "   Checksum:" + str(icmp_checksum) + "\nOther ICMP Header Info:" + str(icmp_header) + "\nICMP Data:" + str(icmp_data)
    output_file.write(next_to_write_icmp)

def igmp(raw_data, raw_binary_data, header):
    igmp_type = int(raw_binary_data[header.ihl:header.ihl+8], 2)
    igmp_max_resp_code = int(raw_binary_data[header.ihl+8:header.ihl+16], 2)
    igmp_checksum = raw_binary_data[header.ihl+16:header.ihl+32]
    igmp_group_address = '.'.join(map(str, raw_data[32//8:64//8]))
    igmp_resv = int(raw_binary_data[header.ihl+64:header.ihl+68], 2)
    igmp_s = raw_binary_data[header.ihl+68:header.ihl+69], 2
    igmp_qrv = int(raw_binary_data[header.ihl+69:header.ihl+72], 2)
    igmp_qqic = int(raw_binary_data[header.ihl+72:header.ihl+80], 2)
    igmp_number_of_sources = int(raw_binary_data[header.ihl+80:header.ihl+96], 2)

    # raw_data[(header.ihl+112)//8:]
    igmp_source_address = []

    start_pos = 96//8
    for i in range(igmp_number_of_sources):
        igmp_source_address.append('.'.join(map(str, raw_data[start_pos:start_pos+4])))
        start_pos += 4

    print("IGMP Packet")
    print("Type:", igmp_type, "   Max Response Code:", igmp_max_resp_code, "   Checksum:", igmp_checksum)
    print("Group Address:", igmp_group_address)
    print("Reserved:", igmp_resv, "   Suppress Flag:", igmp_s, "   QRV Flag:", igmp_qrv, "Queriers Query Interval Code:", igmp_qqic)
    print("Number of Sources:", igmp_number_of_sources)

    next_to_write_igmp = "\n\nIGMP Packet" + "\nType:" + str(igmp_type) + "   Max Response Code:" + str(igmp_max_resp_code) + "   Checksum:" + str(igmp_checksum) + "\nGroup Address:" + str(igmp_group_address) + "\nReserved:" + str(igmp_resv) + "   Suppress Flag:" + str(igmp_s) + "   QRV Flag:" + str(igmp_qrv) + "Queriers Query Interval Code:" + str(igmp_qqic) + "\nNumber of Sources:" + str(igmp_number_of_sources)
    output_file.write(next_to_write_igmp)

    for address in igmp_source_address:
        i = 1
        next_to_write_igmp_addr = "Source Address", str(i) + ":" + str(address)
        output_file.write(next_to_write_igmp_addr)
        output_file.write("\nSource Address", i + ":", address)
        i += 1

def tcp(raw_data, raw_binary_data, header):
    tcp_source = int(raw_binary_data[header.ihl:header.ihl+16], 2)
    tcp_destination = int(raw_binary_data[header.ihl+16:header.ihl+32], 2)
    tcp_sequence_number = int(raw_binary_data[header.ihl+32:header.ihl+64], 2)
    tcp_acknowledgement_number = int(raw_binary_data[header.ihl+64:header.ihl+96], 2)
    tcp_data_offset = int(raw_binary_data[header.ihl+96:header.ihl+100], 2)
    tcp_reserved = int(raw_binary_data[header.ihl+100:header.ihl+103], 2)

    # flags:
    tcp_ns = raw_binary_data[header.ihl+103:header.ihl+104]
    tcp_cwr = raw_binary_data[header.ihl+104:header.ihl+105]
    tcp_ece = raw_binary_data[header.ihl+105:header.ihl+106]
    tcp_urg = raw_binary_data[header.ihl+106:header.ihl+107]
    tcp_ack = raw_binary_data[header.ihl+107:header.ihl+108]
    tcp_psh = raw_binary_data[header.ihl+108:header.ihl+109]
    tcp_rst = raw_binary_data[header.ihl+109:header.ihl+110]
    tcp_syn = raw_binary_data[header.ihl+110:header.ihl+111]
    tcp_fin = raw_binary_data[header.ihl+111:header.ihl+112]

    tcp_window_size = int(raw_binary_data[header.ihl+112:header.ihl+128], 2)
    tcp_checksum = raw_binary_data[header.ihl+128:header.ihl+144]
    tcp_urgent_pointer = raw_binary_data[header.ihl+111:header.ihl+112]
    tcp_options = raw_data[(header.ihl+112)//8:]

    print("TCP Packet")
    print("Source:", tcp_source, "   Destination:", tcp_destination)
    print("SYN Flag:", tcp_syn, "   Sequence Number:", tcp_sequence_number) # sequence number use depends on SYN flag
    print("Acknowledgement Flag:", tcp_ack, "   Acknowledgement Number:", tcp_acknowledgement_number)
    print("URG Flag:", tcp_urg, "   Urgent Pointer:", tcp_urgent_pointer)
    print("Data Offset:", tcp_data_offset, "   Reserved:", tcp_reserved)
    print("Windows Size:", tcp_window_size, "   Checksum:", tcp_checksum)
    print("Other Flags: NS:", tcp_ns, "   CWR:", tcp_cwr, "   ECE:", tcp_ece, "   PSH:", tcp_psh, "   RST:", tcp_rst, "   FIN:", tcp_fin)
    print("TCP Options:", tcp_options)

    next_to_write_tcp = "\n\nTCP Packet" + "\nSource:" + str(tcp_source) + "   Destination:" + str(tcp_destination) + "\nSYN Flag:" + str(tcp_syn) + "   Sequence Number:" + str(tcp_sequence_number) + "\nAcknowledgement Flag:" + str(tcp_ack) + "   Acknowledgement Number:" + str(tcp_acknowledgement_number) + "\nURG Flag:" + str(tcp_urg) + "   Urgent Pointer:" + str(tcp_urgent_pointer) + "\nData Offset:" + str(tcp_data_offset) + "   Reserved:" + str(tcp_reserved) + "\nWindows Size:" + str(tcp_window_size) + "   Checksum:" + str(tcp_checksum) + "\nOther Flags: NS:" + str(tcp_ns) + "   CWR:" + str(tcp_cwr) + "   ECE:" + str(tcp_ece) + "   PSH:" + str(tcp_psh) + "   RST:" + str(tcp_rst) + "   FIN:" + str(tcp_fin) + "\nTCP Options:" + str(tcp_options)
    output_file.write(next_to_write_tcp)

def udp(raw_data, raw_binary_data, header):
    udp_source = int(raw_binary_data[header.ihl:header.ihl+16], 2)
    udp_destination = int(raw_binary_data[header.ihl+16:header.ihl+32], 2)
    udp_length = int(raw_binary_data[header.ihl+32:header.ihl+48], 2) * 4
    udp_checksum = raw_binary_data[header.ihl+48:header.ihl+64]
    udp_data = raw_data[(header.ihl+64)//8:]
    
    print("UDP Packet")
    print("Source:", udp_source, "   Destination:", udp_destination, "   Length:", udp_length, "Checksum:", udp_checksum)
    print("Data:", udp_data)

    next_to_write_udp = "\n\nUDP Packet" + "\nSource:" + str(udp_source) + "   Destination:" + str(udp_destination) + "   Length:" + str(udp_length) + "Checksum:" + str(udp_checksum) + "\nData:" + str(udp_data)
    output_file.write(next_to_write_udp)

# encapsulated as ipv6 packet
def encap():
    print("ENCAP Packet")
    output_file.write("\n\nENCAP Packet\n\n")

# open shortest path first
def ospf():
    print("OSPF Packet")
    output_file.write("\n\nOSPF Packet\n\n")

# stream control transmission protocol
def sctp():
    print("SCTP Packet")
    output_file.write("\n\nSCTP Packet\n\n")

def main():
    # raw_packets = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    raw_packets = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # s = socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    # for windows
    raw_packets.bind((socket.gethostbyname(socket.gethostname()), 0))
    raw_packets.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw_packets.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    # recvfrom is from socket, the argument is the buffer size, 65565 is the max buffer size
    while True:
        raw_packet, ip_address = raw_packets.recvfrom(65535) # gather all of the packets, looking at each individual packet that's recieved. also gathers (ip addrress, 0)
        raw_binary_packet = bin(int(binascii.hexlify(raw_packet), 16))

        # printing the raw data as bytes (hex) and        
        # print(raw_packet)
        # print(raw_binary_packet)

        # s_packet = s.recvform(65535)

        # print('check if this is different from other mac:', hex_to_mac(s_packet[0:6], s_packet[6:12]))

        # raw ethernet frame info
        dest = raw_packet[0:6]
        src = raw_packet[6:12]
        ether_type_raw = raw_packet[12:14]

        # should use tcp for ether type
        # formated mac addresses
        # dest_mac, src_mac = hex_to_mac(dest, src)
        # ether type as an int, should be a short as ether type is 2 bytes long, not 4
        # ether_type = int(hex(ether_type_raw[0]) + hex(ether_type_raw[1])[2:], 16)
        # printing the ethernete frame content
        # print("\nDestination MAC: ", dest_mac, "   Source MAC: ", src_mac, "   Ether Type: ", ether_type)

        # next_to_write_ether_type = "\n\nDestination MAC: " + str(dest_mac) + "   Source MAC: " + str(src_mac) + "   Ether Type: " + str(ether_type);
        # output_file.write(next_to_write_ether_type)

        header = ipv4(raw_packet, raw_binary_packet)

        print("\nHeader Version:", header.version, "   Header Length:", header.ihl, "bytes", "   DSCP:", header.dscp, "   ECN:", header.ecn)
        print("Total Length of packet:", header.total_length, "bytes", "   Identification:", header.identification, "   Flags:", header.flags, "   Fragment Offset:", header.fragment_offset, "bytes")
        print("Time To Live:", header.time_to_live, "   Checksum:", header.header_checksum, "   Source IP:", header.source_ip, "   Destination IP:", header.destination_ip)
        print("Protocol:", header.protocol)

        next_to_write = "\n\n\nHeader Version:" + str(header.version) + "   Header Length:" + str(header.ihl) + "bytes" + "   DSCP:" + str(header.dscp) + "   ECN:" + str(header.ecn) + "\nTotal Length of packet:" + str(header.total_length) + "bytes" + "   Identification:" + str(header.identification) + "   Flags:" + str(header.flags) + "   Fragment Offset:" + str(header.fragment_offset) + "bytes" + "\nTime To Live:" + str(header.time_to_live) + "   Checksum:" + str(header.header_checksum) + "   Source IP:" + str(header.source_ip) + "   Destination IP:" + str(header.destination_ip) + "\nProtocol:" + str(header.protocol)
        output_file.write(next_to_write)

        # 1 = icmp, 2 = igmp, 6 = tcp, 17 = udp, 41 = encap, 89 = ospf, 132 = sctp, other = broken for ipv4
        if header.protocol == 1:
            icmp(raw_packet, raw_binary_packet, header)
        elif header.protocol == 2:
            igmp(raw_packet, raw_binary_packet, header)
        elif header.protocol == 6:
            tcp(raw_packet, raw_binary_packet, header)
        elif header.protocol == 17:
            udp(raw_packet, raw_binary_packet, header)
        elif header.protocol ==  41:
            encap(raw_packet, raw_binary_packet, header)
        elif header.protocol == 89:
            ospf(raw_packet, raw_binary_packet, header)
        elif header.protocol == 132:
            sctp(raw_packet, raw_binary_packet, header)
        else:
            print("Unrecognized ipv4 protocol")

        # print("\n\nheader stuff again:\n\n")
        # print(header.version, header.ihl, header.dscp, header.ecn, header.total_length, header.identification, header.flags, header.fragment_offset, header.time_to_live, header.protocol, header.header_checksum, header.source_ip, header.destination_ip, header.options)


main()