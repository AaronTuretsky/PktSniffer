"""
Parses a .pcap file for IPv4 packets and sends data to terminal.
Author: Aaron Turetsky
Date: 09/01/2020
"""
# ============================================================== #
#  SECTION: Imports                                              #
# ============================================================== #

# standard library
import sys

# third party library
# local
from util import *
from packet import PacketHeader, GlobalHeader, Packet, UDPHeader, TCPHeader, ICMPHeader


# ============================================================== #
#  SECTION: Global Functions                                     #
# ============================================================== #

def is_host(packet, ip):
    """Returns True if packet's source or destination ip matches ip.

       Packet: Object representing a network packet.
       ip: List of bytes representing an ip address
    """
    source_address = '{}.{}.{}.{}'.format(*[int(byte, 16) for byte in packet.ip_source])
    destination_address = '{}.{}.{}.{}'.format(*[int(byte, 16) for byte in packet.ip_dest])
    if ip == source_address or ip == destination_address:
        return True
    return False


def is_port(packet, port):
    """Returns True if packet's source or destination port matches port.

       Packet: Object representing a network packet.
       port: String representing a port value
    """
    # ICMP has no src or dst port
    if hasattr(packet.protocol_header, 'source_port'):
        source_port = str(packet.protocol_header.source_port)
        dest_port = str(packet.protocol_header.destination_port)
        if port == source_port or port == dest_port:
            return True
    return False


def is_ip(packet):
    """Returns True if packet is an IP packet.
       NOTE: Currently only handles IPv4

       Packet: Object representing a network packet.
    """
    if bytes_to_int(packet.e_type) in [8]:
        return True
    return False


def is_tcp(packet):
    """Returns True if packet is using TCP protocol.

       Packet: Object representing a network packet.
    """
    if packet.protocol_header.name == TCPHeader.name:
        return True
    return False


def is_udp(packet):
    """Returns True if packet is using UDP protocol.

       Packet: Object representing a network packet.
    """
    if packet.protocol_header.name == UDPHeader.name:
        return True
    return False


def is_icmp(packet):
    """Returns True if packet is using ICMP protocol.

       Packet: Object representing a network packet.
    """
    if packet.protocol_header.name == ICMPHeader.name:
        return True
    return False


def is_net(packet, net):
    """Returns True if source or destination address of packet has net as a network number.

       Packet: Object representing a network packet.
       net: String representing a network number
    """
    shift = int(net.split('/')[1])
    bits = net.split('/')[0].split('.')
    net = ''.join([format(bin(int(byte)).lstrip('0b').zfill(8)) for byte in bits])
    source = ''.join([format(bin(int(byte, 16)).lstrip('0b').zfill(8)) for byte in packet.ip_source])
    dest = ''.join([format(bin(int(byte, 16)).lstrip('0b').zfill(8)) for byte in packet.ip_dest])

    if net[:shift] == source[:shift] or net == dest[:shift]:
        return True
    return False


def create_udp_header(packet_data):
    """Constructs a UDPHeader object and returns it.
       packet_data: List of hex data to parsed into header.
    """
    return UDPHeader(source_port=bytes_to_int(packet_data[0:2], big_e=True),
                     destination_port=bytes_to_int(packet_data[2:4], big_e=True),
                     length=bytes_to_int(packet_data[4:6], big_e=True),
                     checksum=packet_data[6:8],
                     data=packet_data[8:])


def create_tcp_header(packet_data):
    """Constructs a TCPHeader object and returns it.
       packet_data: List of hex data to parsed into header.
    """
    return TCPHeader(source_port=bytes_to_int(packet_data[0:2], big_e=True),
                     destination_port=bytes_to_int(packet_data[2:4], big_e=True),
                     sequence_num=bytes_to_int(packet_data[4:8], big_e=True),
                     ack_num=bytes_to_int(packet_data[8:12], big_e=True),
                     data_offset=(bytes_to_int(packet_data[12], big_e=True) >> 4) * 4,
                     flags=packet_data[13],
                     window=packet_data[14:16],
                     checksum=packet_data[16:18],
                     urgent_pointer=bytes_to_int(packet_data[18:20], big_e=True),
                     data=packet_data[20:])


def create_icmp_header(packet_data):
    """Constructs a ICMPHeader object and returns it.
       packet_data: List of hex data to parsed into header.
    """
    return ICMPHeader(p_type=bytes_to_int(packet_data[0]),
                      code=bytes_to_int(packet_data[1]),
                      checksum=packet_data[2:4],
                      data=packet_data[4:])


# ============================================================== #
#  SECTION: Global Definitions                                   #
# ============================================================== #

# dictionary mapping protocol names to functions that call constructors and return objects
PROTOCOL_TO_CLASS = {Protocol.UDP.name: create_udp_header,
                     Protocol.TCP.name: create_tcp_header,
                     Protocol.ICMP.name: create_icmp_header}

# dictionary mapping argument keywords to verification functions
KEYWORD_TO_FUNCTION = {'host': is_host,
                       'port': is_port,
                       'ip': is_ip,
                       'tcp': is_tcp,
                       'udp': is_udp,
                       'icmp': is_icmp,
                       'net': is_net}

# argument keywords that require no additional arguments
single_args = ['ip', 'tcp', 'udp', 'icmp']

# argument keywords that require an additional argument
double_args = ['host', 'port', 'net']

# ============================================================== #
#  SECTION: Main                                                 #
# ============================================================== #


if __name__ == '__main__':

    # removes __file__ from args list
    args = sys.argv[1:]

    # ensure -r flag and file are in arguments
    assert len(args) >= 2, 'Required arguments not found, see readme'
    assert args[0] == '-r', 'Required flag -r not found, see readme'
    file = args[1]

    # parses for -c flag and value
    i = 2
    count = -1
    if len(args) > 2 and args[2] == '-c':
        assert len(args) >= 4, '-c flag found, but not argument'
        count = int(args[3])
        i = 4

    # sets args to unparsed values
    args = args[i:]

    # iterates through remaining values for keyword arguments and values
    verification_sets = []
    current_set = []
    i = 0
    while i < len(args):
        result = True
        # bools are only expected after first expression
        if i:
            assert args[i] in ['and', 'or'], 'expected bool instead found: {}, see readme'.format(args[i])
            # if or is found make new set
            if args[i] == 'or':
                verification_sets.append(current_set)
                current_set = []
            i += 1

        # checks if expression is negated
        if len(args) > i and args[i] == 'not':
            result = False
            i += 1

        # handles out of bounds exception
        assert len(args) > i, 'expected flag after {}, see readme'.format(args[i-1])
        # handles item not found in dict exception
        assert args[i] in single_args or args[i] in KEYWORD_TO_FUNCTION, \
            'expected flag instead found: {}, see readme'.format(args[i])
        # adds tuple of (exp_result, verification_function, additional_arg) to current set
        if args[i] in single_args:
            current_set.append((result, KEYWORD_TO_FUNCTION[args[i]]))
        elif args[i] in double_args:
            assert len(args) > i + 1, 'expected value for {}'.format(args[i])
            current_set.append((result, KEYWORD_TO_FUNCTION[args[i]], args[i+1]))
            i += 1
        i += 1
    # add most recent set to verification_sets
    verification_sets.append(current_set)

    # read file and output into a list of hexadecimals
    with open(file, 'rb') as fp:
        hex_file = [hex(b) for b in fp.read()]

    # set up global header
    gh = GlobalHeader(magic_number=hex_file[:4],
                      version_major=hex_file[4:6],
                      version_minor=hex_file[6:8],
                      this_zone=hex_file[8:12],
                      sig_figs=hex_file[12:16],
                      snap_len=hex_file[16:20],
                      network=hex_file[20:GlobalHeader.length])
    hex_file = hex_file[GlobalHeader.length:]

    # read and print packet data until count reaches 0 or eof
    while count != 0 and hex_file:

        # parse and setup packet header
        ph = PacketHeader(bytes_to_int(hex_file[:4]),
                          bytes_to_int(hex_file[4:8]),
                          bytes_to_int(hex_file[8:12]),
                          bytes_to_int(hex_file[12:PacketHeader.length]))
        hex_file = hex_file[PacketHeader.length:]

        # if the protocol is not in Protocol skip
        # currently this parser only handles IPv4
        if bytes_to_int(hex_file[23]) not in Protocol._value2member_map_:
            hex_file = hex_file[ph.packet_length:]
            continue

        # parse and assemble protocol header
        protocol_header = PROTOCOL_TO_CLASS[Protocol(bytes_to_int(hex_file[23])).name](hex_file[34:])

        # parse and assemble entire packet
        packet = Packet(header=ph,
                        mac_dest=hex_file[:6],
                        mac_source=hex_file[6:12],
                        e_type=hex_file[12:14],
                        version=bytes_to_int(hex_file[14]) >> 4,
                        ihl=(bytes_to_int(hex_file[14]) & 0x0F) * 4,
                        dscp=bytes_to_int(hex_file[15]) >> 2,
                        ecn=bytes_to_int(hex_file[15]) & 0x03,
                        total_length=bytes_to_int(hex_file[16:18], big_e=True),
                        identification=bytes_to_int(hex_file[18:20], big_e=True),
                        flags=hex_file[20:22],
                        ttl=bytes_to_int(hex_file[22]),
                        protocol=bytes_to_int(hex_file[23], big_e=True),
                        header_checksum=hex_file[24:26],
                        ip_source=hex_file[26:30],
                        ip_dest=hex_file[30:34],
                        protocol_header=protocol_header)

        # verify that the packet meets argument criteria if so print string representation
        for verifications in verification_sets:
            if all([verification[0] == verification[1](packet, *verification[2:]) for verification in verifications]):
                print(packet)
                count -= 1
                break

        # remove old packet data from hex_file
        hex_file = hex_file[ph.packet_length:]
