# ============================================================== #
#  SECTION: Imports                                              #
# ============================================================== #

# standard library
# third party library
# local
from util import *

# ============================================================== #
#  SECTION: Global Functions                                     #
# ============================================================== #

GLOBAL_HEADER_LENGTH = 24

PACKET_HEADER_LENGTH = 16
# ============================================================== #
#  SECTION: Class Definitions                                    #
# ============================================================== #


class GlobalHeader:
    """Class representing the global packet header."""
    length = GLOBAL_HEADER_LENGTH

    def __init__(self, magic_number, version_major, version_minor,
                 this_zone, sig_figs, snap_len, network):
        self.magic_number = magic_number
        self.version_major = version_major
        self.version_minor = version_minor
        self.this_zone = this_zone
        self.sig_figs = sig_figs
        self.snap_len = snap_len
        self.network = network


class PacketHeader:
    """Class representing a packet header."""
    length = PACKET_HEADER_LENGTH

    def __init__(self, timestamp, microseconds, data_size, packet_length):
        # timestamp in seconds
        self.timestamp = timestamp
        self.microseconds = microseconds
        self.data_size = data_size
        self.packet_length = packet_length

    def __str__(self):
        pass


class UDPHeader:
    """Class representing the header of UDP section of a packet."""
    # string name of protocol
    name = Protocol.UDP.name
    # maps ports to service
    ports_to_service = {2049: 'NFS',
                        1234: 'games'}

    def __init__(self, source_port, destination_port, length, checksum, data):
        self.source_port = source_port
        self.destination_port = destination_port
        self.length = length
        self.checksum = checksum
        self.data = data

    def __str__(self):
        """Returns string representation of UDPHeader."""
        protocol_header = \
            '{0}:  -----{0} Header -----\n' \
            '{0}:\n' \
            '{0}:  Source port = {1}\n' \
            '{0}:  Destination port = {2} ({3})\n' \
            '{0}:  Length = {4}\n' \
            '{0}:  Checksum = {5}{6}\n' \
            '\n'

        protocol_header = protocol_header.format(self.name,
                                                 self.source_port,
                                                 self.destination_port,
                                                 self.ports_to_service[self.destination_port]
                                                 if self.destination_port in self.ports_to_service else 'unknown',
                                                 self.length,
                                                 *[byte.lstrip('0x').zfill(2) for byte in self.checksum])
        return protocol_header


class ICMPHeader:
    """Class representing the header of ICMP section of a packet."""
    # string name of protocol
    name = Protocol.ICMP.name
    # maps type to request
    type_to_request = {8: 'request',
                       0: 'reply'}

    def __init__(self, p_type, code, checksum, data):
        self.p_type = p_type
        self.code = code
        self.checksum = checksum
        self.data = data

    def __str__(self):
        """Returns string representation of ICMPHeader."""
        protocol_header = \
            '{0}:  -----{0} Header -----\n' \
            '{0}:\n' \
            '{0}:  Type = {1} (Echo {2})\n' \
            '{0}:  Code = {3}\n' \
            '{0}:  Checksum = {4}{5}\n' \
            '\n'

        protocol_header = protocol_header.format(self.name,
                                                 self.p_type,
                                                 self.type_to_request[self.p_type]
                                                 if self.p_type in self.type_to_request else 'unknown',
                                                 self.code,
                                                 *[byte.lstrip('0x').zfill(2) for byte in self.checksum])
        return protocol_header


class TCPHeader:
    """Class representing the header of TCP section of a packet."""
    # string name of protocol
    name = Protocol.TCP.name
    # maps ports to service
    ports_to_service = {2049: 'NFS',
                        80: 'http'}

    def __init__(self, source_port, destination_port, sequence_num, ack_num, data_offset, flags, window,
                 checksum, urgent_pointer, data):
        self.source_port = source_port
        self.destination_port = destination_port
        self.sequence_num = sequence_num
        self.ack_num = ack_num
        self.data_offset = data_offset
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgent_pointer = urgent_pointer
        self.data = data

    def __str__(self):
        """Returns string representation of TCPHeader."""
        protocol_header = \
            '{0}:  -----{0} Header -----\n' \
            '{0}:\n' \
            '{0}:  Source port = {1}\n' \
            '{0}:  Destination port = {2} ({3})\n' \
            '{0}:  Sequence number = {4}\n' \
            '{0}:  Acknowledgement number = {5}\n' \
            '{0}:  Data offset = {6} bytes\n' \
            '{0}:  Flags = {7}\n' \
            '{0}:        ..{8}. .... ={9} urgent pointer\n' \
            '{0}:        ...{10} .... ={11} Acknowledgement\n' \
            '{0}:        .... {12}... ={13} Push\n' \
            '{0}:        .... .{14}.. ={15} Reset\n' \
            '{0}:        .... ..{16}. ={17} Sys\n' \
            '{0}:        .... ...{18} ={19} Fin\n' \
            '{0}:  Window = {20}{21}\n' \
            '{0}:  Checksum = 0x{22}{23}\n' \
            '{0}:  Urgent pointer = {24}\n' \
            '{0}:  No options\n'

        protocol_header = protocol_header.format(self.name,
                                                 self.source_port,
                                                 self.destination_port,
                                                 self.ports_to_service[self.destination_port]
                                                 if self.destination_port in self.ports_to_service else 'unknown',
                                                 self.sequence_num,
                                                 self.ack_num,
                                                 self.data_offset,
                                                 self.flags,
                                                 (bytes_to_int(self.flags, big_e=True) >> 5) & 1,
                                                 ' No' if not (bytes_to_int(self.flags, big_e=True) >> 5) & 1 else '',
                                                 (bytes_to_int(self.flags, big_e=True) >> 4) & 1,
                                                 ' No' if not (bytes_to_int(self.flags, big_e=True) >> 4) & 1 else '',
                                                 (bytes_to_int(self.flags, big_e=True) >> 3) & 1,
                                                 ' No' if not (bytes_to_int(self.flags, big_e=True) >> 3) & 1 else '',
                                                 (bytes_to_int(self.flags, big_e=True) >> 2) & 1,
                                                 ' No' if not (bytes_to_int(self.flags, big_e=True) >> 2) & 1 else '',
                                                 (bytes_to_int(self.flags, big_e=True) >> 1) & 1,
                                                 ' No' if not (bytes_to_int(self.flags, big_e=True) >> 1) & 1 else '',
                                                 (bytes_to_int(self.flags, big_e=True) >> 5) & 1,
                                                 ' No' if not bytes_to_int(self.flags, big_e=True) & 1 else '',
                                                 *[byte.lstrip('0x').zfill(2) for byte in self.window],
                                                 *[byte.lstrip('0x').zfill(2) for byte in self.checksum],
                                                 self.urgent_pointer)
        return protocol_header


class Packet:
    """Class representing entire packet."""
    def __init__(self, header, mac_dest, mac_source, e_type, version, ihl, dscp, ecn, total_length,
                 identification, flags, ttl, protocol, header_checksum, ip_source, ip_dest,
                 protocol_header):
        self.header = header
        self.mac_dest = mac_dest
        self.mac_source = mac_source
        self.e_type = e_type
        self.version = version
        self.ihl = ihl
        self.dscp = dscp
        self.ecn = ecn
        self.total_length = total_length
        self.identification = identification
        self.flags = flags
        self.ttl = ttl
        self.protocol = protocol
        self.header_checksum = header_checksum
        self.ip_source = ip_source
        self.ip_dest = ip_dest
        self.protocol_header = protocol_header

    def __str__(self):
        """Returns string representation of packet."""
        ether_header = \
            'ETHER:  -----Ether Header -----\n' \
            'ETHER:\n' \
            'ETHER:  Packet size = {} bytes\n' \
            'ETHER:  Destination = {}:{}:{}:{}:{}:{},\n' \
            'ETHER:  Source      = {}:{}:{}:{}:{}:{},\n' \
            'ETHER:  Ethertype = {}{} ({})\n' \
            'ETHER:\n'

        ip_header = \
            'IP:   -----IP Header -----\n' \
            'IP:\n' \
            'IP:   Version = {}\n' \
            'IP:   Header length = {} bytes\n' \
            'IP:   Type of service = 0x{}\n' \
            'IP:         xxx. .... = 0 (precedence)\n' \
            'IP:         ...{} .... = {} delay\n' \
            'IP:         .... {}... = {} throughput\n' \
            'IP:         .... .{}.. = {} reliability\n' \
            'IP:   Total length = {} bytes\n' \
            'IP:   Identification = {}\n' \
            'IP:   Flags = {}\n' \
            'IP:         .{}.. .... ={} fragment\n' \
            'IP:         ..{}. .... = {}\n' \
            'IP:   Fragment offset = {} bytes\n' \
            'IP:   Time to live = {} seconds/hops\n' \
            'IP:   Protocol = {} ({})\n' \
            'IP:   Header checksum = {}{}\n' \
            'IP:   Source address = {}.{}.{}.{}, (hostname unknown)\n' \
            'IP:   Destination address = {}.{}.{}.{}, (hostname unknown)\n' \
            'IP:   No options\n' \
            'IP:\n'

        ether_header = ether_header.format(self.header.packet_length,
                                           *[byte.lstrip('0x') for byte in self.mac_dest],
                                           *[byte.lstrip('0x') for byte in self.mac_source],
                                           *[byte.lstrip('0x').zfill(2) for byte in self.e_type],
                                           'IP' if bytes_to_int(self.e_type) in [8] else 'UNKNOWN')

        ip_header = ip_header.format(self.version,
                                     self.ihl,
                                     hex(self.dscp).lstrip('0x').zfill(2),
                                     (self.dscp >> 4) & 0x01,
                                     'normal' if not (self.dscp >> 4) & 0x01 else 'abnormal',
                                     (self.dscp >> 3) & 0x01,
                                     'normal' if not (self.dscp >> 3) & 0x01 else 'abnormal',
                                     (self.dscp >> 2) & 0x01,
                                     'normal' if not (self.dscp >> 2) & 0x01 else 'abnormal',
                                     self.total_length,
                                     self.identification,
                                     hex(int(self.flags[0], 16) >> 4),
                                     (int(self.flags[0], 16) >> 6) & 0x01,
                                     ' do not' if (int(self.flags[0], 16) >> 6) & 0x01 else '',
                                     (int(self.flags[0], 16) >> 5) & 0x01,
                                     'last fragment' if not (int(self.flags[0], 16) >> 5) & 0x01 else 'more fragments',
                                     bytes_to_int([hex(int(self.flags[0], 16) & 0x01), *self.flags[1:]], True),
                                     self.ttl,
                                     Protocol(self.protocol).value,
                                     Protocol(self.protocol).name,
                                     *[byte.lstrip('0x').zfill(2) for byte in self.header_checksum],
                                     *[int(byte, 16) for byte in self.ip_source],
                                     *[int(byte, 16) for byte in self.ip_dest])

        # calls the __str__ function of the protocol header
        protocol_header = str(self.protocol_header)

        return ether_header + ip_header + protocol_header
