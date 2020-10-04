# Packet Sniffer

Parses a .pcap file for IPv4 packets and sends data to terminal.

## Requirements

Tested with Python 3.7

## Usage

python pktsniffer.py -r <filename>          : Basic Usage will return output of all IPv4 packets in <filename>
                                              'and'/'or' is never required before or after this flag.

python pktsniffer.py -r <filename> -c 10    : Will print 10 packets from <filename>

python pktsniffer.py -r <filename> -c 10 udp
                                            : Will print 10 packets from <filename> that are also udp packets.

python pktsniffer.py -r <filename> -c 10 not udp
                                            : Will print 10 packets from <filename> that are not udp packets.

python pktsniffer.py -r <filename> -c 10 port 80
                                            : Will print 10 packets from <filename> that have a src or dst port of 80.

python pktsniffer.py -r <filename> udp and host 1.1.1.1
                                            : Will print all packets from <filename> that are udp packets with a src
                                           or dst ip address of 1.1.1.1.

python pktsniffer.py -r <filename> udp and host 1.1.1.1 or net 123.123.0.0/16
                                            : Will print all packets from <filename> that are (udp packets with a src
                                              or dst ip address of 1.1.1.1) OR (whose src or dst address has a net number).
                                              Net - Only the first 16 bits of the provided net flag and the src/dst
                                              addresses will be compared.
                                              In this example net will return true for the following src/dst addresses
                                              123.123.234.232
                                              123.123.445.345
                                              etc.
                                              In this example net will return False for the following src/dst addresses
                                              645.233.0.0
                                              123.124.0.0
                                              etc.


Optional Args:
    -c <integer>                        : Prints up to <integer> packets that meet remaining criteria
                                          If provided must be immediatly after -r requirement.
                                          'and'/'or' is never required before or after this flag.


    Match filters:
    host <ip_address>                   : Only packets with a src or dst ip address will be considered.
    port <port>                         : Only packets with matching src or dst ports will be considered.
    net  <ip_mask>/<integer>            : Only packets whose src or dst addresses has net as a network number will be considered.

    Type filters:
    ip                                  : Only IP packets will be considered.
    tcp                                 : Only TCP packets will be considered.
    udp                                 : Only UDP packets will be considered.
    icmp                                : Only ICMP packets will be considered.

    Booleans:
    not                                 : Use prior to any of the 'Match' or 'Type' filters to negate them
    and                                 : Use in between two of the 'Match' or 'Type' filters to chain requirements.
    or                                  : Use in between two of the 'Match' or 'Type' filters to create a new requirement set.
