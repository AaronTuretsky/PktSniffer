# ============================================================== #
#  SECTION: Imports                                              #
# ============================================================== #

# standard library
from enum import Enum

# third party library
# local

# ============================================================== #
#  SECTION: Global Definitions                                   #
# ============================================================== #

# int value of tcp
TCP_NUM = 6

# int value of ICMP
ICMP_NUM = 1

# int value of UDP
UDP_NUM = 17

# ============================================================== #
#  SECTION: Class Definitions                                    #
# ============================================================== #


class Protocol(Enum):
    TCP = TCP_NUM
    ICMP = ICMP_NUM
    UDP = UDP_NUM

# ============================================================== #
#  SECTION: Global Definitions                                   #
# ============================================================== #


def bytes_to_int(bytes, big_e=False):
    if not isinstance(bytes, list):
        bytes = [bytes]
    if big_e:
        bytes = reversed(bytes)
    value = 0
    for i, byte in enumerate(bytes):
        value = value | (int(byte, 16) << (8 * i))
    return value
