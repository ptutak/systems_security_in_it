from enum import Enum


class ByteOrder(Enum):
    BIG = "big"
    SMALL = "small"


HEADING_LENGTH = 8
HEADING_BYTEORDER = ByteOrder.BIG
HEADING_SIGNED = False
