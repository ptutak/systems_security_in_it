import hashlib
from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class ByteOrder(Enum):
    BIG = "big"
    SMALL = "small"


HEADING_LENGTH = 8
HEADING_BYTEORDER = ByteOrder.BIG.value
HEADING_SIGNED = False


KEY_PADDING = padding.OAEP
KEY_ALGORITHM = hashes.SHA256
KEY_MGF = padding.MGF1
KEY_MGF_ALGORITHM = hashes.SHA256


HASHING_ALGORITHM = hashlib.sha256

ZERO_UUID = bytes(16)
