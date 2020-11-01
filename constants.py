import hashlib
from enum import Enum

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class ByteOrder(Enum):
    BIG = "big"
    SMALL = "small"


HEADING_LENGTH = 8
HEADING_BYTEORDER = ByteOrder.BIG
HEADING_SIGNED = False


PUBLIC_KEY_PADDING = padding.OAEP
PUBLIC_KEY_ALGORITHM = hashes.SHA256
PUBLIC_KEY_MGF = padding.MGF1
PUBLIC_KEY_MGF_ALGORITHM = hashes.SHA256


HASHING_ALGORITHM = hashlib.sha256

ZERO_UUID = bytes(16)
