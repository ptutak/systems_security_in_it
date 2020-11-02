import socketserver
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


class ClientConnection:
    pass


class ClientStorage:
    pass


class CommunicationServer(socketserver.ThreadingTCPServer):
    pass


class Client:
    def __init__(self, server_address: Tuple[str, int]) -> int:
        self._server_address = server_address
        self._server_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._server_public_key = self._private_key.public_key()
