import hashlib
import logging
import pickle
import socketserver
import threading
from typing import Dict, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives import serialization

from constants import (
    HEADING_BYTEORDER,
    HEADING_LENGTH,
    HEADING_SIGNED,
    PUBLIC_KEY_ALGORITHM,
    PUBLIC_KEY_MGF,
    PUBLIC_KEY_MGF_ALGORITHM,
    PUBLIC_KEY_PADDING,
)
from exception import ShasumError


class ClientConnection:
    def __init__(self, public_key_data: bytes):
        self._lock = threading.Lock()
        public_key, public_key_sha256 = pickle.loads(public_key_data)
        if hashlib.sha256(public_key).hexdigest() != public_key_sha256:
            raise ShasumError("The public key has been tampered")
        self._public_key: _RSAPublicKey = serialization.load_pem_public_key(
            public_key, default_backend()
        )
        self._symmetric_key = Fernet.generate_key()
        self._cryption: Fernet = Fernet(self._symmetric_key)

    def prepare_symmetric_key(self):
        self._public_key.encrypt(
            self._symmetric_key,
            PUBLIC_KEY_PADDING(
                mgf=PUBLIC_KEY_MGF(PUBLIC_KEY_MGF_ALGORITHM()),
                algorithm=PUBLIC_KEY_ALGORITHM(),
                label=None,
            ),
        )

    def __enter__(self):
        self._lock.acquire()

    def __exit__(self):
        self._lock.release()


class ClientStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._clients: Dict[Tuple[str, int], ClientConnection] = {}

    def get_client(
        self, client_id: Tuple[str, int], data: bytes
    ) -> Optional[ClientConnection]:
        with self._lock:
            if client_id in self._clients:
                return self._clients[client_id]
            return self._create_client(client_id, data)

    def _create_client(self, client_id, data) -> ClientConnection:
        new_connection = ClientConnection(data)
        self._clients[client_id] = new_connection
        return new_connection


class EncryptionMessageHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(self, request, client_address, server)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    def setup(self):
        pass

    def handle(self):
        data = self._get_data(self.request)
        client = self.server.client_storage.get_client(self.client_address, data)

    @classmethod
    def _get_data(self, request):
        heading = request.recv(HEADING_LENGTH)
        message_length = int.from_bytes(
            heading, byteorder=HEADING_BYTEORDER.value, signed=HEADING_SIGNED,
        )
        message = request.recv(message_length)
        return (heading, message)

    def finish(self):
        pass


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(self, server_address, handler_class)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageServer]")
        self.client_storage = ClientStorage()
