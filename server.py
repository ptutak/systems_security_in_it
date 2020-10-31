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

from common import Command
from constants import (
    HASHING_ALGORITHM,
    HEADING_BYTEORDER,
    HEADING_LENGTH,
    HEADING_SIGNED,
    PUBLIC_KEY_ALGORITHM,
    PUBLIC_KEY_MGF,
    PUBLIC_KEY_MGF_ALGORITHM,
    PUBLIC_KEY_PADDING,
)
from exception import InvalidCommand, ShasumError


class ClientConnection:
    def __init__(self, public_key_data: bytes):
        command, public_key_composit = pickle.loads(public_key_data)

        if command != Command.CONNECT:
            raise InvalidCommand("Expected CONNECT command.")

        public_key, public_key_sha256 = public_key_composit

        if HASHING_ALGORITHM(public_key).hexdigest() != public_key_sha256:
            raise ShasumError("The public key has been tampered.")

        self._public_key: _RSAPublicKey = serialization.load_pem_public_key(
            public_key, default_backend()
        )

        self._symmetric_key = Fernet.generate_key()
        self._cryption: Fernet = Fernet(self._symmetric_key)

    def prepare_symmetric_key(self):
        encrypted_key = self._public_key.encrypt(
            self._symmetric_key,
            PUBLIC_KEY_PADDING(
                mgf=PUBLIC_KEY_MGF(PUBLIC_KEY_MGF_ALGORITHM()),
                algorithm=PUBLIC_KEY_ALGORITHM(),
                label=None,
            ),
        )
        return pickle.dumps(
            (encrypted_key, HASHING_ALGORITHM(encrypted_key).hexdigest())
        )

    def decrypt(self, data):
        return pickle.loads(self._cryption.decrypt(data))

    def encrypt(self, data):
        return self._cryption.encrypt(data)


class ClientStorage:
    def __init__(self):
        self._clients_lock = threading.Lock()
        self._clients: Dict[Tuple[str, int], ClientConnection] = {}
        self._client_nicknames_lock = threading.Lock()
        self._client_nicknames: Dict[str, Tuple[str, int]] = {}
        self._connections

    def get_client(
        self, client_id: Tuple[str, int], data: bytes
    ) -> Optional[ClientConnection]:
        with self._clients_lock:
            if client_id in self._clients:
                client = self._clients[client_id]
                response = client.decrypt(data)
            else:
                client = self._create_client(client_id, data)
                response = client.prepare_symmetric_key()

        return (response, client)

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
