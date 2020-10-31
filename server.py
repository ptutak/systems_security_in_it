import logging
import pickle
import socketserver
import threading
from typing import Any, Callable, Dict, Optional, Tuple

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

    def get_response(
        self, client_id: Tuple[str, int], data: bytes
    ) -> Tuple[Command, Any, ClientConnection]:
        with self._clients_lock:
            if client_id in self._clients:
                client_connection = self._clients[client_id]
                command, message = client_connection.decrypt(data)
            else:
                client_connection = self._create_client(client_id, data)
                message = client_connection.prepare_symmetric_key()
                command = Command.CONNECT
        return (command, message, client_connection)

    def _create_client(self, client_id, data) -> ClientConnection:
        new_connection = ClientConnection(data)
        self._clients[client_id] = new_connection
        return new_connection

    def match_client(self, client_address) -> Optional[ClientConnection]:
        with self._clients_lock:
            return self._clients.get(client_address)

    def match_client_by_nickname(self, nickname) -> Optional[Tuple[str, int]]:
        with self._client_nicknames_lock:
            return self._client_nicknames.get(nickname)

    def register_client_nickname(self, client_id, nickname) -> bool:
        with self._client_nicknames_lock:
            if nickname not in self._client_nicknames:
                self._client_nicknames[nickname] = client_id
                return True
            else:
                return False


class EncryptionMessageHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(self, request, client_address, server)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    def setup(self):
        pass

    def handle(self):
        heading, data = self._get_data(self.request)
        command, message, client_connection = self.server.client_storage.get_response(
            self.client_address, data
        )
        self.COMMANDS[command](self, self.client_address, message, client_connection)

    @classmethod
    def _get_data(cls, request):
        heading = request.recv(HEADING_LENGTH)
        data_length = int.from_bytes(
            heading, byteorder=HEADING_BYTEORDER.value, signed=HEADING_SIGNED,
        )
        data = request.recv(data_length)
        return (heading, data)

    @classmethod
    def _prepare_data(cls, message):
        data_length = len(message)
        heading = data_length.to_bytes(
            HEADING_LENGTH, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED
        )
        return (heading, message)

    def _connect_command(
        self,
        client_address: Tuple[str, int],
        message: bytes,
        client_connection: ClientConnection,
    ):
        heading, message = self._prepare_data(message)
        self.request.sendall(heading)
        self.request.sendall(message)

    def _get_user_list_command(self, client_address, message, client_connection):
        pass

    def _register_nickname_command(self, client_address, message, client_connection):
        pass

    def _send_message_command(self, client_address, message, client_connection):
        pass

    def finish(self):
        pass

    COMMANDS: Dict[Command, Callable] = {
        Command.CONNECT: _connect_command,
        Command.GET_USER_LIST: _get_user_list_command,
        Command.REGISTER_NICKNAME: _register_nickname_command,
        Command.SEND_MESSAGE: _send_message_command,
    }


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(self, server_address, handler_class)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageServer]")
        self.client_storage = ClientStorage()
