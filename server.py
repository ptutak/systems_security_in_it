import logging
import pickle
import socketserver
import threading
import uuid
from typing import Callable, Dict, Optional, Tuple

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
    ZERO_UUID,
)
from exception import AuthenticationError, InvalidCommand, ShasumError, ResponseAddressError


class ClientConnection:
    def __init__(self, client_uuid: bytes, public_key_data: bytes):
        self._lock = threading.Lock()
        self._client_uuid = client_uuid
        self._client_secret_uuid = uuid.uuid4().bytes
        self._client_response_address = None

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

    @property
    def client_uuid(self):
        return self._client_uuid

    @property
    def client_secret_uuid(self):
        return self._client_secret_uuid

    @property
    def client_response_address(self):
        if self._client_response_address is not None:
            return self._client_response_address
        else:
            raise ResponseAddressError("The response address is not set.")

    @client_response_address.setter
    def client_response_address(self, response_address: Tuple[str, int]):
        with self._lock:
            if self._client_response_address is None:
                self._client_response_address = response_address
            else:
                raise ResponseAddressError("The response address for the connection is already set.")

    def prepare_symmetric_key(self):
        symmetric_key_hash = HASHING_ALGORITHM(self._symmetric_key).hexdigest()
        data = pickle.dumps((self._symmetric_key, symmetric_key_hash))
        heading = self._client_secret_uuid
        encrypted_data = self._public_key.encrypt(
            heading + data,
            PUBLIC_KEY_PADDING(
                mgf=PUBLIC_KEY_MGF(PUBLIC_KEY_MGF_ALGORITHM()),
                algorithm=PUBLIC_KEY_ALGORITHM(),
                label=None,
            ),
        )
        return encrypted_data

    def decrypt(self, data):
        decrypted = self._cryption.decrypt(data)
        client_secret_uuid = decrypted[:16]
        if client_secret_uuid != self.client_secret_uuid:
            raise AuthenticationError("Wrong secret key.")
        return pickle.loads(decrypted[16:])

    def encrypt(self, data):
        return self._cryption.encrypt(self._client_secret_uuid + pickle.dumps(data))


class ClientStorage:
    def __init__(self):
        self._clients_lock = threading.Lock()
        self._clients: Dict[bytes, ClientConnection] = {}

    def get_response(
        self, data: bytes
    ) -> Tuple[Command, bytes, Optional[ClientConnection]]:
        client_uuid = data[:16]
        datagram = data[16:]
        with self._clients_lock:
            return self._extract_response(client_uuid, datagram)

    def _extract_response(
        self, client_uuid: bytes, datagram: bytes
    ) -> Tuple[Command, bytes, ClientConnection]:
        if client_uuid != ZERO_UUID:
            client_connection = self._clients.get(client_uuid)
            if client_connection is None:
                return (Command.RESET, b"", None)
            command, message = client_connection.decrypt(datagram)
        else:
            while True:
                new_uuid = uuid.uuid4().bytes
                if new_uuid not in self._clients:
                    break
            client_connection = self._create_client(new_uuid, datagram)
            message = client_connection.prepare_symmetric_key()
            command = Command.CONNECT
        return (command, message, client_connection)

    def _create_client(self, client_uuid, data) -> ClientConnection:
        new_connection = ClientConnection(client_uuid, data)
        self._clients[client_uuid] = new_connection
        return new_connection

    def match_client(self, client_uuid: bytes) -> Optional[ClientConnection]:
        with self._clients_lock:
            return self._clients.get(client_uuid)


class UserStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._client_nicknames: Dict[str, bytes] = {}

    def get_client_id(self, nickname):
        pass


class EncryptionMessageHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(self, request, client_address, server)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    def setup(self):
        pass

    def handle(self):
        heading, data = self._extract_data(self.request)
        command, message, client_connection = self.server.client_storage.get_response(
            data
        )
        self.COMMANDS[command](self, self.client_address, message, client_connection)

    @classmethod
    def _extract_data(cls, request):
        heading = request.recv(HEADING_LENGTH)
        data_length = int.from_bytes(
            heading, byteorder=HEADING_BYTEORDER.value, signed=HEADING_SIGNED,
        )
        data = request.recv(data_length)
        return (heading, data)

    @classmethod
    def _prepare_data(cls, message: bytes, client_connection: ClientConnection):
        data = client_connection.client_uuid + message
        data_length = len(data)
        heading = data_length.to_bytes(
            HEADING_LENGTH, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED
        )
        return (heading, data)

    def _connect_command(
        self,
        client_address: Tuple[str, int],
        message: bytes,
        client_connection: ClientConnection,
    ) -> None:
        heading, data = self._prepare_data(message, client_connection)
        self.request.sendall(heading)
        self.request.sendall(data)

    def _register_command(
        self,
        client_address: Tuple[str, int],
        message: bytes,
        client_connection: ClientConnection,
    ):
        client_response_address, client_nickname = pickle.loads(message)
        client_connection.client_response_address = client_response_address
        self.server.user_storage.register(client_nickname, client_connection)


    def _get_user_list_command(self, client_address, message, client_connection):
        pass

    def _send_message_command(self, client_address, message, client_connection):
        pass

    def _reset_command(self, client_address, message, client_connection):
        pass

    def finish(self):
        pass

    COMMANDS: Dict[Command, Callable] = {
        Command.CONNECT: _connect_command,
        Command.GET_USER_LIST: _get_user_list_command,
        Command.REGISTER: _register_command,
        Command.SEND_MESSAGE: _send_message_command,
        Command.RESET: _reset_command,
    }


class EncryptionMessageServer(socketserver.ThreadingTCPServer):
    def __init__(self, server_address, handler_class=EncryptionMessageHandler):
        super().__init__(self, server_address, handler_class)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageServer]")
        self.client_storage = ClientStorage()
        self.user_storage = UserStorage()
