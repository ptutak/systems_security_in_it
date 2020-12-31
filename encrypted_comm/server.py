import logging
import pickle
import socketserver
import threading
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .common import (
    Command,
    Cryption,
    Response,
    Message,
    Request,
    FernetCryption,
    IdentCryption,
    RSAEncryption,
)
from .constants import (
    HASHING_ALGORITHM,
    HEADING_BYTEORDER,
    HEADING_LENGTH,
    HEADING_SIGNED,
    KEY_ALGORITHM,
    KEY_MGF,
    KEY_MGF_ALGORITHM,
    KEY_PADDING,
    ZERO_UUID,
)
from .exception import (
    AuthenticationError,
    InvalidCommand,
    RegistrationError,
    ResponseAddressError,
    ShasumError,
)


class ClientConnection:
    ZERO_CRYPTION = IdentCryption()

    def __init__(self, client_uuid: uuid.UUID, register_request: bytes):
        self._lock = threading.Lock()
        self._uuid = client_uuid
        self._secret_uuid = uuid.uuid4()
        self._symmetric_key: bytes = Fernet.generate_key()
        self._cryption: Cryption = FernetCryption(
            self.uuid, self.secret_uuid, self._symmetric_key
        )

        self._client_communication_address = None
        request = self.ZERO_CRYPTION.decrypt_and_get_request(register_request)
        command, public_key_composit = request.command, request.message.data
        if command != Command.CONNECT:
            raise InvalidCommand("Expected CONNECT command.")

        public_key, public_key_sha256 = public_key_composit
        if HASHING_ALGORITHM(public_key).hexdigest() != public_key_sha256:
            raise ShasumError("The public key has been tampered.")

        self._public_key: RSAPublicKey = serialization.load_pem_public_key(
            public_key, default_backend()
        )

        self._public_key_cryption = RSAEncryption(
            self.uuid, self.secret_uuid, self._public_key
        )

    @property
    def uuid(self):
        return self._uuid

    @property
    def secret_uuid(self):
        return self._secret_uuid

    @property
    def communication_address(self):
        if self._client_communication_address is not None:
            return self._client_communication_address
        else:
            raise ResponseAddressError("The response address is not set.")

    @communication_address.setter
    def communication_address(self, communication_address: Tuple[str, int]):
        with self._lock:
            if self._client_communication_address is None:
                self._client_communication_address = communication_address
            else:
                raise ResponseAddressError(
                    "The response address for the connection is already set."
                )

    def prepare_encrypted_symmetric_key(self) -> bytes:
        symmetric_key_hash = HASHING_ALGORITHM(self._symmetric_key).hexdigest()
        data = (self._symmetric_key, symmetric_key_hash)
        request = Request(Response.CONNECTION_SUCCESS, Message.from_data(data))
        return self._public_key_cryption.prepare_request_and_encrypt(request)

    def decrypt(self, encrypted_request: bytes) -> Request:
        return self._cryption.decrypt_and_get_request(encrypted_request)

    def encrypt(self, request: Request) -> bytes:
        return self._cryption.prepare_request_and_encrypt(request)


class ClientRequest:
    def __init__(self, request: Request, connection: ClientConnection):
        self.request = request
        self.connection = connection


class ClientStorage:
    def __init__(self):
        self._clients_lock = threading.Lock()
        self._clients: Dict[bytes, ClientConnection] = {}

    def get_request(
        self, data: bytes
    ) -> Tuple[Command, bytes, Optional[ClientConnection]]:
        with self._clients_lock:
            return self._extract_response(client_uuid, datagram)

    def _extract_response(
        self, client_uuid: bytes, datagram: bytes
    ) -> Tuple[Command, bytes, ClientConnection]:
        if client_uuid != ZERO_UUID:
            client_connection = self._clients.get(client_uuid)
            if client_connection is None:
                return ClientRequest(Request(Command.RESET, Message(bytes(0))), None)
            command, message = client_connection.decrypt(datagram)
        else:
            while True:
                new_uuid = uuid.uuid4().bytes
                if new_uuid not in self._clients:
                    break
            client_connection = self._create_client(new_uuid, datagram)
            message = bytes(0)
            command = Command.CONNECT
        return ClientRequest(Request(command, Message(message)), client_connection)

    def _create_client(self, client_uuid, data) -> ClientConnection:
        new_connection = ClientConnection(client_uuid, data)
        self._clients[client_uuid] = new_connection
        return new_connection

    def match_client(self, message: bytes) -> Optional[ClientConnection]:
        return self._clients.get(message[0:16])


class UserStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._client_nicknames: Dict[str, ClientConnection] = {}

    def get_client(self, nickname: str) -> Optional[ClientConnection]:
        return self._client_nicknames.get(nickname, None)

    def get_user_list(self) -> List[str]:
        return list(self._client_nicknames.keys())

    def register(self, nickname, client: ClientConnection) -> None:
        with self._lock:
            if self._client_nicknames.get(nickname) is not None:
                raise RegistrationError("Nickname already registered.")
            self._client_nicknames[nickname] = client


class EncryptionMessageHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageHandler]")

    def setup(self):
        pass

    def handle(self):
        heading, data = self._extract_data(self.request)
        client_request: ClientRequest = self.server.client_storage.get_message_data(
            data
        )
        self.COMMANDS[client_request.request.command](
            self, client_request.request.message.bytes, client_request.connection
        )

    @classmethod
    def _extract_data(cls, request):
        heading = request.recv(HEADING_LENGTH)
        data_length = int.from_bytes(
            heading, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED,
        )
        data = request.recv(data_length)
        return (heading, data)

    def _connect_command(
        self, message: bytes, client_connection: ClientConnection,
    ) -> None:
        encrypted_message = client_connection.prepare_encrypted_symmetric_key()
        encrypted_response = client_connection.prepare_response(encrypted_message)
        self.request.sendall(encrypted_response)

    def _register_command(
        self, message: bytes, client_connection: ClientConnection,
    ) -> None:
        client_response_address, client_nickname = pickle.loads(message)
        host = self.client_address[0]
        port = client_response_address[1]
        client_connection.client_response_address = (host, port)

        try:
            self.server.user_storage.register(client_nickname, client_connection)
        except RegistrationError:
            encrypted_message = client_connection.encrypt(
                Response.NICKNAME_ALREADY_USED
            )
            prepared_response = client_connection.prepare_response(encrypted_message)
        else:
            encrypted_message = client_connection.encrypt(
                Response.NICKNAME_REGISTRATION_SUCCESS
            )
            prepared_response = client_connection.prepare_response(encrypted_message)

        self.request.sendall(prepared_response)

    def _get_user_list_command(
        self, message: bytes, client_connection: ClientConnection,
    ) -> None:
        user_list = self.server.user_storage.get_user_list()
        encrypted_message = client_connection.encrypt(user_list)
        prepared_response = client_connection.prepare_response(encrypted_message)
        self.request.sendall(prepared_response)

    def _send_message_command(
        self, message: bytes, client_connection: ClientConnection,
    ) -> None:
        pass

    def _reset_command(
        self, message: bytes, client_connection: ClientConnection,
    ) -> None:
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
        super().__init__(server_address, handler_class)
        self.logger = logging.getLogger(f"{__name__}[EncryptionMessageServer]")
        self.client_storage = ClientStorage()
        self.user_storage = UserStorage()
