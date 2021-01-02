import logging
import pickle
import socket
import socketserver
import threading
from typing import Dict, List, Optional, Tuple

from .common import (
    AsymmetricDecryption, ChatMessage,
    Command,
    Cryption, EncryptingConnectionHandler,
    FernetCryption,
    IdemCryption,
    Message,
    RSACryption,
    Request,
    Response,
)

from .constants import HASHING_ALGORITHM
from .exception import AuthenticationError

LOGGER = logging.getLogger(__name__)


class ClientConnection:
    def __init__(self, rsa_cryption: RSACryption):
        self._rsa_cryption = rsa_cryption


class ClientConnections:
    def __init__(self):
        self._lock = threading.Lock()
        self._nickname_connections: Dict[str, ClientConnection] = {}
        self._connection_nicknames: Dict[ClientConnection, str] = {}

    def get_connection(self, nickname: str) -> Optional[ClientConnection]:
        return self._nickname_connections.get(nickname, None)

    def get_nickname(self, connection: ClientConnection) -> Optional[str]:
        return self._connection_nicknames.get(connection, None)

    def get_user_list(self) -> List[str]:
        return list(self._nickname_connections.keys())

    def register(self, nickname: str, client_connection: ClientConnection) -> None:
        with self._lock:
            if self._connection_nicknames.get(client_connection) is not None:
                raise RuntimeError("Connection already registered.")
            if self._nickname_connections.get(nickname) is not None:
                raise RuntimeError("Nickname already registered.")

            self._connection_nicknames[client_connection] = nickname
            self._nickname_connections[nickname] = client_connection

    def deregister_connection(self, client_connection: ClientConnection) -> None:
        with self._lock:
            if client_connection in self._connection_nicknames:
                nickname = self._connection_nicknames[client_connection]
                del self._connection_nicknames[client_connection]
                del self._nickname_connections[nickname]

    def deregister_nickname(self, nickname: str) -> None:
        with self._lock:
            if nickname in self._nickname_connections:
                connection = self._nickname_connections[nickname]
                del self._nickname_connections[nickname]
                del self._connection_nicknames[connection]


class CommunicationHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    def handle(self) -> None:
        if self.request.client_address != self.server.destination_server_address:
            LOGGER.warning("Bad client address")
            return


class CommunicationServer(socketserver.ThreadingTCPServer):
    def __init__(
        self,
        server_address,
        *,
        destination_server_address,
        handler_class=CommunicationHandler,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.destination_server_address = destination_server_address
        self.client_storage = ClientConnections()


class Client(EncryptingConnectionHandler):
    ZERO_CRYPTION = IdemCryption()

    def __init__(self, server_address: Tuple[str, int]) -> int:
        self._server_address = server_address
        self._server_rsa_cryption = RSACryption()
        self._private_key_decryption: AsymmetricDecryption = AsymmetricDecryption(
            self._server_rsa_cryption
        )
        self._communication_server: Optional[CommunicationServer] = None
        self._communication_server_thread = None
        self._server_cryption: Cryption = IdemCryption()

    @property
    def communication_address(self) -> Tuple[str, int]:
        return self._server_address

    @property
    def cryption(self) -> Cryption:
        return self._server_cryption

    def initiate_communication_server(self):
        self._communication_server = CommunicationServer(
            ("localhost", 0),
            destination_server_address=self._server_address,
            handler_class=CommunicationHandler,
        )
        self._communication_server_thread = threading.Thread(
            target=self._communication_server.serve_forever
        )
        self._communication_server_thread.daemon = True
        self._communication_server_thread.start()

    def connect_to_server(self):
        unencrypted_public_key_request = self._prepare_unencrypted_public_key_request()

        prepared_datagram = self.ZERO_CRYPTION.prepare_request_and_encrypt(
            unencrypted_public_key_request
        )

        encrypted_response = self.send_data_and_receive_response(prepared_datagram, self._server_address)

        request = self._private_key_decryption.decrypt_and_get_request(
            encrypted_response
        )

        if request.command_or_response != Response.CONNECTION_SUCCESS:
            raise RuntimeError("Connection failed")

        uuid = self._private_key_decryption.uuid
        secret_uuid = self._private_key_decryption.secret_uuid
        symmetric_key, symmetric_key_hash = request.message.data

        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise AuthenticationError("Error while processing keys")

        self._server_cryption = FernetCryption(uuid, secret_uuid, symmetric_key)

    def _prepare_unencrypted_public_key_request(self) -> Request:
        serialized_public_key = self._server_rsa_cryption.public_key_serialized
        public_key_hash = HASHING_ALGORITHM(serialized_public_key).hexdigest()
        request = Request(
            Command.CONNECT, Message.from_data((serialized_public_key, public_key_hash))
        )
        return request

    def register(self, nickname: str) -> bool:
        if self._communication_server is None:
            self.initiate_communication_server()
        request = Request(
            Command.REGISTER,
            Message.from_data((self._communication_server.server_address, nickname)),
        )
        response = self.send_request(request)
        if response.command_or_response == Response.NICKNAME_ALREADY_USED:
            return False
        elif response.command_or_response == Response.NICKNAME_REGISTRATION_SUCCESS:
            return True
        raise RuntimeError("Unexpected response")

    def get_user_list(self) -> List[str]:
        request = Request(Command.GET_USER_LIST, Message.zero_message())
        response = self.send_request(request)
        if response.command_or_response != Response.USER_LIST:
            raise RuntimeError("Unexpected response")
        user_list = response.message.data
        return user_list

    def connect_to_user(self, nickname: str) -> bool:
        rsa_cryption = RSACryption()
        serialized_key = rsa_cryption.public_key_serialized
        data = (serialized_key, HASHING_ALGORITHM(serialized_key).hexdigest())
        bytes_data = pickle.dumps(data)
        request = Request(Command.CONNECT_TO_USER, ChatMessage(None, nickname, bytes_data))
        response = self.send_request(request)
        if response.command_or_response != Response.CONNECTION_SUCCESS:
            raise RuntimeError("Connection failed")
        message = ChatMessage.from_message(response.message)

        symmetric_key, symmetric_key_hash = message.message
        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise RuntimeError("Symmetric key hash error.")

        self._communication_server.client_storage.new_user(nickname, symmetric_key)

    def send_message(self, nickname: str, message: str) -> bool:
        request = Request(Command.MESSAGE, Message.from_data(Request()))
