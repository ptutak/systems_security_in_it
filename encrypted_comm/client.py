from abc import ABC, abstractmethod
import logging
import pickle
import socketserver
import threading
from typing import Dict, List, Optional, Tuple

from cryptography.fernet import Fernet

from .common import (
    AsymmetricDecryption,
    ChatMessage,
    Command,
    ConnectionHandler,
    Cryption,
    EncryptingConnectionHandler,
    FernetCryption,
    IdemCryption,
    Message,
    Request,
    Response,
    RSACryption,
)
from .constants import HASHING_ALGORITHM
from .exception import AuthenticationError

LOGGER = logging.getLogger(__name__)


class Observer(ABC):
    @abstractmethod
    def update(self, message: str) -> None:
        """
        Update observer with a state message
        """


class ClientConnection:
    def __init__(self, sym_key: bytes):
        self._cryption = Fernet(sym_key)
        self._lock = threading.Lock()
        self._observers: List[Observer] = list()

    def encrypt(self, data: object) -> bytes:
        return self._cryption.encrypt(pickle.dumps(data))

    def decrypt(self, message: bytes) -> object:
        return pickle.loads(self._cryption.decrypt(message))

    def attach(self, observer: Observer) -> None:
        with self._lock:
            self._observers.append(observer)

    def detach(self, observer: Observer) -> None:
        with self._lock:
            try:
                self._observers.remove(observer)
            except ValueError:
                return

    def notify(self, message: str) -> None:
        with self._lock:
            for observer in self._observers:
                observer.update(message)


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

    def new_connection(self, nickname: str, sym_key: bytes) -> ClientConnection:
        connection = ClientConnection(sym_key)
        self.register(nickname, connection)
        return connection

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


class CommunicationHandler(socketserver.BaseRequestHandler, ConnectionHandler):

    IDEM_CRYPTION = IdemCryption()

    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    @property
    def cryption(self) -> Cryption:
        return self.server.server_cryption

    def receive_request(self, request) -> Request:
        data_length, data = self.receive_data(request)
        return self.decrypt(data)

    def decrypt(self, data: bytes) -> Request:
        return self.cryption.decrypt_and_get_request(data)

    def error_response(self, error_message: str) -> bytes:
        request = Request(Response.ERROR, Message(error_message))
        return self.encrypt(request)

    def encrypt(self, request: Request) -> bytes:
        return self.cryption.prepare_request_and_encrypt(request)

    def handle(self) -> None:
        if self.request.client_address != self.server.destination_server_address:
            LOGGER.warning("Bad client address")
            return
        request = self.receive_request(self.request)
        command = request.command_or_response
        if command not in self.COMMANDS:
            wrong_command = Request(Response.WRONG_COMMAND, Message.zero_message())
            self.request.sendall(self.encrypt(wrong_command))
            return
        self.COMMANDS[command](request)

    def _connect_to_user(self, request: Request) -> None:
        pass

    def _message(self, request: Request) -> None:
        pass

    COMMANDS = {
        Command.CONNECT_TO_USER: _connect_to_user,
        Command.MESSAGE: _message,
    }


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
        self.client_connections = ClientConnections()
        self.server_cryption = IdemCryption()


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

        encrypted_response = self.send_data_and_receive_response(
            prepared_datagram, self._server_address
        )

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
        self._communication_server.server_cryption = self._server_cryption

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

    def connect_to_user(self, nickname: str, observer: Observer) -> bool:
        rsa_cryption = RSACryption()
        serialized_key = rsa_cryption.public_key_serialized
        data = (serialized_key, HASHING_ALGORITHM(serialized_key).hexdigest())
        bytes_data = pickle.dumps(data)
        request = Request(
            Command.CONNECT_TO_USER, ChatMessage(None, nickname, bytes_data)
        )
        response = self.send_request(request)
        if response.command_or_response != Response.CONNECTION_SUCCESS:
            raise RuntimeError("Connection failed")
        message = ChatMessage.from_message(response.message)

        symmetric_key, symmetric_key_hash = message.message
        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise RuntimeError("Symmetric key hash error.")

        new_connection = self._communication_server.client_connections.new_connection(
            nickname, symmetric_key
        )
        new_connection.attach(observer)

    def send_message(self, nickname: str, message: str) -> bool:
        request = Request(Command.MESSAGE, Message.from_data(Request()))
