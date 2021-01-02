import logging
import pickle
import socket
import socketserver
import threading
from typing import List, Optional, Tuple

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
        self._storage = {}

    def update_list(self, client_list: List[str]) -> None:
        with self._lock:
            for client in client_list:
                if client not in self._storage:
                    self._storage[client] = ClientConnection()
            for client in self._storage:
                if client not in client_list:
                    del self._storage[client]

    def new_user(self, nickname: str, rsa_cryption: RSACryption) -> ClientConnection:
        with self._lock:
            if nickname not in self._storage:
                self._storage[nickname] = ClientConnection(rsa_cryption)
                return self._storage[nickname]
            else:
                raise RuntimeError("Nickname already registered")

    def get_client(self, nickname: str) -> Optional[ClientConnection]:
        with self._lock:
            if nickname not in self._storage:
                return None
            return self._storage[nickname]


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

    def new_connection(self, nickname: str, cryption: RSACryption) -> None:
        self.client_storage.new_user(nickname, cryption)


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

    def send_message(self, nickname: str, message: str) -> bool:
        request = Request(Command.MESSAGE, Message.from_data(Request()))
