import pickle
import socket
import socketserver
import threading
from typing import List, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import PublicFormat

from .common import Command, Response, Request, Message,  Cryption
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
from .exception import AuthenticationError


class ClientConnection:
    pass


class ClientStorage:
    def __init__(self):
        self._lock = threading.Lock()
        self._storage = {}

    def update_list(self, client_list: List[str]) -> None:
        with self._lock:
            for client in client_list:
                if client not in self._storage:
                    self._storage[client] = None
            for client in self._storage:
                if client not in client_list:
                    del self._storage[client]

    def get_client(self, nickname: str) -> ClientConnection:
        pass


class CommunicationHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server) -> None:
        super().__init__(request, client_address, server)

    def handle(self) -> None:
        if self.request.client_address != self.server.destination_server_address:
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
        self.client_storage = ClientStorage()


class ServerConnection:
    def __init__(self, sym_key):
        pass


class Client:
    def __init__(self, server_address: Tuple[str, int]) -> int:
        self._server_address = server_address
        self._server_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._server_public_key = self._server_private_key.public_key()
        self._communication_server = None
        self._communication_server_thread = None
        self._uuid = ZERO_UUID
        self._secret_uuid = ZERO_UUID
        self._server_cryption: Cryption = IdentCryption()

    def initiate_communication_server(self):
        self._communication_server = CommunicationServer(
            ("localhost", 0),
            handler_class=CommunicationHandler,
            destination_server_address=self._server_address,
        )
        self._communication_server_thread = threading.Thread(
            target=self._communication_server.serve_forever
        )
        self._communication_server_thread.daemon = True
        self._communication_server_thread.start()

    def connect_to_server(self):
        unencrypted_public_key = self._prepare_unencrypted_public_key()
        data_with_secret_uuid = self._encrypt(unencrypted_public_key)
        response = self._send_data_and_get_response(data_with_secret_uuid)
        self_uuid = response[:16]
        decrypted = self._server_private_key.decrypt(
            response[16:],
            KEY_PADDING(
                mgf=KEY_MGF(algorithm=KEY_MGF_ALGORITHM()),
                algorithm=KEY_ALGORITHM(),
                label=None,
            ),
        )
        symmetric_key, symmetric_key_hash = pickle.loads(decrypted[16:])
        if HASHING_ALGORITHM(symmetric_key).hexdigest() != symmetric_key_hash:
            raise AuthenticationError("Error while processing keys")
        self._uuid = self_uuid
        self._secret_uuid = decrypted[:16]
        self._server_cryption = Fernet(symmetric_key)

    def register(self, nickname: str) -> bool:
        if self._communication_server is None:
            self.initiate_communication_server()
        data = (
            Command.REGISTER,
            pickle.dumps((self._communication_server.server_address, nickname)),
        )
        encrypted_data = self._encrypt(data)
        response = self._send_data_and_get_response(encrypted_data)
        decrypted_message = self._extract_message_from_response(response)
        if decrypted_message == Response.NICKNAME_ALREADY_USED:
            return False
        elif decrypted_message == Response.NICKNAME_REGISTRATION_SUCCESS:
            return True
        else:
            raise RuntimeError("Unexpected response")

    def _extract_message_from_response(self, response: bytes) -> object:
        if self._uuid != response[:16]:
            raise AuthenticationError("Bad UUID")
        return self._decrypt(response[16:])

    def get_user_list(self) -> List[str]:
        data = (Command.GET_USER_LIST, b"")
        encrypted_data = self._encrypt(data)
        response = self._send_data_and_get_response(encrypted_data)
        user_list = self._extract_message_from_response(response)
        return user_list

    def _prepare_unencrypted_public_key(self) -> Request:
        stored_public_key = self._server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
        public_key_hash = HASHING_ALGORITHM(stored_public_key).hexdigest()
        data = Request(Command.CONNECT, Message(pickle.dumps((stored_public_key, public_key_hash))))
        data = (Command.CONNECT, pickle.dumps((stored_public_key, public_key_hash)))
        return data

    def _encrypt(self, message: object) -> bytes:
        return self._server_cryption.encrypt(self._secret_uuid + pickle.dumps(message))

    def _decrypt(self, encrypted_message: bytes) -> object:
        decrypted = self._server_cryption.decrypt(encrypted_message)
        if self._secret_uuid != decrypted[:16]:
            raise AuthenticationError("Bad Secret UUID")
        return pickle.loads(decrypted[16:])

    def _send_data_and_get_response(self, encrypted_data: bytes):
        data_with_uuid = self._uuid + encrypted_data
        data_length = len(data_with_uuid)
        heading = data_length.to_bytes(
            length=HEADING_LENGTH, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED
        )
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.connect(self._server_address)
            connection.sendall(heading + data_with_uuid)
            recv_heading = connection.recv(HEADING_LENGTH)
            data_length = int.from_bytes(
                recv_heading, byteorder=HEADING_BYTEORDER, signed=HEADING_SIGNED,
            )
            data = connection.recv(data_length)
            return data
