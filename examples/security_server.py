import hashlib
import pickle
import socket
import time
from exceptions import AuthenticationError

from cryptography.fernet import Fernet

import rsa


class Server:

    # Used to mark the number of clients connected at the same time
    number = 0

    # The default maximum number of waiting is 5
    # Default to use the machine's ip address and port 8080
    def __init__(self, backlog=5, addr=("localhost", 8080)):
        # By default, the AF_INET protocol family is used, that is, the combination of
        # ipv4 address and port number and tcp protocol.
        self.serverSocket = socket.socket()
        # Bind the listening IP address and port number
        self.serverSocket.bind(addr)
        #
        self.serverSocket.listen(backlog)

    # This function needs to be processed in parallel
    def link_one_client(self):
        # Get client object and client address
        clientSocket, addr = self.serverSocket.accept()

        # Client number plus 1
        Server.number = Server.number + 1
        # flag the current client number
        now_number = Server.number

        #
        print(
            "Connection to client {0}\n destination host address: {1}".format(
                now_number, addr
            )
        )
        # Accept the public key passed by the client
        # Here you can add a hash function to verify the correctness of the public key!
        # Using pickle for deserialization
        publicKeyPK, pubKeySha256 = pickle.loads(clientSocket.recv(1024))
        if hashlib.sha256(publicKeyPK).hexdigest() != pubKeySha256:
            raise AuthenticationError("The key has been tampered!")
        else:
            publicKey = pickle.loads(publicKeyPK)
            print("Accepted public key")

        # The following is the process of encrypting and passing a symmetric key with a public key.
        # Generate a key for symmetric encryption
        sym_key = Fernet.generate_key()
        # serialize with pickle for network transmission
        # Hash the key to ensure its accuracy
        en_sym_key = rsa.encrypt(pickle.dumps(sym_key), publicKey)
        en_sym_key_sha256 = hashlib.sha256(en_sym_key).hexdigest()
        print("Encrypting Transfer Key")
        clientSocket.send(pickle.dumps((en_sym_key, en_sym_key_sha256)))

        # Here you can add a key exchange successful function

        # Initialize the encrypted object
        f = Fernet(sym_key)

        # The following process of using a symmetric key for encrypted conversations
        while True:
            time.sleep(0.3)
            # Received encrypted message
            en_recvData = clientSocket.recv(1024)
            recvData = f.decrypt(en_recvData).decode()
            print("Received message from client {0}: {1}".format(now_number, recvData))

            # Call Turing Robot
            sendData = "Reply OK"
            # Encrypt the message
            en_sendData = f.encrypt(sendData.encode())
            clientSocket.send(en_sendData)
