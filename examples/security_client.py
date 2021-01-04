import hashlib
import pickle
import socket

from cryptography.fernet import Fernet

import rsa
from errorclass import AuthenticationError


class Client:
    def __init__(self):
        # Generate an asymmetric key
        self.asyKey = rsa.newkeys(2048)
        # public key and private key
        self.publicKey = self.asyKey[0]
        self.privateKey = self.asyKey[1]

    def link_server(self, addr=("localhost", 8080)):
        # Create a socket communication object
        # By default, the AF_INET protocol family is used, that is, the combination of ipv4 address
        #  and port number and tcp protocol.
        clientSocket = socket.socket()
        # Default connection server address is native ip and port 8080
        clientSocket.connect(addr)

        # Pass the public key to the server, and the sha256 value after the public key is stringified
        print("Transferring public key to server")
        sendKey = pickle.dumps(self.publicKey)
        sendKeySha256 = hashlib.sha256(sendKey).hexdigest()
        clientSocket.send(pickle.dumps((sendKey, sendKeySha256)))

        # Accept the key passed by the server and decrypt it
        symKey, symKeySha256 = pickle.loads(clientSocket.recv(1024))
        if hashlib.sha256(symKey).hexdigest() != symKeySha256:
            raise AuthenticationError("The key has been tampered!")
        else:
            self.symKey = pickle.loads(rsa.decrypt(symKey, self.privateKey))
            print("Key exchange completed")

        # Initialize the encrypted object
        f = Fernet(self.symKey)

        while True:

            sendData = input("Enter the message you want to send:")
            en_sendData = f.encrypt(sendData.encode())
            clientSocket.send(en_sendData)

            en_recvData = clientSocket.recv(1024)
            recvData = f.decrypt(en_recvData).decode()
            print("Received messages from the server: {0}".format(recvData))
