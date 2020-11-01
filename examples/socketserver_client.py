import socket
import sys
import threading
from time import sleep

HOST, PORT = "localhost", 9999
data = " ".join(sys.argv[1:])
threads = []


def call():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Connect to server and send data
        sock.connect((HOST, PORT))
        sock.sendall(bytes(data + "\n", "utf-8"))
        sleep(1)
        # Receive data from the server and shut down
        received = str(sock.recv(1024), "utf-8")
        print(received)

        sock.sendall(bytes(data + "\n", "utf-8"))
        sleep(1)
        # Receive data from the server and shut down
        received = str(sock.recv(1024), "utf-8")
        print(received)

call()
