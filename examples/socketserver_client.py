import socket
import sys
from time import sleep
import threading

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
    if received == data.upper():
        print(".", end="")


for i in range(100000):
    # Create a socket (SOCK_STREAM means a TCP socket)
    threads.append(threading.Thread(target=call))

for thread in threads:
    thread.start()

for thread in threads:
    thread.join()
