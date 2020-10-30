import threading

from server import Server

print("Welcome to the server program!")

server = Server()
while True:
    # Use multithreading here to avoid server blocking on a client
    t = threading.Thread(target=server.link_one_client)
    t.start()
