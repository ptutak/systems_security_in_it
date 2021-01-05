from encrypted_comm.server import EncryptionMessageServer

ADDRESS = ("127.0.0.1", 7000)

EncryptionMessageServer.allow_reuse_address = True

print(f"Starting server at {ADDRESS} ...")
with EncryptionMessageServer(ADDRESS) as server:
    server.serve_forever()
