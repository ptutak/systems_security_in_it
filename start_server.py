from encrypted_comm.server import EncryptionMessageServer

EncryptionMessageServer.allow_reuse_address = True

address = ("127.0.0.1", 7000)

with EncryptionMessageServer(address) as server:
    print(f"Starting server at {address} ...")
    server.serve_forever()
