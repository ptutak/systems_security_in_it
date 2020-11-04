from encrypted_comm.server import EncryptionMessageServer

EncryptionMessageServer.allow_reuse_address = True

with EncryptionMessageServer(("127.0.0.1", 7000)) as server:
    print("Starting server...")
    server.serve_forever()
