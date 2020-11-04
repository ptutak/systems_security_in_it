from encrypted_comm.server import EncryptionMessageServer

new_server = EncryptionMessageServer(("127.0.0.1", 7000))
new_server.serve_forever()
