from .encrypted_comm.client import Client

new_client = Client(("127.0.0.1", 7000))

new_client.connect_to_server()
result = new_client.register("New Nickname")

assert result

user_list = new_client.get_user_list()

print(user_list)
