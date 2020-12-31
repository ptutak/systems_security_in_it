## systems_security_in_it


Message payload:

```
Connect communication:
Data:
[Length Heading][Zero UUID, Non Encrypted Payload]

Non Encrypted Payload:
[Zero UUID, Pickled: (CONNECT Command, (Public Key, Public Key Hash))]


Connect Response:
[Length Heading][User UUID, Server-Encryption Response Message]

Server-Encryption Response Message:
[User Secret UUID, Pickled: (Response.CONNECTION_SUCCESS, Pickled: (Symmetric Key, SymmetricKeyHash))]



Regular communication:

Client to Server Data:
[Length Heading][User UUID, Server-Encryption Payload]

Server-Encryption Payload:
[User Secret UUID, Pickled: (Command, Client-Communication Data / Server-Communication Data)]

Client-Communication Data:
Pickled: (Destination Nickname, Client-Encrypted Data)


Server to Client Data:
[Length Heading][User UUID, Client-Encryption Payload]

Client-Encryption Payload
[User Secret UUID, Pickled: (Command.MESSAGE, Client-Communication Data)]

Client-Communication Data:
Pickled: (Source Nickname, Client-Encrypted Data)


```
