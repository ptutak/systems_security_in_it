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
[User Secret UUID, Pickled: (Symmetric Key, SymmetricKeyHash)]



Regular communication:
Data:
[Length Heading][User UUID, Server-Encryption Payload]

Server-Encryption Payload:
[User Secret UUID, Pickled: (Command, Client-Encryption Data / Server-Communication Data)]

```
