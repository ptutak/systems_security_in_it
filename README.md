## systems_security_in_it


Message payload:

```
Connect communication:
Data:
[Zero UUID, Pickled: (CONNECT Command, (Public Key, Public Key Hash))]


Normal communication:
Data:
[User UUID, Encrypted Payload]

Encrypted Payload:
[User Secret UUID, Pickled: (Command, Encrypted Data)]

```
