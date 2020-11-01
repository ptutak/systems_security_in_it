import hashlib
import pickle
from time import time

start = time()

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

private_key = rsa.generate_private_key(65537, key_size=2048, backend=default_backend())
publicKey = private_key.public_key()

print(type(publicKey))

encrypted = publicKey.encrypt(
    b"encrypt me",
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)

sendKey = publicKey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

print(sendKey)
print(len(sendKey))

sendKeySha256 = hashlib.sha256(sendKey).hexdigest()
print(sendKeySha256)
print(len(sendKeySha256))
payload = pickle.dumps((sendKey, sendKeySha256))
print(payload)
print(len(payload))

symKey = Fernet.generate_key()
print(type(symKey))

cryption = Fernet(symKey)
print(type(cryption))

encrypted = cryption.encrypt(b"encryspt sssme")
x = (13453433423).to_bytes(length=8, byteorder="big", signed=False)
print(len(x))
y = int.from_bytes(x, byteorder="big", signed=False)
print(x)
print(y)
print(encrypted)
print(len(encrypted))

double_encrypted = cryption.encrypt(encrypted)
print(double_encrypted)
print(len(double_encrypted))

print(time() - start)
