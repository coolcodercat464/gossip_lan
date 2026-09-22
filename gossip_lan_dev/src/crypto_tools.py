from Cryptodome.Cipher import AES

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

# sign challenge
def sign(message, self_authentication_private_key):
    return self_authentication_private_key.sign(message)

# verify a signature
def verify(public_key, signature, message):
    # parse it
    if type(public_key) == str:
        public_key = serialization.load_ssh_public_key(public_key.strip().encode("utf-8"))

    # verify signature
    try:
        public_key.verify(signature, message)
        return True
    except:
        return False

# aes gcm encryption class (copied from stack overflow lol)
class GCM:
    def __init__(self, secretKey):
        self.secretKey = secretKey

    def encrypt(self, msg):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None)
        aesKey = hkdf.derive(self.secretKey)
                       
        cipher = AES.new(aesKey, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
        return cipher.nonce + ciphertext + tag

    def decrypt(self, msg):
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None)
        aesKey = hkdf.derive(self.secretKey)
                       
        nonce = msg[:16]
        tag = msg[-16:]
        msg = msg[16:-16]

        cipher = AES.new(aesKey, AES.MODE_GCM, nonce=nonce)
        try:
            return cipher.decrypt_and_verify(msg, tag).decode()
        except ValueError:
            print("Decryption failed: Key incorrect or message tampered with")
            return False
