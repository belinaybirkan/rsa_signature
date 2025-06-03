from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

def generate_keys():
    key = RSA.generate(2048)
    return key, key.publickey()

def sign_message(private_key, message):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

def verify_signature(public_key_str, message, signature_b64):
    try:
        public_key = RSA.import_key(public_key_str.encode())
        h = SHA256.new(message.encode())
        signature = base64.b64decode(signature_b64.encode())
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
