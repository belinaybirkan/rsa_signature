import socket
import json
from utils import generate_keys, sign_message

private_key, public_key = generate_keys()
message = input("Enter message: ")
signature = sign_message(private_key, message)

packet = {
    "message": message,
    "signature": signature,
    "public_key": public_key.export_key().decode()
}

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('localhost', 5000))
    s.sendall(json.dumps(packet).encode())
    print("✅ Sent to Verifier.")
