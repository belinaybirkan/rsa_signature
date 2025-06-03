import socket
import json
from utils import verify_signature

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('localhost', 5000))
    s.listen(1)
    print("🔎 Waiting...")

    conn, addr = s.accept()
    with conn:
        data = conn.recv(8192)
        payload = json.loads(data.decode())
        valid = verify_signature(payload["public_key"], payload["message"], payload["signature"])

        print(f"Message: {payload['message']}")
        print("✅ Valid Signature" if valid else "❌ Invalid Signature")
