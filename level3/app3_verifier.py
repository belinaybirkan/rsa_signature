import socket
import json
from utils import verify_signature

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('localhost', 7000))
    s.listen(1)
    print("👂 Verifier waiting...")

    conn, _ = s.accept()
    with conn:
        data = conn.recv(8192)
        packet = json.loads(data.decode())
        print(f"Message: {packet['message']}")
        result = verify_signature(packet["public_key"], packet["message"], packet["signature"])
        print("✅ Signature VALID" if result else "❌ Signature INVALID")
