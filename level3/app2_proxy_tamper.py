import socket
import json

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('localhost', 6000))
    s.listen(1)
    print("📦 Waiting for signer...")
    conn, _ = s.accept()
    with conn:
        data = conn.recv(8192)
        packet = json.loads(data.decode())

print(f"Original Signature:
{packet['signature'][:60]}...")
choice = input("Tamper signature? (y/n): ")
if choice.lower() == 'y':
    packet['signature'] = packet['signature'][::-1]

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('localhost', 7000))
    s.sendall(json.dumps(packet).encode())
    print("🔁 Forwarded to Verifier")
