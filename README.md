# RSA Digital Signature Project (Levels 1–2–3)

This project demonstrates the RSA digital signature scheme implemented in Python, across 3 difficulty levels.

## What Is a Digital Signature?

A digital signature ensures the integrity and authenticity of a message:
- A message is hashed using SHA-256
- The hash is signed using the **private key**
- The receiver verifies the signature using the **public key**

---

## Project Structure

```
rsa_signature_project/
├── level1_gui_app.py
├── level2/
│   ├── utils.py
│   ├── app1_sign_send.py
│   ├── app2_receive_verify.py
├── level3/
│   ├── utils.py
│   ├── app1_signer.py
│   ├── app2_proxy_tamper.py
│   ├── app3_verifier.py
```

---

## Level 1 – Single Application (GUI)

### Features:
- Enter a message
- Generate a digital signature using RSA
- Manually modify the signature to simulate tampering
- Verify the signature

### Run:
```bash
python level1_gui_app.py
```

---

## Level 2 – Two Applications (Sockets)

- **app1_sign_send.py**: Signs the message and sends it
- **app2_receive_verify.py**: Receives the message and verifies the signature

### In Terminal 1:
```bash
python app2_receive_verify.py
```

### In Terminal 2:
```bash
python app1_sign_send.py
```

---

## Level 3 – Three Applications (Tampering Proxy)

- **app1_signer.py**: Signs the message
- **app2_proxy_tamper.py**: Allows tampering with the signature before forwarding
- **app3_verifier.py**: Receives the data and verifies the signature

### In Terminal 1:
```bash
python app3_verifier.py
```

### In Terminal 2:
```bash
python app2_proxy_tamper.py
```

### In Terminal 3:
```bash
python app1_signer.py
```

---

## Presentation Key Points

- **Hashing (SHA-256)**: Creates a fixed-size digest of the message
- **Signing**: The digest is encrypted using the private key
- **Verification**: The digest is decrypted using the public key and compared
- **Security**: Any change to the message or signature causes verification to fail

---

## Required Installation

```bash
pip install pycryptodome
```

---

## Prepared By
Belinay Birkan – Practical Work 4: RSA Digital Signature
