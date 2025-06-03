import tkinter as tk
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# Anahtar oluştur
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

def sign_message():
    message = entry_message.get("1.0", tk.END).strip()
    if not message:
        messagebox.showerror("Hata", "Mesaj boş olamaz.")
        return
    hash_obj = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    entry_signature.delete("1.0", tk.END)
    entry_signature.insert(tk.END, base64.b64encode(signature).decode())

def verify_signature():
    message = entry_verify_message.get("1.0", tk.END).strip()
    signature_str = entry_signature.get("1.0", tk.END).strip()
    try:
        signature = base64.b64decode(signature_str.encode())
        hash_obj = SHA256.new(message.encode())
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        label_result.config(text="✅ İmza GEÇERLİ", fg="green")
    except (ValueError, TypeError):
        label_result.config(text="❌ İmza GEÇERSİZ", fg="red")

root = tk.Tk()
root.title("Level 1 - RSA Dijital İmza")
root.geometry("600x600")

tk.Label(root, text="1. İmzalanacak Mesaj:").pack()
entry_message = tk.Text(root, height=4, width=70)
entry_message.pack()
tk.Button(root, text="İmza Oluştur", command=sign_message).pack()

tk.Label(root, text="2. İmza (Değiştirilebilir):").pack()
entry_signature = tk.Text(root, height=5, width=70)
entry_signature.pack()

tk.Label(root, text="3. Doğrulama için Mesaj:").pack()
entry_verify_message = tk.Text(root, height=4, width=70)
entry_verify_message.pack()
tk.Button(root, text="İmzayı Doğrula", command=verify_signature).pack()

label_result = tk.Label(root, text="", font=('Arial', 14))
label_result.pack(pady=10)

root.mainloop()