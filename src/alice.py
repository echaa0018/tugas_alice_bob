import socket
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


alice_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
alice_public_key = alice_private_key.public_key()

with open("alice_public.pem", "wb") as f:
    f.write(alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

def send_message():
    print("\n--- Konfigurasi Jaringan ---")
    target_host = input("Masukkan IP LAN Bob (contoh: 192.168.1.10): ").strip()
    target_port = 65420

    try:
        with open("bob_public.pem", "rb") as key_file:
            bob_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    except FileNotFoundError:
        print("[!] Kunci publik Bob (bob_public.pem) tidak ditemukan")
        return

    while True:
        pesan = input("\n[Alice] Masukkan pesan (ketik 'exit' untuk keluar): ")
        if pesan.lower() == 'exit':
            break


        # [LANGKAH 1]
        print(f"[Langkah 1] Alice bikin plaintext.")
        print(f"            -> Pesan: '{pesan}'")
        plaintext_bytes = pesan.encode('utf-8')
        
        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()

        # [LANGKAH 2]
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        print(f"[Langkah 2] Alice membuat symmetric key (AES-256).")
        print(f"            -> AES Key (Hex): {aes_key.hex()}")

        # [LANGKAH 3]
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        print(f"[Langkah 3] Alice mengenkripsi plaintext dengan symmetric encryption.")
        print(f"            -> Ciphertext (Base64): {base64.b64encode(ciphertext).decode('utf-8')[:40]}... (dipotong)")

        # [LANGKAH 4]
        encrypted_key = bob_public_key.encrypt(
            aes_key,
            rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        print(f"[Langkah 4] Alice mengenkripsi symmetric key dengan public key Bob.")
        print(f"            -> Encrypted Key (Base64): {base64.b64encode(encrypted_key).decode('utf-8')[:40]}... (dipotong)")

        # [LANGKAH 5]
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(plaintext_bytes)
        hash_plaintext = digest.finalize()
        print(f"[Langkah 5] Alice membuat hash dari plaintext.")
        print(f"            -> Hash SHA-256: {base64.b64encode(hash_plaintext).decode('utf-8')}")

        # [LANGKAH 6]
        signature = alice_private_key.sign(
            hash_plaintext,
            rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print(f"[Langkah 6] Alice membuat digital signature dengan private key miliknya dari.")
        print(f"            -> Signature (Base64): {base64.b64encode(signature).decode('utf-8')[:40]}... (dipotong)")

        payload = {
            "source_ip": "IP_Alice",
            "destination_ip": target_host,
            "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
            "encrypted_key": base64.b64encode(encrypted_key).decode('utf-8'),
            "iv": base64.b64encode(iv).decode('utf-8'),
            "hash": base64.b64encode(hash_plaintext).decode('utf-8'),
            "signature": base64.b64encode(signature).decode('utf-8')
        }

        # [LANGKAH 7]
        print(f"[Langkah 7] Alice mengirim payload ke Bob melalui komunikasi IP...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((target_host, target_port))
                s.sendall(json.dumps(payload).encode('utf-8'))
                print("            [+] Payload berhasil meluncur ke jaringan!")
        except Exception as e:
            print(f"            [!] Gagal terhubung ke Laptop Bob: {e}")
        

if __name__ == "__main__":
    send_message()