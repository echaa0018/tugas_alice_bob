import socket
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

bob_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
bob_public_key = bob_private_key.public_key()

with open("bob_public.pem", "wb") as f:
    f.write(bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

def start_bob():
    host = '0.0.0.0' # LAN
    port = 65420

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Bob mendengarkan di Port {port}...\n")
        
        while True:
            conn, addr = s.accept()
            with conn:
                data = conn.recv(8192)
                if not data:
                    continue

                payload = json.loads(data.decode('utf-8'))
                
                # [LANGKAH 8]
                print(f"[Langkah 8] Bob menerima payload dari IP: {addr[0]}")
                print(f"            -> Menerima {len(payload)} komponen data enkripsi.")

                ciphertext = base64.b64decode(payload['ciphertext'])
                encrypted_key = base64.b64decode(payload['encrypted_key'])
                received_hash = base64.b64decode(payload['hash'])
                signature = base64.b64decode(payload['signature'])
                iv = base64.b64decode(payload['iv'])

                try:
                    with open("alice_public.pem", "rb") as key_file:
                        alice_public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
                except FileNotFoundError:
                    print("alice public key not found")
                    continue

                # [LANGKAH 9]
                print(f"[Langkah 9] Bob mendekripsi symmetric key menggunakan private key Bob.")
                aes_key = bob_private_key.decrypt(
                    encrypted_key,
                    rsa_padding.OAEP(mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                print(f"            -> Kunci AES berhasil dibuka: {aes_key.hex()}")

                # [LANGKAH 10]
                print(f"[Langkah 10] Bob mendekripsi ciphertext menggunakan symmetric key tersebut.")
                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                unpadder = sym_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
                pesan_asli = plaintext.decode('utf-8')
                print(f"             -> Plaintext berhasil didapatkan: '{pesan_asli}'")

                # [LANGKAH 11]
                print(f"[Langkah 11] Bob memverifikasi hash.")
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(plaintext)
                hash_local = digest.finalize()
                hash_valid = (hash_local == received_hash)
                print(f"             -> Hash Asli  : {base64.b64encode(received_hash).decode('utf-8')}")
                print(f"             -> Hash Lokal : {base64.b64encode(hash_local).decode('utf-8')}")
                print(f"             -> Status Cocok? {'yes' if hash_valid else 'no'}")

                # [LANGKAH 12]
                print(f"[Langkah 12] Bob memverifikasi digital signature menggunakan public key Alice.")
                sig_valid = False
                try:
                    alice_public_key.verify(
                        signature, received_hash,
                        rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()), salt_length=rsa_padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    sig_valid = True
                except Exception:
                    pass
                print(f"             -> Signature Valid? {'yes' if sig_valid else 'no'}")

                # [LANGKAH 13]
                print(f"[Langkah 13] Bob menyimpulkan validitas dan keaslian pesan.")
                print(f"\nKESIMPULAN:")
                if hash_valid and sig_valid:
                    print("=> Pesan benar-benar dikirim oleh Alice")
                    print(f"=> isi pesan: {pesan_asli}")
                else:
                    print("=> Pesanan dimanipulasi")

if __name__ == "__main__":
    start_bob()