# II3230 Latihan: End-to-End Secure Message Delivery

Program ini dibuat oleh:
| NIM| Nama|
| -----: | :--- |
|18223068      |Muhammad Arya Putra Prihastono|
|18223082      |Mahesa Satria Prayata|

## Requirements

Pastikan Python 3 sudah terinstall di sistem. Kemudian install library eksternal cryptography dengan perintah berikut:

```bash
pip install cryptography
```

## Cara Menjalankan Program

Simulasi ini dilakukan dengan dua perangkat berbeda dalam satu jaringan WiFi yang sama (LAN).

1. Di device Bob, run 'ipconfig' di terminal dan copy paste IPv4 Adrress (192.168.xx.x), kirim IP tersebut ke device Alice
2. Run file bob.py dan alice.py di masing-masing deivce
3. Kirim file bob_public.pem ke device Alice, dan kirim alice_pubic.pem ke device Bob (Pastikan mereka berada di folder yang sama dengan .py masing-maisng)
4. Di device Alice dapat menginput IPv4 Address Bob, kemudian Alice dapat mengirim pesan ke Bob
5. Bob dapat membaca pesan Alice