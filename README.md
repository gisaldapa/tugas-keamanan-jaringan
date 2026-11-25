# Simulasi Keamanan Transmisi & Penyimpanan Data Lokal (AES-256-GCM + Packet Sniffing)

Proyek laboratorium keamanan jaringan ini mendemonstrasikan perbedaan antara **keamanan penyimpanan lokal (*Data at Rest*)** dan **keamanan transmisi jaringan (*Data in Transit*)** menggunakan aplikasi web lokal (`127.0.0.1:8000`), enkripsi simetris **AES-256-GCM**, database **SQLite**, serta perekaman lalu lintas jaringan (*packet sniffing*) ke format `.pcap` yang kompatibel dengan Wireshark.

---

## 1. Arsitektur & Skema Jaringan Lokal

### Diagram Skema Jaringan (ASCII)

```text
+-----------------------------------+
|      CLIENT (Browser / Script)    |
|  - Input: Nama & Pesan Rahasia    |
|  - Menerima hasil dekripsi JSON   |
+-----------------+-----------------+
                  |
                  |  [1] HTTP/1.1 Polos (Plaintext JSON)
                  |      POST /api/secrets  &  GET /api/secrets
                  |      Interface: Loopback (lo / \Device\NPF_Loopback)
                  v
    +-------------+-------------+         +----------------------------------+
    |   PACKET SNIFFER (Probe)  |<------->|  Menangkap semua paket TCP:8000  |
    |  scapy / tcpdump / tshark |  Tap    |  Output: bukti_sniffing.pcap     |
    +---------------------------+         +----------------------------------+
                  |
                  v
+-----------------+-----------------+     +----------------------------------+
|     LOCAL WEB SERVER (Backend)    |     |        SECRET KEY (.env)         |
|  Flask @ http://127.0.0.1:8000    |<----|  AES_SECRET_KEY (256-bit Base64) |
|  - crypto_utils.py (AES-256-GCM)  |     |  Terpisah dari kode & database   |
+-----------------+-----------------+     +----------------------------------+
                  |
                  |  [2] Simpan Ciphertext (Nonce 96-bit + Ciphertext + Tag)
                  |  [3] Ambil Ciphertext untuk Dekripsi
                  v
+-----------------+-----------------+
|   LOCAL STORAGE (SQLite Vault)    |
|  File: data/vault.db              |
|  Tabel: secrets                   |
|  Isi: HANYA ciphertext & nonce    |
+-----------------------------------+
```

### Alur Perpindahan Data (*Data Lifecycle*)

1. **Plaintext (Sisi Client -> Jaringan):**
   Pengguna atau skrip simulasi mengirimkan JSON berisi data sensitif (misalnya `{"name": "Agen_Garuda_01", "secret_message": "RAHASIA_NEGARA_123"}`) melalui HTTP polos (`POST http://127.0.0.1:8000/api/secrets`). Karena tidak menggunakan TLS/HTTPS, data bergerak dalam bentuk *plaintext* di interface loopback dan dapat dibaca oleh *packet sniffer*.
2. **Encryption (Sisi Server):**
   Server Flask membaca kunci rahasia 256-bit (`AES_SECRET_KEY`) dari file `.env`, membangkitkan *nonce* acak 96-bit (12 byte) yang unik untuk setiap transaksi, lalu mengenkripsi payload JSON menggunakan algoritma **AES-256-GCM** (menghasilkan *ciphertext* beserta *authentication tag* 128-bit).
3. **Storage (*Data at Rest* di SQLite):**
   Server hanya menyimpan `algorithm`, `nonce_b64`, `ciphertext_b64`, dan `created_at` ke tabel `secrets` pada file `data/vault.db`. Tidak ada teks asli (*plaintext*) yang ditulis ke disk.
4. **Retrieval (Pengambilan dari Storage):**
   Saat endpoint `GET /api/secrets` dipanggil, server mengambil seluruh baris terenkripsi (`nonce_b64` dan `ciphertext_b64`) dari `data/vault.db`.
5. **Decryption (Sisi Server -> Client):**
   Server memverifikasi *authentication tag* dan mendekripsi *ciphertext* menggunakan `AES_SECRET_KEY` dari `.env`, lalu mengirimkan hasil *plaintext* kembali ke *client* dalam respons HTTP JSON (`200 OK`).

---

## 2. Struktur Proyek

```text
Tugas-Keamanan-Jaringan/
├── .env                  # Kunci AES-256-GCM (256-bit Base64) & konfigurasi server
├── .env.example          # Template konfigurasi environment
├── .gitignore            # Pengecualian file sensitif (.env) & cache
├── requirements.txt      # Dependensi Python (Flask, cryptography, dotenv, scapy, requests)
├── app.py                # Server Flask lokal di http://127.0.0.1:8000
├── crypto_utils.py       # Implementasi enkripsi & dekripsi AES-256-GCM
├── database.py           # Operasi SQLite (init, insert ciphertext, fetch, delete)
├── sniffer.py            # Sniffer loopback (Scapy/Npcap) & analyzer PCAP
├── simulate_test.py      # Skrip pengujian otomatis end-to-end
├── templates/
│   └── index.html        # Antarmuka web lokal (Input, Dekripsi, Inspeksi DB)
├── static/
│   ├── style.css         # Gaya antarmuka web
│   └── app.js            # Interaksi frontend ke REST API
├── data/
│   └── vault.db          # Database SQLite berisi ciphertext terenkripsi
├── bukti_sniffing.pcap   # File tangkapan paket jaringan (kompatibel Wireshark)
├── README.md             # Dokumentasi arsitektur & panduan penggunaan
└── LAPORAN_BUKTI.md      # Laporan analisis bukti sniffing & inspeksi storage
```

---

## 3. Cara Menjalankan Proyek

### Prasyarat
- Python 3.10+
- Pada Windows: **Npcap** (terpasang agar Scapy dapat menangkap lalu lintas `\Device\NPF_Loopback`).
- Pada Linux: `libpcap` / `tcpdump` / `tshark` pada interface `lo`.

Instal dependensi:
```bash
pip install -r requirements.txt
```

### Langkah 1: Jalankan Server Web Lokal
```bash
python app.py
```
Server berjalan di `http://127.0.0.1:8000` (HTTP polos). Anda dapat membuka alamat tersebut di browser untuk mencoba fitur **Input & Simpan (Enkripsi)**, **Baca Data (Dekripsi)**, dan **Inspeksi Ciphertext SQLite**.

### Langkah 2: Jalankan Simulasi Sniffing & Pengujian Otomatis
Pada terminal terpisah (saat server aktif):
```bash
python simulate_test.py
```
Skrip ini akan otomatis:
1. Menjalankan `sniffer.py` pada interface loopback (`tcp port 8000`) -> `bukti_sniffing.pcap`.
2. Mengirim `{"name": "Agen_Garuda_01", "secret_message": "RAHASIA_NEGARA_123"}` ke `POST /api/secrets`.
3. Memanggil `GET /api/secrets` untuk memicu proses dekripsi.
4. Menghentikan sniffer, memeriksa isi mentah `data/vault.db`, dan menampilkan ekstraksi paket HTTP dari `bukti_sniffing.pcap`.

### Langkah 3: Analisis Manual File PCAP
Menggunakan skrip bawaan proyek:
```bash
python sniffer.py --analyze bukti_sniffing.pcap
```
Atau jika menggunakan **Wireshark / tshark** (di Linux atau Windows yang memiliki `tshark`):
```bash
tshark -r bukti_sniffing.pcap -Y "http" -V
```
