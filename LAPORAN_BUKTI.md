# Laporan Pembuktian Analisis Lalu Lintas Jaringan & Keamanan Penyimpanan Lokal

## 1. Ringkasan Pengujian

Pengujian dilakukan pada lingkungan lokal Windows menggunakan:
- **Target Server:** `http://127.0.0.1:8000` (`app.py` - Flask HTTP/1.1 polos)
- **Algoritma Enkripsi Penyimpanan:** `AES-256-GCM` (kunci 256-bit di `.env`)
- **Penyimpanan Lokal:** SQLite (`data/vault.db`)
- **Packet Sniffer:** `sniffer.py` (Scapy pada interface `\Device\NPF_Loopback`, BPF filter `tcp port 8000`)
- **Payload Uji:** `{"name": "Agen_Garuda_01", "secret_message": "RAHASIA_NEGARA_123"}`
- **Artefak Rekaman:** `bukti_sniffing.pcap` (28 paket TCP tertangkap, ukuran 3.172 bytes)

---

## 2. Perbandingan Bukti Nyata: Data in Transit vs. Data at Rest

| Aspek Pengamatan | Data di Jaringan (*Data in Transit* — `bukti_sniffing.pcap`) | Data di Database Lokal (*Data at Rest* — `data/vault.db`) |
| :--- | :--- | :--- |
| **Protokol / Mekanisme** | HTTP/1.1 Polos di atas TCP (`127.0.0.1:8000`) | Enkripsi Simetris **AES-256-GCM** sebelum `INSERT` ke SQLite |
| **Bentuk Data (`POST` / Kirim)** | **Plaintext terbaca jelas:** `{"name": "Agen_Garuda_01", "secret_message": "RAHASIA_NEGARA_123"}` | **Ciphertext Base64:** `3H6E3wPYRSB7n2DkpFSqh4tHQiPs9qYOc3eVtg/nKnuSgn5jnnl3Pxmuh0j2yEIoTCdtKMmGXg8O2fX4/a5/6MAHUWHWSj3Mqkamhk9gXQbDPw==` |
| **Bentuk Data (`GET` / Baca)** | **Plaintext terbaca jelas** pada HTTP `200 OK` JSON response | Tetap tersimpan sebagai **Ciphertext + Nonce (`YY0AVArk1XwQW3ty`)** |
| **Kerentanan Jika Disadap/Dicuri** | Penyerang (*sniffer*) di jalur jaringan langsung mendapatkan rahasia `RAHASIA_NEGARA_123` | Penyerang yang mencuri file `vault.db` tanpa file `.env` **tidak dapat membaca** isi data asli |

---

## 3. Bukti Output Terminal: Proses Sniffing & Inspeksi SQLite

Berikut adalah output aktual dari eksekusi `python simulate_test.py` saat transaksi berlangsung:

```text
[SNIFFER] Interface   : \Device\NPF_Loopback
[SNIFFER] BPF Filter  : tcp port 8000
[SNIFFER] Output PCAP : C:\laragon\www\Tugas-Keamanan-Jaringan\bukti_sniffing.pcap
[SNIFFER] Memulai perekaman paket...
[SNIFFER] Perekaman selesai. Total paket tersimpan: 28 -> C:\laragon\www\Tugas-Keamanan-Jaringan\bukti_sniffing.pcap
[1/5] Memeriksa kesehatan server lokal di http://127.0.0.1:8000
      Server aktif: {"host": "127.0.0.1", "port": 8000, "status": "ok", "storage_encryption": "AES-256-GCM", "transport_protocol": "HTTP/1.1 (Plaintext - Sniffable)"}

[2/5] Memulai packet sniffer pada interface loopback (port 8000)...

[3/5] Mengirim payload sensitif (POST /api/secrets) & membaca (GET /api/secrets)...
      POST Response (201): {"message": "Data berhasil dienkripsi (AES-256-GCM) dan disimpan ke SQLite.", "record": {"algorithm": "AES-256-GCM", "ciphertext_b64": "3H6E3wPYRSB7n2DkpFSqh4tHQiPs9qYOc3eVtg/nKnuSgn5jnnl3Pxmuh0j2yEIoTCdtKMmGXg8O2fX4/a5/6MAHUWHWSj3Mqkamhk9gXQbDPw==", "created_at": "2026-11-25T07:08:50.008374+00:00", "id": 1, "nonce_b64": "YY0AVArk1XwQW3ty"}}
      GET Response (200) : {"count": 1, "items": [{"algorithm": "AES-256-GCM", "ciphertext_b64": "3H6E3wPYRSB7n2DkpFSqh4tHQiPs9qYOc3eVtg/nKnuSgn5jnnl3Pxmuh0j2yEIoTCdtKMmGXg8O2fX4/a5/6MAHUWHWSj3Mqkamhk9gXQbDPw==", "created_at": "2026-11-25T07:08:50.008374+00:00", "id": 1, "name": "Agen_Garuda_01", "nonce_b64": "YY0AVArk1XwQW3ty", "secret_message": "RAHASIA_NEGARA_123"}]}

[4/5] Menghentikan packet sniffer & menyimpan bukti_sniffing.pcap...

[5/5] Verifikasi Bukti Penyimpanan Lokal (SQLite) & Analisis PCAP:
--------------------------------------------------------------------------------
INSPEKSI LANGSUNG SQLITE (C:\laragon\www\Tugas-Keamanan-Jaringan\data\vault.db):
  Row id=1 | alg=AES-256-GCM | nonce=YY0AVArk1XwQW3ty | ciphertext=3H6E3wPYRSB7n2DkpFSqh4tHQiPs9qYOc3eVtg/nKnuSgn5jnnl3Pxmuh0j2yEIoTCdtKMmGXg8O2fX4/a5/6MAHUWHWSj3Mqkamhk9gXQbDPw== | created_at=2026-11-25T07:08:50.008374+00:00
  [OK] Terverifikasi: Plaintext 'RAHASIA_NEGARA_123' TIDAK ADA di file database SQLite.
--------------------------------------------------------------------------------
```

---

## 4. Bukti Ekstraksi Paket TCP/HTTP dari `bukti_sniffing.pcap`

Hasil ekstraksi langsung dari `bukti_sniffing.pcap` menggunakan `python sniffer.py --analyze bukti_sniffing.pcap` yang memperlihatkan header layer jaringan (`IP`), header transport (`TCP`), header `HTTP`, dan isi payload yang tertangkap:

```text
================================================================================
ANALISIS FILE PCAP : C:\laragon\www\Tugas-Keamanan-Jaringan\bukti_sniffing.pcap
Total Paket        : 28
Filter Tampilan    : TCP port 8000 (HTTP Payload Only)
================================================================================

--- Frame #4 | Timestamp: 2026-11-25 14:08:50.000 | Length: 248 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:51431 -> 127.0.0.1:8000 [Flags: PA, Seq=227273154, Ack=622990266, Payload=204B]
HTTP Payload    :
    POST /api/secrets HTTP/1.1
    Host: 127.0.0.1:8000
    User-Agent: python-requests/2.34.2
    Accept-Encoding: gzip, deflate
    Accept: */*
    Connection: close
    Content-Length: 66
    Content-Type: application/json
    

--- Frame #6 | Timestamp: 2026-11-25 14:08:50.000 | Length: 110 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:51431 -> 127.0.0.1:8000 [Flags: PA, Seq=227273358, Ack=622990266, Payload=66B]
HTTP Payload    :
    {"name": "Agen_Garuda_01", "secret_message": "RAHASIA_NEGARA_123"}


--- Frame #8 | Timestamp: 2026-11-25 14:08:50.019 | Length: 215 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:8000 -> 127.0.0.1:51431 [Flags: PA, Seq=622990266, Ack=227273424, Payload=171B]
HTTP Payload    :
    HTTP/1.1 201 CREATED
    Server: Werkzeug/3.1.9 Python/3.10.6
    Date: Wed, 25 Nov 2026 07:08:50 GMT
    Content-Type: application/json
    Content-Length: 332
    Connection: close
    

--- Frame #10 | Timestamp: 2026-11-25 14:08:50.020 | Length: 376 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:8000 -> 127.0.0.1:51431 [Flags: PA, Seq=622990437, Ack=227273424, Payload=332B]
HTTP Payload    :
    {"message":"Data berhasil dienkripsi (AES-256-GCM) dan disimpan ke SQLite.","record":{"algorithm":"AES-256-GCM","ciphertext_b64":"3H6E3wPYRSB7n2DkpFSqh4tHQiPs9qYOc3eVtg/nKnuSgn5jnnl3Pxmuh0j2yEIoTCdtKMmGXg8O2fX4/a5/6MAHUWHWSj3Mqkamhk9gXQbDPw==","created_at":"2026-11-25T07:08:50.008374+00:00","id":1,"nonce_b64":"YY0AVArk1XwQW3ty"}}

--- Frame #19 | Timestamp: 2026-11-25 14:08:50.326 | Length: 195 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:51432 -> 127.0.0.1:8000 [Flags: PA, Seq=3763411478, Ack=3717781463, Payload=151B]
HTTP Payload    :
    GET /api/secrets HTTP/1.1
    Host: 127.0.0.1:8000
    User-Agent: python-requests/2.34.2
    Accept-Encoding: gzip, deflate
    Accept: */*
    Connection: close
    

--- Frame #21 | Timestamp: 2026-11-25 14:08:50.331 | Length: 210 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:8000 -> 127.0.0.1:51432 [Flags: PA, Seq=3717781463, Ack=3763411629, Payload=166B]
HTTP Payload    :
    HTTP/1.1 200 OK
    Server: Werkzeug/3.1.9 Python/3.10.6
    Date: Wed, 25 Nov 2026 07:08:50 GMT
    Content-Type: application/json
    Content-Length: 330
    Connection: close
    

--- Frame #23 | Timestamp: 2026-11-25 14:08:50.331 | Length: 374 bytes ---
Network Layer   : 127.0.0.1 -> 127.0.0.1
Transport (TCP) : 127.0.0.1:8000 -> 127.0.0.1:51432 [Flags: PA, Seq=3717781629, Ack=3763411629, Payload=330B]
HTTP Payload    :
    {"count":1,"items":[{"algorithm":"AES-256-GCM","ciphertext_b64":"3H6E3wPYRSB7n2DkpFSqh4tHQiPs9qYOc3eVtg/nKnuSgn5jnnl3Pxmuh0j2yEIoTCdtKMmGXg8O2fX4/a5/6MAHUWHWSj3Mqkamhk9gXQbDPw==","created_at":"2026-11-25T07:08:50.008374+00:00","id":1,"name":"Agen_Garuda_01","nonce_b64":"YY0AVArk1XwQW3ty","secret_message":"RAHASIA_NEGARA_123"}]}
================================================================================
Total paket yang ditampilkan: 7
================================================================================
```

---

## 5. Analisis Keamanan & Rekomendasi Mitigasi

1. **Perlindungan Penyimpanan Lokal (*Encryption at Rest*) Berhasil:**
   - Pada **Frame #10** dan **Inspeksi SQLite**, data yang disimpan ke `data/vault.db` adalah *ciphertext* `3H6E3wPYRSB...` dengan *nonce* 96-bit `YY0AVArk1XwQW3ty`.
   - Karena kunci `AES_SECRET_KEY` disimpan terpisah di `.env`, kebocoran file `data/vault.db` tidak membocorkan informasi sensitif.
2. **Kerentanan Transmisi HTTP Polos (*Plaintext in Transit*) Terbukti:**
   - Pada **Frame #6** (`127.0.0.1:51431 -> 127.0.0.1:8000`), payload permintaan `{"name": "Agen_Garuda_01", "secret_message": "RAHASIA_NEGARA_123"}` tertangkap utuh tanpa enkripsi.
   - Pada **Frame #23** (`127.0.0.1:8000 -> 127.0.0.1:51432`), hasil dekripsi dari server juga dikirim kembali sebagai teks polos di jaringan.
3. **Rekomendasi Produksi:**
   - Wajib mengaktifkan **HTTPS / TLS 1.3** di lapisan transport (misalnya menggunakan *reverse proxy* Nginx/Caddy atau sertifikat TLS) agar lalu lintas HTTP terenkripsi saat transit.
   - Pertahankan enkripsi **AES-256-GCM** di lapisan aplikasi/penyimpanan untuk pertahanan berlapis (*Defense in Depth*) dan gunakan *Key Management Service* (KMS) atau *secret manager* untuk rotasi kunci.
