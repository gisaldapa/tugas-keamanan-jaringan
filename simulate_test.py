"""
Skrip Simulasi & Pembuktian End-to-End:
1. Memastikan server lokal HTTP (127.0.0.1:8000) berjalan.
2. Menjalankan sniffer.py pada interface loopback -> bukti_sniffing.pcap.
3. Mengirim data sensitif ("RAHASIA_NEGARA_123") ke POST /api/secrets.
4. Membaca kembali data terdekripsi dari GET /api/secrets.
5. Menghentikan sniffer, memeriksa isi mentah SQLite (ciphertext),
   dan mengekstrak bukti payload HTTP dari bukti_sniffing.pcap.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import requests

from sniffer import analyze_pcap

BASE_DIR = Path(__file__).resolve().parent
SERVER_URL = "http://127.0.0.1:8000"
PCAP_PATH = BASE_DIR / "bukti_sniffing.pcap"
DB_PATH = BASE_DIR / "data" / "vault.db"

TEST_PAYLOAD = {
    "name": "Agen_Garuda_01",
    "secret_message": "RAHASIA_NEGARA_123",
}


def wait_for_file(path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.1)
    raise TimeoutError(f"Timeout menunggu file penanda: {path}")


def main() -> None:
    print("[1/5] Memeriksa kesehatan server lokal di", SERVER_URL)
    health_res = requests.get(f"{SERVER_URL}/health", timeout=5)
    health_res.raise_for_status()
    print("      Server aktif:", json.dumps(health_res.json(), ensure_ascii=False))

    with tempfile.TemporaryDirectory() as tmpdir:
        ready_file = Path(tmpdir) / "sniffer.ready"
        stop_file = Path(tmpdir) / "sniffer.stop"

        print("\n[2/5] Memulai packet sniffer pada interface loopback (port 8000)...")
        sniffer_proc = subprocess.Popen(
            [
                sys.executable,
                str(BASE_DIR / "sniffer.py"),
                "--capture",
                "--output",
                str(PCAP_PATH),
                "--port",
                "8000",
                "--ready-file",
                str(ready_file),
                "--stop-file",
                str(stop_file),
            ],
            cwd=str(BASE_DIR),
        )

        try:
            wait_for_file(ready_file, timeout=10.0)
            time.sleep(0.8)  # Beri waktu agar handle Npcap aktif sepenuhnya

            print("\n[3/5] Mengirim payload sensitif (POST /api/secrets) & membaca (GET /api/secrets)...")
            headers = {"Connection": "close"}

            post_res = requests.post(
                f"{SERVER_URL}/api/secrets",
                json=TEST_PAYLOAD,
                headers=headers,
                timeout=5,
            )
            post_res.raise_for_status()
            post_json = post_res.json()
            print("      POST Response (201):", json.dumps(post_json, ensure_ascii=False))

            time.sleep(0.3)

            get_res = requests.get(
                f"{SERVER_URL}/api/secrets",
                headers=headers,
                timeout=5,
            )
            get_res.raise_for_status()
            get_json = get_res.json()
            print("      GET Response (200) :", json.dumps(get_json, ensure_ascii=False))

            time.sleep(0.8)  # Pastikan seluruh paket TCP ACK/FIN selesai terekam
        finally:
            print("\n[4/5] Menghentikan packet sniffer & menyimpan bukti_sniffing.pcap...")
            stop_file.write_text("STOP", encoding="utf-8")
            sniffer_proc.wait(timeout=10)

    print("\n[5/5] Verifikasi Bukti Penyimpanan Lokal (SQLite) & Analisis PCAP:")
    print("-" * 80)
    print(f"INSPEKSI LANGSUNG SQLITE ({DB_PATH}):")
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT id, algorithm, nonce_b64, ciphertext_b64, created_at FROM secrets ORDER BY id DESC"
        ).fetchall()
        for row in rows:
            print(
                f"  Row id={row[0]} | alg={row[1]} | nonce={row[2]} | "
                f"ciphertext={row[3]} | created_at={row[4]}"
            )
            assert TEST_PAYLOAD["secret_message"] not in row[3], (
                "ALERT: Plaintext ditemukan di database!"
            )
    print("  [OK] Terverifikasi: Plaintext 'RAHASIA_NEGARA_123' TIDAK ADA di file database SQLite.")
    print("-" * 80)

    analyze_pcap(str(PCAP_PATH), port=8000, http_only=True)


if __name__ == "__main__":
    main()
