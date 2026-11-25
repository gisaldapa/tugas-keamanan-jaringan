"""
Server Web Lokal (HTTP Polos di 127.0.0.1:8000) untuk Simulasi Keamanan Data.

Tujuan Arsitektur:
- Protokol Transport: HTTP polos (tanpa TLS) agar paket lalu lintas dapat diamati
  secara jelas menggunakan sniffer pada loopback interface (lo / Npcap Loopback).
- Keamanan Penyimpanan (Data at Rest): Data sensitif dienkripsi di sisi server
  menggunakan AES-256-GCM dengan kunci dari .env sebelum disimpan ke SQLite.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from crypto_utils import ALGORITHM_NAME, decrypt_data, encrypt_data, load_secret_key
from database import (
    delete_record_by_id,
    fetch_all_encrypted_records,
    init_db,
    insert_encrypted_record,
)

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def create_app() -> Flask:
    app = Flask(__name__)
    db_rel_path = os.getenv("DATABASE_PATH", "data/vault.db")
    db_path = str((BASE_DIR / db_rel_path).resolve())

    # Validasi kunci enkripsi dan inisialisasi database saat startup
    load_secret_key()
    init_db(db_path)

    @app.get("/")
    def index():
        return render_template("index.html", algorithm=ALGORITHM_NAME)

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "host": os.getenv("FLASK_HOST", "127.0.0.1"),
                "port": int(os.getenv("FLASK_PORT", "8000")),
                "transport_protocol": "HTTP/1.1 (Plaintext - Sniffable)",
                "storage_encryption": ALGORITHM_NAME,
            }
        )

    @app.post("/api/secrets")
    def save_secret():
        body = request.get_json(silent=True) or {}
        name = str(body.get("name", "")).strip()
        secret_message = str(body.get("secret_message", "")).strip()

        if not name or not secret_message:
            return (
                jsonify(
                    {
                        "error": "Field 'name' dan 'secret_message' wajib diisi.",
                    }
                ),
                400,
            )

        nonce_b64, ciphertext_b64 = encrypt_data(
            {
                "name": name,
                "secret_message": secret_message,
            }
        )

        record = insert_encrypted_record(
            db_path=db_path,
            algorithm=ALGORITHM_NAME,
            nonce_b64=nonce_b64,
            ciphertext_b64=ciphertext_b64,
        )

        return (
            jsonify(
                {
                    "message": "Data berhasil dienkripsi (AES-256-GCM) dan disimpan ke SQLite.",
                    "record": record,
                }
            ),
            201,
        )

    @app.get("/api/secrets")
    def read_secrets():
        encrypted_rows = fetch_all_encrypted_records(db_path)
        decrypted_items = []

        for row in encrypted_rows:
            try:
                plaintext_obj = decrypt_data(row["nonce_b64"], row["ciphertext_b64"])
                decrypted_items.append(
                    {
                        "id": row["id"],
                        "name": plaintext_obj.get("name", ""),
                        "secret_message": plaintext_obj.get("secret_message", ""),
                        "algorithm": row["algorithm"],
                        "nonce_b64": row["nonce_b64"],
                        "ciphertext_b64": row["ciphertext_b64"],
                        "created_at": row["created_at"],
                    }
                )
            except InvalidTag:
                decrypted_items.append(
                    {
                        "id": row["id"],
                        "error": "Gagal dekripsi: authentication tag tidak valid atau kunci berbeda.",
                        "algorithm": row["algorithm"],
                        "created_at": row["created_at"],
                    }
                )

        return jsonify(
            {
                "count": len(decrypted_items),
                "items": decrypted_items,
            }
        )

    @app.get("/api/secrets/raw")
    def read_raw_ciphertext():
        """Menampilkan isi mentah tabel SQLite (ciphertext) untuk inspeksi keamanan penyimpanan."""
        encrypted_rows = fetch_all_encrypted_records(db_path)
        return jsonify(
            {
                "count": len(encrypted_rows),
                "database_path": db_rel_path,
                "records": encrypted_rows,
            }
        )

    @app.delete("/api/secrets/<int:record_id>")
    def delete_secret(record_id: int):
        deleted = delete_record_by_id(db_path, record_id)
        if not deleted:
            return jsonify({"error": f"Record ID {record_id} tidak ditemukan."}), 404
        return jsonify({"message": f"Record ID {record_id} berhasil dihapus."}), 200

    return app


app = create_app()


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "8000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    print(f"[*] Menjalankan Secure Vault Local Server di http://{host}:{port} (HTTP Polos)")
    app.run(host=host, port=port, debug=debug, use_reloader=False)
