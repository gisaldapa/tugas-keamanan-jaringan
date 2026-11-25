"""
Modul Kriptografi Simetris (AES-256-GCM) untuk Keamanan Penyimpanan Lokal (Data at Rest).

Menggunakan Authenticated Encryption with Associated Data (AEAD) AES-256-GCM:
- Panjang Kunci: 256-bit (32 byte), dimuat dari variabel lingkungan (.env).
- Nonce (IV): 96-bit (12 byte) acak per operasi enkripsi agar ciphertext selalu unik
  meskipun plaintext identik.
- Authentication Tag: 128-bit (16 byte) otomatis disertakan oleh AESGCM untuk
  memastikan kerahasiaan (confidentiality) dan integritas (integrity) data.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ALGORITHM_NAME = "AES-256-GCM"
NONCE_SIZE_BYTES = 12
KEY_SIZE_BYTES = 32


def load_secret_key() -> bytes:
    """Memuat dan memvalidasi kunci AES-256 (32 byte Base64) dari environment variable."""
    raw_key = os.getenv("AES_SECRET_KEY", "").strip()
    if not raw_key:
        raise RuntimeError(
            "AES_SECRET_KEY tidak ditemukan di environment/.env. "
            "Setel variabel AES_SECRET_KEY terlebih dahulu."
        )

    try:
        key_bytes = base64.b64decode(raw_key, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("Format AES_SECRET_KEY harus berupa Base64 yang valid.") from exc

    if len(key_bytes) != KEY_SIZE_BYTES:
        raise RuntimeError(
            f"Panjang kunci AES-256 harus {KEY_SIZE_BYTES} byte (256-bit), "
            f"ditemukan {len(key_bytes)} byte."
        )
    return key_bytes


def encrypt_data(payload: dict[str, Any], key: bytes | None = None) -> tuple[str, str]:
    """
    Mengenkripsi dictionary menjadi pasangan (nonce_b64, ciphertext_b64) menggunakan AES-256-GCM.
    Ciphertext yang dihasilkan sudah mencakup 16-byte authentication tag di bagian akhir.
    """
    secret_key = key if key is not None else load_secret_key()
    aesgcm = AESGCM(secret_key)
    nonce = os.urandom(NONCE_SIZE_BYTES)
    plaintext_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ciphertext_bytes = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)

    return (
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(ciphertext_bytes).decode("ascii"),
    )


def decrypt_data(nonce_b64: str, ciphertext_b64: str, key: bytes | None = None) -> dict[str, Any]:
    """
    Mendekripsi pasangan (nonce_b64, ciphertext_b64) kembali menjadi dictionary asli.
    Melempar cryptography.exceptions.InvalidTag jika data dimodifikasi atau kunci salah.
    """
    secret_key = key if key is not None else load_secret_key()
    aesgcm = AESGCM(secret_key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext_bytes = base64.b64decode(ciphertext_b64)

    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_bytes, associated_data=None)
    return json.loads(plaintext_bytes.decode("utf-8"))
