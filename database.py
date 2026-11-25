"""
Modul Manajemen Penyimpanan Lokal (SQLite) untuk Data Terenkripsi (Ciphertext).
Database hanya menyimpan nonce, ciphertext (termasuk auth tag), algoritma, dan timestamp.
Tidak ada plaintext sensitif yang disimpan ke disk.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _get_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """Membuat direktori data dan tabel SQLite jika belum tersedia."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with _get_connection(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                algorithm TEXT NOT NULL,
                nonce_b64 TEXT NOT NULL,
                ciphertext_b64 TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def insert_encrypted_record(
    db_path: str,
    algorithm: str,
    nonce_b64: str,
    ciphertext_b64: str,
) -> dict[str, Any]:
    """Menyimpan record terenkripsi baru ke tabel secrets dan mengembalikan metadatanya."""
    created_at = datetime.now(timezone.utc).isoformat()
    with _get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO secrets (algorithm, nonce_b64, ciphertext_b64, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (algorithm, nonce_b64, ciphertext_b64, created_at),
        )
        conn.commit()
        record_id = cursor.lastrowid

    return {
        "id": record_id,
        "algorithm": algorithm,
        "nonce_b64": nonce_b64,
        "ciphertext_b64": ciphertext_b64,
        "created_at": created_at,
    }


def fetch_all_encrypted_records(db_path: str) -> list[dict[str, Any]]:
    """Mengambil seluruh record terenkripsi dari database SQLite (terurut dari terbaru)."""
    if not os.path.exists(db_path):
        return []
    with _get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, algorithm, nonce_b64, ciphertext_b64, created_at
            FROM secrets
            ORDER BY id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def delete_record_by_id(db_path: str, record_id: int) -> bool:
    """Menghapus satu record berdasarkan ID."""
    with _get_connection(db_path) as conn:
        cursor = conn.execute("DELETE FROM secrets WHERE id = ?", (record_id,))
        conn.commit()
        return cursor.rowcount > 0
