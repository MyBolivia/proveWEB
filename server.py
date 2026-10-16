"""Applicazione Flask per registrazione e login utenti.

Avvio locale:
    pip install -r requirements.txt
    python server.py
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from pathlib import Path

from flask import Flask, abort, jsonify, request, send_from_directory


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "users.db"
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
STATIC_FILES = {"index.html", "register.html", "welcome.html", "style.css", "database.svg"}

app = Flask(__name__)


def setup_database() -> None:
    """Crea il database e la tabella alla prima esecuzione."""
    with sqlite3.connect(DATABASE_PATH) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


def hash_password(password: str) -> str:
    """Restituisce sale e hash PBKDF2 in un formato conservabile nel DB."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    salt_hex, digest_hex = stored_hash.split("$", 1)
    computed = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 600_000
    )
    return hmac.compare_digest(computed.hex(), digest_hex)


@app.get("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/<path:filename>")
def static_file(filename: str):
    """Serve solo i file pubblici dell'interfaccia."""
    if filename not in STATIC_FILES:
        abort(404)
    return send_from_directory(BASE_DIR, filename)


@app.post("/register")
def register():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not EMAIL_PATTERN.fullmatch(email) or len(password) < 8:
        return jsonify(
            message="Inserisci nome, un indirizzo email valido e una password di almeno 8 caratteri."
        ), 400

    try:
        with sqlite3.connect(DATABASE_PATH) as connection:
            connection.execute(
                "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, hash_password(password)),
            )
    except sqlite3.IntegrityError:
        return jsonify(message="Esiste già un utente con questa email."), 409

    return jsonify(message="Registrazione completata."), 201


@app.post("/login")
def login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    with sqlite3.connect(DATABASE_PATH) as connection:
        user = connection.execute(
            "SELECT password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

    if user is None or not verify_password(password, user[0]):
        return jsonify(message="Email o password non corretti."), 401

    return jsonify(message="Accesso effettuato.")


setup_database()

if __name__ == "__main__":
    # PORT permette l'avvio su servizi cloud; in locale resta disponibile su 8000.
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port, debug=True)
