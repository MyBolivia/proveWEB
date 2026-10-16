"""Server web minimale per la registrazione utenti.

Avvio: python server.py
Poi apri: http://localhost:8000
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "users.db"
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


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
    """Utile per aggiungere in seguito un endpoint di login."""
    salt_hex, digest_hex = stored_hash.split("$", 1)
    computed = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 600_000
    )
    return hmac.compare_digest(computed.hex(), digest_hex)


class RegistrationHandler(SimpleHTTPRequestHandler):
    """Serve i file statici e riceve login e registrazione."""

    def do_POST(self) -> None:
        if self.path not in {"/register", "/login"}:
            self.send_error(HTTPStatus.NOT_FOUND, "Endpoint non trovato")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.respond_json(HTTPStatus.BAD_REQUEST, '{"message":"Richiesta non valida."}')
            return

        if length > 10_000:
            self.respond_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, '{"message":"Richiesta troppo grande."}')
            return

        data = parse_qs(self.rfile.read(length).decode("utf-8"), keep_blank_values=True)
        email = data.get("email", [""])[0].strip().lower()
        password = data.get("password", [""])[0]

        if self.path == "/login":
            self.login(email, password)
            return

        name = data.get("name", [""])[0].strip()

        if not name or not EMAIL_PATTERN.fullmatch(email) or len(password) < 8:
            self.respond_json(
                HTTPStatus.BAD_REQUEST,
                '{"message":"Inserisci nome, un indirizzo email valido e una password di almeno 8 caratteri."}',
            )
            return

        try:
            with sqlite3.connect(DATABASE_PATH) as connection:
                connection.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, hash_password(password)),
                )
        except sqlite3.IntegrityError:
            self.respond_json(HTTPStatus.CONFLICT, '{"message":"Esiste già un utente con questa email."}')
            return

        self.respond_json(HTTPStatus.CREATED, '{"message":"Registrazione completata."}')

    def login(self, email: str, password: str) -> None:
        """Controlla le credenziali senza rivelare se l'email esiste."""
        with sqlite3.connect(DATABASE_PATH) as connection:
            user = connection.execute(
                "SELECT password_hash FROM users WHERE email = ?", (email,)
            ).fetchone()

        if user is None or not verify_password(password, user[0]):
            self.respond_json(
                HTTPStatus.UNAUTHORIZED,
                '{"message":"Email o password non corretti."}',
            )
            return

        self.respond_json(HTTPStatus.OK, '{"message":"Accesso effettuato."}')

    def respond_json(self, status: HTTPStatus, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


if __name__ == "__main__":
    os.chdir(BASE_DIR)  # SimpleHTTPRequestHandler servirà la cartella del progetto.
    setup_database()
    server = ThreadingHTTPServer(("localhost", 8000), RegistrationHandler)
    print("Server in ascolto su http://localhost:8000")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer arrestato.")
    finally:
        server.server_close()
