"""
Sistem login toko kue.

Saat mendaftar, password disimpan dengan tiga cara sekaligus (untuk bahan perbandingan):
  1. plaintext
  2. hash SHA-256 saja
  3. hash SHA-256 + salt unik per pengguna
Saat login, password diperiksa memakai mode LOGIN_MODE (default: salted).
"""
import hashlib
import hmac
import os
import re
import secrets

import psycopg2
from dotenv import load_dotenv
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for)
from psycopg2 import errors

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Tabel untuk tiap cara penyimpanan password.
# Saat mendaftar, password disimpan ke KETIGA tabel sekaligus (untuk bahan perbandingan serangan).
# Nama tabel ditulis tetap di kode, tidak pernah dari input pengguna.
TABLES = {"plain": "users_plain", "hash": "users_hash", "salted": "users_salted"}

# Tabel yang dipakai untuk memeriksa login. Ubah lewat LOGIN_MODE di file .env
# (plain / hash / salted). Default: salted, yaitu yang paling aman.
LOGIN_MODE = os.environ.get("LOGIN_MODE", "salted")
if LOGIN_MODE not in TABLES:
    raise SystemExit("LOGIN_MODE di .env harus plain, hash, atau salted.")

# Nama toko, bisa diganti lewat SHOP_NAME di file .env
SHOP_NAME = os.environ.get("SHOP_NAME", "Dapur Cantika")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,50}$")


# ---------------------------------------------------------------- database
def db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=os.environ.get("DB_PORT", "5432"),
        dbname=os.environ.get("DB_NAME", "toko_kue"),
        user=os.environ.get("DB_USER", "postgres"),
        password=os.environ.get("DB_PASSWORD", ""),
    )


# ------------------------------------------------------------------ kripto
def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def safe_equal(a: str, b: str) -> bool:
    """Perbandingan waktu-konstan agar tahan timing attack."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def create_user(username: str, password: str) -> None:
    """Simpan akun ke ketiga tabel dalam satu transaksi (semua berhasil atau tidak sama sekali)."""
    salt = secrets.token_hex(16)  # 16 byte acak, unik per pengguna
    conn = db()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {TABLES['plain']} (username, password) VALUES (%s, %s)",
                (username, password),
            )
            cur.execute(
                f"INSERT INTO {TABLES['hash']} (username, password_hash) VALUES (%s, %s)",
                (username, sha256_hex(password)),
            )
            cur.execute(
                f"INSERT INTO {TABLES['salted']} (username, salt, password_hash) "
                "VALUES (%s, %s, %s)",
                (username, salt, sha256_hex(salt + password)),
            )
    finally:
        conn.close()


def verify_login(username: str, password: str) -> bool:
    table = TABLES[LOGIN_MODE]
    conn = db()
    try:
        with conn, conn.cursor() as cur:
            if LOGIN_MODE == "plain":
                cur.execute(f"SELECT password FROM {table} WHERE username = %s", (username,))
                row = cur.fetchone()
                return row is not None and safe_equal(row[0], password)

            if LOGIN_MODE == "hash":
                cur.execute(f"SELECT password_hash FROM {table} WHERE username = %s", (username,))
                row = cur.fetchone()
                return row is not None and safe_equal(row[0], sha256_hex(password))

            cur.execute(
                f"SELECT salt, password_hash FROM {table} WHERE username = %s", (username,)
            )
            row = cur.fetchone()
            if row is None:
                return False
            salt, stored_hash = row
            return safe_equal(stored_hash, sha256_hex(salt + password))
    finally:
        conn.close()


@app.context_processor
def inject_shop_name():
    return {"shop_name": SHOP_NAME}


# ----------------------------------------------------------------- helpers
def validate(username: str, password: str):
    if not USERNAME_RE.match(username):
        return "Username harus 3-50 karakter: huruf, angka, atau garis bawah."
    # Batas minimum sengaja rendah (4) supaya password lemah tetap bisa dipakai untuk pengujian serangan.
    if not 4 <= len(password) <= 128:
        return "Password harus 4-128 karakter."
    return None


# ------------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if "username" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        error = validate(username, password)
        if error:
            flash(error, "error")
        else:
            try:
                create_user(username, password)
            except errors.UniqueViolation:
                flash("Username ini sudah dipakai. Coba username lain.", "error")
            except psycopg2.Error:
                app.logger.exception("Gagal menyimpan akun")
                flash("Tidak bisa terhubung ke database. Periksa PostgreSQL dan file .env.", "error")
            else:
                flash("Akunmu sudah jadi. Silakan masuk.", "success")
                return redirect(url_for("login"))
    return render_template("register.html", username=username)


@app.route("/login", methods=["GET", "POST"])
def login():
    username = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        try:
            ok = verify_login(username, password)
        except psycopg2.Error:
            app.logger.exception("Gagal membaca database")
            flash("Tidak bisa terhubung ke database. Periksa PostgreSQL dan file .env.", "error")
        else:
            if ok:
                session.clear()
                session["username"] = username
                return redirect(url_for("dashboard"))
            flash("Username atau password salah. Periksa lagi ya.", "error")
    return render_template("login.html", username=username)


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Kamu sudah keluar.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    # debug=True hanya untuk pengembangan lokal.
    app.run(debug=True)
