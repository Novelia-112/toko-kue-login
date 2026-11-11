"""
Mengukur waktu satu kali proses hashing untuk tiga skema:
SHA-256 saja, SHA-256 + salt, dan PBKDF2-HMAC-SHA256 (key stretching).

Jalankan: python perf.py
"""
import hashlib
import secrets
import time

PASSWORD_UJI = "Contoh_Password123"
SALT_UJI = secrets.token_hex(16)
ITERASI_PBKDF2 = 100_000
ULANGAN = 1000  # jumlah pengulangan supaya rata-rata stabil


def waktu_rata_rata(fungsi, ulangan=ULANGAN):
    mulai = time.perf_counter()
    for _ in range(ulangan):
        fungsi()
    total = time.perf_counter() - mulai
    return (total / ulangan) * 1000  # ke milidetik


def sha256_saja():
    return hashlib.sha256(PASSWORD_UJI.encode("utf-8")).hexdigest()


def sha256_salt():
    return hashlib.sha256((SALT_UJI + PASSWORD_UJI).encode("utf-8")).hexdigest()


def pbkdf2():
    return hashlib.pbkdf2_hmac(
        "sha256", PASSWORD_UJI.encode("utf-8"), bytes.fromhex(SALT_UJI), ITERASI_PBKDF2
    ).hex()


def main():
    print(f"Rata-rata dari {ULANGAN} kali pengulangan:\n")
    for nama, fungsi in [
        ("SHA-256 saja", sha256_saja),
        ("SHA-256 + salt", sha256_salt),
        (f"PBKDF2-HMAC-SHA256 ({ITERASI_PBKDF2:,} iterasi)", pbkdf2),
    ]:
        ms = waktu_rata_rata(fungsi)
        print(f"{nama:38s}: {ms:9.4f} ms/proses")


if __name__ == "__main__":
    main()