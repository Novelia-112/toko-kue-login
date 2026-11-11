import sys
import psycopg2
from psycopg2 import errors

from app import create_user

AKUN_UJI = [
    # Kategori lemah: password umum. Sebagian sengaja kembar untuk menguji efek salt.
    ("lemah01", "123456"),
    ("lemah02", "123456"),
    ("lemah03", "123456"),
    ("lemah04", "password"),
    ("lemah05", "password"),
    ("lemah06", "qwerty"),
    ("lemah07", "iloveyou"),
    ("lemah08", "abc123"),
    ("lemah09", "letmein"),
    ("lemah10", "welcome"),
    # Kategori sedang: kata + angka.
    ("sedang01", "kucing2024"),
    ("sedang02", "kucing2024"),
    ("sedang03", "bunga1234"),
    ("sedang04", "sayang123"),
    ("sedang05", "matahari99"),
    ("sedang06", "jember2026"),
    ("sedang07", "bakso2020"),
    ("sedang08", "melati777"),
    ("sedang09", "cantik2025"),
    ("sedang10", "kopi8899"),
    # Kategori kuat: acak, 12 karakter campuran.
    ("kuat01", "Xk9#mQ2vLp7z"),
    ("kuat02", "vR4$tN8wBc1y"),
    ("kuat03", "Hf6&zD3jUe5q"),
    ("kuat04", "pW2!sG7kYa9m"),
    ("kuat05", "Tn8@cV4xJr6d"),
    ("kuat06", "Zb5%qL1hMw3e"),
    ("kuat07", "Qd7^yK2uNf8s"),
    ("kuat08", "Mj3*eP9tXc4v"),
    ("kuat09", "Ys6(rA1gHb7w"),
    ("kuat10", "Lc9)wT5nVd2k"),
]


def main():
    dibuat = dilewati = 0
    for username, password in AKUN_UJI:
        try:
            create_user(username, password)
            dibuat += 1
        except errors.UniqueViolation:
            dilewati += 1
        except psycopg2.OperationalError as e:
            sys.exit(f"Tidak bisa terhubung ke database. Periksa .env dan PostgreSQL.\n{e}")
    print(f"Selesai. Dibuat: {dibuat}, dilewati (sudah ada): {dilewati}, total: {len(AKUN_UJI)}")


if __name__ == "__main__":
    main()