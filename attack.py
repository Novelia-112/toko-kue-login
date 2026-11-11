import csv
import hashlib
import itertools #dipakai nanti untuk membuat semua kombinasi karakter (brute force).
import string
import time

from app import db

ALFABET_BRUTE = string.ascii_lowercase + string.digits
PANJANG_BRUTE_MAKS = 4  # brute force dicoba untuk password sepanjang 1..4 karakter


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def muat_wordlist(path="wordlist.txt"):
    with open(path, encoding="utf-8") as f:
        return [baris.strip() for baris in f if baris.strip()]


def ambil_dump():
    """Membaca isi tabel seolah-olah database sudah bocor."""
    conn = db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT username, password_hash FROM users_hash")
            dump_hash = cur.fetchall()
            cur.execute("SELECT username, salt, password_hash FROM users_salted")
            dump_salted = cur.fetchall()
            cur.execute("SELECT username, password FROM users_plain")
            jawaban_asli = dict(cur.fetchall())  # hanya untuk verifikasi, bukan bahan serangan
        return dump_hash, dump_salted, jawaban_asli
    finally:
        conn.close()


# ------------------------------------------------------------- serangan
def serang_lookup_table(dump, wordlist, bergaram):
    """
    Dictionary attack / lookup table sederhana.
    bergaram=False -> users_hash: satu tabel hash->password cukup untuk semua akun.
    bergaram=True  -> users_salted: hash dihitung ULANG per akun karena salt berbeda.
    """
    mulai = time.perf_counter()
    hitung_hash = 0
    bobol = {}

    if not bergaram:
        tabel = {}
        for kata in wordlist:
            tabel[sha256_hex(kata)] = kata
            hitung_hash += 1
        for username, hash_tersimpan in dump:
            if hash_tersimpan in tabel:
                bobol[username] = tabel[hash_tersimpan]
    else:
        for username, salt, hash_tersimpan in dump:
            for kata in wordlist:
                hitung_hash += 1
                if sha256_hex(salt + kata) == hash_tersimpan:
                    bobol[username] = kata
                    break

    durasi = time.perf_counter() - mulai
    return bobol, hitung_hash, durasi


def serang_brute_force(dump, bergaram, panjang_maks=PANJANG_BRUTE_MAKS):
    mulai = time.perf_counter()
    hitung_hash = 0
    bobol = {}

    if not bergaram:
        tabel = {}
        for n in range(1, panjang_maks + 1):
            for kombinasi in itertools.product(ALFABET_BRUTE, repeat=n):
                tebakan = "".join(kombinasi)
                tabel[sha256_hex(tebakan)] = tebakan
                hitung_hash += 1
        for username, hash_tersimpan in dump:
            if hash_tersimpan in tabel:
                bobol[username] = tabel[hash_tersimpan]
    else:
        for username, salt, hash_tersimpan in dump:
            ditemukan = False
            for n in range(1, panjang_maks + 1):
                if ditemukan:
                    break
                for kombinasi in itertools.product(ALFABET_BRUTE, repeat=n):
                    tebakan = "".join(kombinasi)
                    hitung_hash += 1
                    if sha256_hex(salt + tebakan) == hash_tersimpan:
                        bobol[username] = tebakan
                        ditemukan = True
                        break

    durasi = time.perf_counter() - mulai
    return bobol, hitung_hash, durasi


# ------------------------------------------------------------- pelaporan
def tulis_hasil(baris_csv):
    with open("hasil_serangan.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["skema", "metode", "jumlah_akun", "jumlah_bobol",
                    "persen_bobol", "jumlah_hash_dihitung", "waktu_detik"])
        w.writerows(baris_csv)


def main():
    wordlist = muat_wordlist()
    dump_hash, dump_salted, jawaban_asli = ambil_dump()
    total_akun = len(dump_hash)
    print(f"Memuat {len(wordlist)} kata, {total_akun} akun pada dump.\n")

    skenario = [
        ("hash_saja", "dictionary", lambda: serang_lookup_table(dump_hash, wordlist, bergaram=False)),
        ("hash_salt", "dictionary", lambda: serang_lookup_table(dump_salted, wordlist, bergaram=True)),
        ("hash_saja", "brute_force", lambda: serang_brute_force(dump_hash, bergaram=False)),
        ("hash_salt", "brute_force", lambda: serang_brute_force(dump_salted, bergaram=True)),
    ]

    baris_csv = []
    for skema, metode, fungsi in skenario:
        bobol, hitung_hash, durasi = fungsi()
        benar = sum(1 for u, tebakan in bobol.items() if jawaban_asli.get(u) == tebakan)
        persen = 100 * benar / total_akun
        print(f"[{skema:10s} | {metode:11s}] bobol benar: {benar:2d}/{total_akun} "
              f"({persen:5.1f}%) | hash dihitung: {hitung_hash:>10,} | waktu: {durasi:7.3f} detik")
        baris_csv.append([skema, metode, total_akun, benar, f"{persen:.1f}",
                           hitung_hash, f"{durasi:.3f}"])

    tulis_hasil(baris_csv)
    print("\nHasil lengkap disimpan ke hasil_serangan.csv")


if __name__ == "__main__":
    main()