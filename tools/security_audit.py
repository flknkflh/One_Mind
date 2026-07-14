import sqlite3
import json
import shutil
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DB = ROOT / "data" / "database" / "one_mind.sqlite3"
STORAGE = ROOT / "data" / "storage"
BACKUP = ROOT / "tools" / "backup"

BACKUP.mkdir(exist_ok=True)


# ==========================================================
# Utility
# ==========================================================

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def choose_share():

    conn = db()

    rows = conn.execute("""
        SELECT
            file_id,
            recipient,
            permission
        FROM shares
        ORDER BY file_id
    """).fetchall()

    conn.close()

    if not rows:
        print("\nTidak ada data share.\n")
        return None

    print()

    for i, r in enumerate(rows, 1):

        print(
            f"{i}. "
            f"{r['file_id']}  |  "
            f"{r['recipient']}  |  "
            f"{r['permission']}"
        )

    print()

    idx = int(input("Pilih nomor : "))

    return rows[idx - 1]


def backup_wrapped(file_id, recipient, wrapped_json):

    path = BACKUP / f"{file_id}_{recipient}_wrapped.json"

    with open(path, "w", encoding="utf8") as f:

        f.write(wrapped_json)


def backup_envelope(file_id):

    folder = STORAGE / file_id[:2]

    src = folder / f"{file_id}.json"

    dst = BACKUP / f"{file_id}_envelope.json"

    shutil.copy2(src, dst)


# ==========================================================
# Attack 1
# ==========================================================

def tamper_wrapped():

    import random
    import hashlib

    target = choose_share()

    if target is None:
        return

    conn = db()

    row = conn.execute(
        """
        SELECT wrapped_key
        FROM shares
        WHERE file_id=?
        AND recipient=?
        """,
        (
            target["file_id"],
            target["recipient"]
        )
    ).fetchone()

    if row is None:

        print("\nShare tidak ditemukan.\n")

        conn.close()

        return

    wrapped_json = row["wrapped_key"]

    backup_wrapped(
        target["file_id"],
        target["recipient"],
        wrapped_json
    )

    wrapped = json.loads(wrapped_json)

    # ==========================================
    # Simpan salinan original
    # ==========================================

    original = json.loads(
        json.dumps(wrapped)
    )

    before_hash = hashlib.sha256(
        json.dumps(
            wrapped,
            sort_keys=True
        ).encode()
    ).hexdigest()

    print()
    print("=" * 60)
    print("        WRAPPED KEY TAMPERING")
    print("=" * 60)

    print(f"File ID     : {target['file_id']}")
    print(f"Recipient   : {target['recipient']}")
    print(f"Vector V    : {len(wrapped['V'])} elemen")

    print()
    print("Pilih tingkat serangan")
    print("----------------------")
    print("1. Ringan  (100 elemen +500)")
    print("2. Sedang  (300 elemen XOR)")
    print("3. Berat   (Semua +20000)")
    print("4. Brutal  (Random seluruh V)")
    print()

    mode = input("Mode : ").strip()

    # ==========================================
    # MODE 1
    # ==========================================

    if mode == "1":

        total = min(
            100,
            len(wrapped["V"])
        )

        for i in range(total):

            wrapped["V"][i] += 500

    # ==========================================
    # MODE 2
    # ==========================================

    elif mode == "2":

        total = min(
            300,
            len(wrapped["V"])
        )

        idx = random.sample(
            range(len(wrapped["V"])),
            total
        )

        for i in idx:

            wrapped["V"][i] ^= 0x00FF

    # ==========================================
    # MODE 3
    # ==========================================

    elif mode == "3":

        for i in range(len(wrapped["V"])):

            wrapped["V"][i] += 20000

    # ==========================================
    # MODE 4
    # ==========================================

    elif mode == "4":

        for i in range(len(wrapped["V"])):

            wrapped["V"][i] = random.randint(
                0,
                65535
            )

    else:

        print("\nMode tidak dikenal.\n")

        conn.close()

        return

    # ==========================================
    # HASH SESUDAH DIMODIFIKASI
    # ==========================================

    attack_hash = hashlib.sha256(
        json.dumps(
            wrapped,
            sort_keys=True
        ).encode()
    ).hexdigest()

    # ==========================================
    # UPDATE DATABASE
    # ==========================================

    conn.execute(
        """
        UPDATE shares
        SET wrapped_key=?
        WHERE file_id=?
        AND recipient=?
        """,
        (
            json.dumps(wrapped),
            target["file_id"],
            target["recipient"]
        )
    )

    conn.commit()

    # ==========================================
    # BACA ULANG DATABASE
    # ==========================================

    row = conn.execute(
        """
        SELECT wrapped_key
        FROM shares
        WHERE file_id=?
        AND recipient=?
        """,
        (
            target["file_id"],
            target["recipient"]
        )
    ).fetchone()

    saved = json.loads(row["wrapped_key"])

    conn.close()

    after_hash = hashlib.sha256(
        json.dumps(
            saved,
            sort_keys=True
        ).encode()
    ).hexdigest()

    # ==========================================
    # VERIFIKASI
    # ==========================================

    changed = 0

    for a, b in zip(
        original["V"],
        saved["V"]
    ):

        if a != b:

            changed += 1

    print()
    print("=" * 60)
    print("             VERIFIKASI")
    print("=" * 60)

    print()

    print("Hash Sebelum Attack")
    print(before_hash)

    print()

    print("Hash Setelah Attack")
    print(attack_hash)

    print()

    print("Hash Database")
    print(after_hash)

    print()

    if before_hash == attack_hash:

        print("❌ ATTACK TIDAK MEMODIFIKASI DATA")

    elif attack_hash != after_hash:

        print("❌ DATABASE TIDAK MENYIMPAN PERUBAHAN")

    else:

        print("✅ DATABASE BERHASIL DIMODIFIKASI")

    print()

    print(
        f"Elemen V berubah : "
        f"{changed} / {len(saved['V'])}"
    )

    print()

    print("10 Elemen Pertama")

    print("----------------------")

    for i in range(min(10, len(saved["V"]))):

        print(
            f"{i:>2} : "
            f"{original['V'][i]}"
            f"  -->  "
            f"{saved['V'][i]}"
        )

    print()

    print("=" * 60)

    print("Backup berhasil dibuat.")

    print("Silakan login sebagai RECIPIENT.")

    print("Kemudian coba DOWNLOAD file.")

    print()

    print("Expected Result")

    print("----------------")

    print("Decrypt harus gagal.")

    print("AES-GCM authentication harus gagal.")

    print()

    print("Jika file MASIH berhasil dibuka,")
    print("maka implementasi DIPP perlu diaudit lebih lanjut.")

    print("=" * 60)

    print()
# ==========================================================
# Restore
# ==========================================================

def restore_wrapped():

    import hashlib

    backups = sorted(
        BACKUP.glob("*_wrapped.json")
    )

    if not backups:

        print("\nTidak ada backup.\n")

        return

    print()

    for i, f in enumerate(backups, 1):

        print(f"{i}. {f.name}")

    print()

    idx = int(
        input("Restore nomor : ")
    )

    backup_file = backups[idx - 1]

    name = backup_file.stem.replace(
        "_wrapped",
        ""
    )

    file_id, recipient = name.split(
        "_",
        1
    )

    with open(
        backup_file,
        encoding="utf8"
    ) as f:

        wrapped_json = f.read()

    expected_hash = hashlib.sha256(
        wrapped_json.encode()
    ).hexdigest()

    conn = db()

    conn.execute(
        """
        UPDATE shares
        SET wrapped_key=?
        WHERE file_id=?
        AND recipient=?
        """,
        (
            wrapped_json,
            file_id,
            recipient
        )
    )

    conn.commit()

    row = conn.execute(
        """
        SELECT wrapped_key
        FROM shares
        WHERE file_id=?
        AND recipient=?
        """,
        (
            file_id,
            recipient
        )
    ).fetchone()

    conn.close()

    saved_json = row["wrapped_key"]

    actual_hash = hashlib.sha256(
        saved_json.encode()
    ).hexdigest()

    print()

    print("=" * 60)
    print("RESTORE RESULT")
    print("=" * 60)

    print()

    print("Expected SHA256")

    print(expected_hash)

    print()

    print("Database SHA256")

    print(actual_hash)

    print()

    if expected_hash == actual_hash:

        print("✅ RESTORE BERHASIL")

    else:

        print("❌ RESTORE GAGAL")

    print()

# ==========================================================
# Menu
# ==========================================================

while True:

    print("=" * 60)

    print("      ONE_MIND SECURITY AUDIT")

    print("=" * 60)

    print()

    print("1. Tamper Wrapped Key")

    print("2. Restore Wrapped Key")

    print()

    print("0. Exit")

    print()

    choose = input("Pilih : ")

    if choose == "1":

        tamper_wrapped()

    elif choose == "2":

        restore_wrapped()

    elif choose == "0":

        break