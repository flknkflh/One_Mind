from pathlib import Path
import shutil
import sqlite3

ROOT = Path(__file__).resolve().parent.parent

DB = ROOT / "data" / "database" / "one_mind.sqlite3"

STORAGE = ROOT / "data" / "storage"
TEMP = ROOT / "data" / "temp_uploads"
BACKUP = ROOT / "data" / "backup"

CSR = ROOT / "app" / "pki" / "csr"
ISSUED = ROOT / "app" / "pki" / "issued"
REVOKED = ROOT / "app" / "pki" / "revoked"


# ==========================================================
# Hapus isi folder
# ==========================================================

def clear_directory(folder: Path):

    if not folder.exists():
        return

    for item in folder.iterdir():

        try:

            if item.is_dir():
                shutil.rmtree(item)

            else:
                item.unlink()

        except Exception as e:

            print(f"[WARN] {item} : {e}")


# ==========================================================
# Kosongkan seluruh database
# ==========================================================

def reset_database():

    conn = sqlite3.connect(DB)

    conn.execute("PRAGMA foreign_keys = OFF")

    cur = conn.cursor()

    print("\nMembersihkan database...\n")

    tables = [

        # File System
        "shares",
        "files",
        "upload_sessions",

        # PKI
        "certificate_challenges",
        "certificate_requests",
        "certificates",
        "certificate_revocation",

        # User
        "users"

    ]

    for table in tables:

        try:

            cur.execute(f"DELETE FROM {table};")

            print(f"✓ {table}")

        except Exception as e:

            print(f"✗ {table} : {e}")

    conn.commit()

    conn.execute("PRAGMA foreign_keys = ON")

    conn.close()


# ==========================================================
# MAIN
# ==========================================================

def main():

    print("=" * 60)
    print("ONE_MIND FULL RESET")
    print("=" * 60)

    reset_database()

    print("\nMembersihkan Storage...")
    clear_directory(STORAGE)

    print("Membersihkan Temp Upload...")
    clear_directory(TEMP)

    print("Membersihkan Backup...")
    clear_directory(BACKUP)

    print("Membersihkan CSR...")
    clear_directory(CSR)

    print("Membersihkan Issued Certificate...")
    clear_directory(ISSUED)

    print("Membersihkan Revoked Certificate...")
    clear_directory(REVOKED)

    print("\n================================================")
    print("RESET SELESAI")
    print("================================================")

    print("\nYang TETAP dipertahankan:")

    print("  ✓ Root CA")
    print("  ✓ Intermediate CA")
    print("  ✓ TLS Certificate")
    print("  ✓ Server Secret")

    print("\nYang DIHAPUS:")

    print("  ✓ Users")
    print("  ✓ Certificate Challenges")
    print("  ✓ Certificate Requests")
    print("  ✓ Certificates")
    print("  ✓ Certificate Revocation")
    print("  ✓ Files")
    print("  ✓ Shares")
    print("  ✓ Upload Sessions")
    print("  ✓ Storage")
    print("  ✓ Temp Upload")
    print("  ✓ Backup")
    print("  ✓ CSR")
    print("  ✓ Issued Certificate")
    print("  ✓ Revoked Certificate")

    print("\nSilakan register ulang user dari awal.\n")


if __name__ == "__main__":

    main()