from pathlib import Path
import shutil
import sqlite3

ROOT = Path(__file__).resolve().parent.parent

DB = ROOT / "data" / "database" / "one_mind.sqlite3"

STORAGE = ROOT / "data" / "storage"

TEMP = ROOT / "data" / "temp_uploads"

BACKUP = ROOT / "data" / "backup"


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


def reset_database():

    conn = sqlite3.connect(DB)

    cur = conn.cursor()

    print("Membersihkan tabel...")

    cur.execute("DELETE FROM shares;")

    cur.execute("DELETE FROM files;")

    cur.execute("DELETE FROM upload_sessions;")

    # nanti kalau ada audit log tinggal tambah
    #
    # cur.execute("DELETE FROM audit_log;")

    conn.commit()

    conn.close()


def main():

    print("=" * 60)
    print("ONE_MIND DEMO RESET")
    print("=" * 60)

    reset_database()

    print("Membersihkan Storage...")
    clear_directory(STORAGE)

    print("Membersihkan Temp Upload...")
    clear_directory(TEMP)

    print("Membersihkan Backup...")
    clear_directory(BACKUP)

    print()

    print("SELESAI")

    print()

    print("Data yang dipertahankan:")

    print("  ✓ Users")

    print("  ✓ Password")

    print("  ✓ DIPP")

    print("  ✓ TLS Certificate")

    print("  ✓ Server Secret")

    print()

    print("Data yang dihapus:")

    print("  ✓ Files")

    print("  ✓ Shares")

    print("  ✓ Upload Sessions")

    print("  ✓ Storage")

    print("  ✓ Temp Upload")

    print("  ✓ Backup")


if __name__ == "__main__":

    main()