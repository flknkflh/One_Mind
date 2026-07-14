import sqlite3
import json
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "database" / "one_mind.sqlite3"


def main():

    print("=" * 60)
    print(" ONE_MIND - Wrapped Key Tampering Tool")
    print("=" * 60)

    file_id = input("File ID      : ").strip()
    recipient = input("Recipient    : ").strip()

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    row = conn.execute(
        """
        SELECT wrapped_key
        FROM shares
        WHERE file_id = ?
        AND recipient = ?
        """,
        (
            file_id,
            recipient
        )
    ).fetchone()

    if row is None:

        print("\nShare tidak ditemukan.")
        return

    wrapped = json.loads(
        row["wrapped_key"]
    )

    print("\nAlgorithm :", wrapped.get("algorithm"))

    if "V" not in wrapped:

        print("Wrapped key tidak memiliki field V.")
        return

    print("Panjang V :", len(wrapped["V"]))

    original = wrapped["V"][0]

    wrapped["V"][0] = original + 1

    conn.execute(
        """
        UPDATE shares
        SET wrapped_key = ?
        WHERE file_id = ?
        AND recipient = ?
        """,
        (
            json.dumps(wrapped),
            file_id,
            recipient
        )
    )

    conn.commit()

    conn.close()

    print("\nSUCCESS")
    print(f"V[0] : {original} -> {wrapped['V'][0]}")

    print("\nSekarang coba download file menggunakan user tersebut.")
    print("Decrypt HARUS gagal.")


if __name__ == "__main__":
    main()