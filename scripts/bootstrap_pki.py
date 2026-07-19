"""Bootstrap material PKI ke storage runtime yang dikonfigurasi."""

from app.pki.pki import BASE_DIR, initialize_pki


def main() -> None:
    initialize_pki(auto_init=True)
    print(f"PKI runtime tersedia di: {BASE_DIR}")


if __name__ == "__main__":
    main()
