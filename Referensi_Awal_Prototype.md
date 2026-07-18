# Referensi Awal Prototype

Direktori `Referensi_Awal_Prototype/` menyimpan kode eksperimen sebelum sistem disatukan menjadi aplikasi web FastAPI/JavaScript saat ini.

File referensi:

- `Enkripsi_One_Mind_V_1.py`
- `Key_Generator_and_Enkriptor_DIPP_One_Mind_v1.py`
- `Server_One_Mind_Client.py`
- `Server_One_Mind_Server.py`

File tersebut dipertahankan untuk riwayat desain dan pembandingan algoritma. File tersebut:

- bukan entry point deployment Docker saat ini;
- tidak menentukan API, skema database, alur admin/approval, RSA challenge, certificate, atau penyimpanan browser aktual;
- tidak boleh dijadikan dokumentasi operasional produksi;
- dapat memiliki format key/envelope dan asumsi keamanan yang berbeda dari `static/app.js` serta `app/main.py`.

Untuk perilaku sistem aktual, gunakan:

- [README.md](README.md)
- [docs/MANUAL_BOOK.md](docs/MANUAL_BOOK.md)
- [docs/SECURITY.md](docs/SECURITY.md)
- [docs/TLS_MIGRATION.md](docs/TLS_MIGRATION.md)
- [Prompt.md](Prompt.md)

DIPP-KEM tetap merupakan algoritma custom/prototipe dan memerlukan review kriptografi independen sebelum digunakan untuk data sensitif.
