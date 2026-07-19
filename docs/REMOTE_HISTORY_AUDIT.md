# Audit Riwayat Remote

Tanggal audit: 19 Juli 2026.

Remote yang diperiksa:

```text
https://github.com/flknkflh/One_Mind.git
```

Branch remote aktif:

```text
main
feature/pki-auth-v1.1
production
```

Tidak ada tag pada remote saat audit dilakukan. Pemeriksaan seluruh object yang
masih dapat dijangkau dari ketiga branch tidak menemukan path berikut:

- `data/`, `certs/`, atau `runtime/`;
- direktori material PKI runtime;
- database SQLite;
- private key atau `server_secret.bin`;
- cache Python;
- backup dari security tooling.

Hasil audit:

```text
REMOTE_REACHABLE_HISTORY_CLEAN
```

Audit ini hanya membuktikan kondisi ref remote aktif. Secret lama tetap harus
dianggap pernah terekspos karena dapat berada pada clone, fork, cache, log CI,
atau salinan repository yang dibuat sebelum history rewrite. Seluruh key lama
tetap tidak boleh digunakan kembali.
