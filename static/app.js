const state = {
  token: localStorage.getItem("om_token"),
  username: localStorage.getItem("om_username"),
  adminToken: localStorage.getItem("om_admin_token"),
  adminUsername: localStorage.getItem("om_admin_username"),
  adminSetupRequired: null,
  adminUsers: [],
  adminAccountGroups: {},
  adminCertificateGroups: {},
  files: [],
  users: [],
  fileCatalog: [],
  fileRequests: {incoming: [], outgoing: []},
  pendingUpdateFileId: null,
  fileQuery: "",
  fileScope: "all",
  userQuery: "",
  unlockedPrivateKey: null,
 // keyUnlockedUntil: 0,
 // keyLockTimer: null,
};
let selectedDippFile = null;

const dippSession = {

    privateKey: null,

    publicKey: null,

    username: null,

    runtime: null

};

const rsaEnrollmentSession = {

    privateKey: null,

    publicKey: null,

    username: null

};

const PKI_RSA_BITS = 4096;
const PKI_HASH = "SHA-512";
const enc = new TextEncoder();
const dec = new TextDecoder();
const BACKUP_KEY_ITERATIONS = 600000;
const MAX_FILE_BYTES = 20 * 1024 * 1024 * 1024;
const MAX_INLINE_UPDATE_BYTES = 128 * 1024 * 1024;
const MAX_IDENTITY_FILE_BYTES = 1024 * 1024;
// const SESSION_UNLOCK_MS = 15 * 60 * 1000;
const CHUNK_PROFILES = [

    // ≤10 MB → tidak perlu dipecah (1 chunk)
    {
        maxSize: 10 * 1024 * 1024,
        chunkSize: 10 * 1024 * 1024
    },

    // ≤100 MB → 1 MB/chunk
    {
        maxSize: 100 * 1024 * 1024,
        chunkSize: 1 * 1024 * 1024
    },

    // ≤1 GB → 4 MB/chunk
    {
        maxSize: 1024 * 1024 * 1024,
        chunkSize: 4 * 1024 * 1024
    },

    // ≤10 GB → 8 MB/chunk
    {
        maxSize: 10 * 1024 * 1024 * 1024,
        chunkSize: 8 * 1024 * 1024
    },

    // >10 GB → 16 MB/chunk
    {
        maxSize: Infinity,
        chunkSize: 16 * 1024 * 1024
    }

];

function $(id) { return document.getElementById(id); }

const UI_ERROR_CONTEXT = {
  registerForm: "register",
  loginForm: "login",
  adminSetupForm: "adminSetup",
  adminLoginForm: "adminLogin",
  adminPasswordForm: "changePassword",
  adminAccountGroups: "adminAction",
  refreshAdminBtn: "refresh",
  uploadForm: "upload",
  shareForm: "share",
  fileList: "file",
  refreshFilesBtn: "refresh",
  userList: "fileRequest",
  incomingRequestList: "fileRequest",
  refreshRequestsBtn: "refresh",
  loadAccessBtn: "access",
  rotateKeyBtn: "rotate",
  accessList: "revoke",
  updateFileInput: "update",
  importRsaInput: "keyImport",
  importDippInput: "keyImport",
  exportRsaBtn: "keyExport",
};

function on(id, event, handler) {
  const el = $(id);
  if (!el) return;
  el.addEventListener(event, evt => {
    const form = el instanceof HTMLFormElement
      ? el
      : evt.target?.closest?.("form") || null;
    const isSubmit = event === "submit" && form;
    if (isSubmit) {
      clearFormFeedback(form);
      setFormBusy(form, true);
    }

    let result;
    try {
      result = handler(evt);
    } catch (error) {
      handleUiError(error, {context: UI_ERROR_CONTEXT[id], form});
      if (isSubmit) setFormBusy(form, false);
      return;
    }

    if (result && typeof result.then === "function") {
      result
        .catch(error => handleUiError(
          error,
          {context: UI_ERROR_CONTEXT[id], form}
        ))
        .finally(() => {
          if (isSubmit) setFormBusy(form, false);
        });
    } else if (isSubmit) {
      setFormBusy(form, false);
    }
  });
}

let noticeTimer = null;

function showNotice(message, type = "success", duration = 4200) {
  const notice = $("notice");
  if (!notice) return;
  notice.textContent = message;
  notice.classList.remove("noticeError", "noticeWarning", "noticeInfo");
  if (type === "error") notice.classList.add("noticeError");
  if (type === "warning") notice.classList.add("noticeWarning");
  if (type === "info") notice.classList.add("noticeInfo");
  notice.setAttribute("role", type === "error" ? "alert" : "status");
  notice.setAttribute("aria-live", type === "error" ? "assertive" : "polite");
  notice.classList.remove("hidden");
  if (noticeTimer) clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => notice.classList.add("hidden"), duration);
}

function setFormBusy(form, busy) {
  if (!form) return;
  form.toggleAttribute("aria-busy", busy);
  form.querySelectorAll('button[type="submit"]').forEach(button => {
    button.disabled = busy;
  });
}

function clearFormFeedback(form) {
  form?.querySelector(".formFeedback")?.remove();
}

function showFormFeedback(form, message, type = "error") {
  if (!form) return;
  clearFormFeedback(form);
  const feedback = document.createElement("div");
  feedback.className = `formFeedback ${type === "error" ? "formFeedbackError" : "formFeedbackInfo"}`;
  feedback.setAttribute("role", type === "error" ? "alert" : "status");
  feedback.textContent = message;
  const submitButton = form.querySelector('button[type="submit"]');
  form.insertBefore(feedback, submitButton || null);
  feedback.scrollIntoView({block: "nearest", behavior: "smooth"});
}

class ApiError extends Error {
  constructor(status, detail, path) {
    super(typeof detail === "string" ? detail : `Request gagal (${status}).`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.path = path;
  }
}

function apiErrorFromResponse(response, data, path) {
  return new ApiError(response.status, data?.detail, path);
}

function fieldLabel(field) {
  return ({
    username: "Username",
    password: "Password",
    current_password: "Password saat ini",
    new_password: "Password baru",
    display_name: "Nama lengkap",
    nip: "NIP",
    rank: "Pangkat",
    position: "Jabatan",
    filename: "Nama file",
    recipient: "Penerima",
  })[field] || String(field || "Input").replaceAll("_", " ");
}

function validationMessage(detail) {
  if (!Array.isArray(detail) || !detail.length) return null;
  const issue = detail[0] || {};
  const field = Array.isArray(issue.loc) ? issue.loc.at(-1) : "Input";
  const label = fieldLabel(field);
  const type = String(issue.type || "");
  if (type.includes("missing")) return `${label} wajib diisi.`;
  if (type.includes("too_short")) {
    const minimum = issue.ctx?.min_length;
    return minimum
      ? `${label} minimal ${minimum} karakter.`
      : `${label} terlalu pendek.`;
  }
  if (type.includes("too_long")) {
    const maximum = issue.ctx?.max_length;
    return maximum
      ? `${label} maksimal ${maximum} karakter.`
      : `${label} terlalu panjang.`;
  }
  if (type.includes("greater_than")) return `${label} harus lebih dari nol.`;
  const backendMessage = String(issue.msg || "")
    .replace(/^value error,\s*/i, "")
    .trim();
  if (backendMessage && !/^input should|^field required/i.test(backendMessage)) {
    return backendMessage;
  }
  return `${label} tidak valid. Periksa kembali nilai yang dimasukkan.`;
}

const STATUS_ERROR_MESSAGE = {
  400: "Permintaan tidak valid. Periksa kembali data yang dimasukkan.",
  401: "Autentikasi gagal atau sesi sudah berakhir. Silakan login kembali.",
  403: "Anda tidak memiliki izin untuk melakukan tindakan ini.",
  404: "Data yang diminta tidak ditemukan atau sudah tidak tersedia.",
  409: "Tindakan tidak dapat dilanjutkan karena data sudah berubah atau sudah diproses.",
  413: "Data atau file terlalu besar untuk dikirim.",
  416: "Bagian file yang diminta berada di luar rentang.",
  422: "Data belum lengkap atau format input tidak valid.",
  429: "Terlalu banyak percobaan. Tunggu beberapa menit lalu coba kembali.",
};

const CONTEXT_ERROR_MESSAGE = {
  register: "Registrasi gagal. Periksa data akun lalu coba kembali.",
  login: "Login gagal. Periksa username, password, Identitas DIPP, dan RSA Login Key.",
  adminSetup: "Inisialisasi administrator gagal.",
  adminLogin: "Login administrator gagal. Periksa username dan password.",
  changePassword: "Password belum berhasil diubah. Periksa password saat ini dan password baru.",
  upload: "Upload gagal. File Anda tidak disimpan sebagai file aktif.",
  download: "Download atau dekripsi gagal. Periksa akses dan Identitas DIPP Anda.",
  share: "File belum berhasil dibagikan. Periksa penerima dan kunci yang digunakan.",
  fileRequest: "Permintaan file belum berhasil diproses.",
  access: "Daftar akses belum berhasil dimuat.",
  revoke: "Akses belum berhasil dicabut.",
  rotate: "Rotasi kunci belum berhasil diselesaikan.",
  update: "Update file belum berhasil diselesaikan.",
  keyImport: "File key tidak dapat dimuat. Pastikan file benar dan sesuai dengan akun.",
  keyExport: "File key belum berhasil diekspor.",
  file: "Tindakan pada file belum berhasil diselesaikan.",
  adminAction: "Tindakan administrator belum berhasil diselesaikan.",
  refresh: "Data belum berhasil dimuat ulang. Periksa koneksi lalu coba kembali.",
};

function humanizeServerDetail(detail, context) {
  const message = String(detail || "").trim();
  if (!message) return null;
  if (
    context === "upload"
    && /total_chunks|chunk_index|upload session|folder upload|ukuran chunk|base64 chunk/i.test(message)
  ) {
    return "Upload terputus atau salah satu bagian file tidak konsisten. Pilih file dan ulangi upload.";
  }
  if (/integrity check gagal/i.test(message)) {
    return "Pemeriksaan integritas upload gagal. Ciphertext yang diterima server tidak sama dengan hasil enkripsi browser.";
  }
  if (/wrapped key harus dibuat ulang/i.test(message)) {
    return "Daftar akses berubah saat file diproses. Muat ulang data lalu ulangi update atau rotasi kunci.";
  }
  if (/ciphertext update|metadata chunk|format penyimpanan file/i.test(message)) {
    return CONTEXT_ERROR_MESSAGE[context]
      || "Format file terenkripsi tidak dapat diproses.";
  }
  if (/RSA Public Key user belum tersedia|PKI Public Key belum tersedia/i.test(message)) {
    return "RSA Login Key akun belum terdaftar. Hubungi administrator atau lakukan registrasi ulang sesuai prosedur.";
  }
  if (/Proof of Possession RSA tidak valid/i.test(message)) {
    return "Tanda tangan RSA Login Key tidak valid. Pastikan key tersebut milik akun yang sedang login.";
  }
  return message;
}

function humanizeError(error, context) {
  if (error instanceof ApiError) {
    if (error.status >= 500) {
      return "Server mengalami gangguan saat memproses permintaan. Periksa status terbaru sebelum mencoba kembali.";
    }
    const validation = validationMessage(error.detail);
    if (validation) return validation;
    if (typeof error.detail === "string" && error.detail.trim()) {
      return humanizeServerDetail(error.detail, context);
    }
    return STATUS_ERROR_MESSAGE[error.status]
      || CONTEXT_ERROR_MESSAGE[context]
      || "Permintaan belum berhasil diproses.";
  }

  const name = String(error?.name || "");
  const message = String(error?.message || "").trim();
  if (
    name === "TypeError"
    && /fetch|network|load failed|connection/i.test(message)
  ) {
    return "Tidak dapat terhubung ke server. Periksa jaringan dan koneksi HTTPS, lalu coba kembali.";
  }
  if (name === "OperationError") {
    return context === "download" || context === "rotate" || context === "update"
      ? "Dekripsi gagal. Key tidak cocok, akses sudah berubah, atau ciphertext tidak valid."
      : "Operasi kriptografi gagal. Pastikan file key benar dan sesuai dengan akun.";
  }
  if (name === "DataError" || name === "InvalidCharacterError" || name === "SyntaxError") {
    return CONTEXT_ERROR_MESSAGE[context]
      || "Format data atau file key tidak valid.";
  }
  if (name === "QuotaExceededError" || error instanceof RangeError) {
    return "File terlalu besar untuk diproses di memori browser pada perangkat ini.";
  }
  if (name === "NotAllowedError") {
    return "Operasi dibatalkan atau tidak diizinkan oleh browser.";
  }
  if (/PKI Private Key|RSA Login Private Key/i.test(message)) {
    return "RSA Login Key belum dimuat. Pilih file RSA Login Key yang sesuai dengan akun.";
  }
  if (/Jumlah bit DIPP|Paket kunci DIPP/i.test(message)) {
    return "Data DIPP atau wrapped key tidak konsisten dan tidak dapat digunakan.";
  }
  if (/Metadata download chunk/i.test(message)) {
    return "Informasi download file tidak valid. Muat ulang daftar file lalu coba kembali.";
  }
  if (/SHA-256 ciphertext hasil download tidak cocok/i.test(message)) {
    return "Pemeriksaan integritas gagal. Data hasil download tidak sama dengan file yang tersimpan.";
  }
  if (/Chunk \d+ tidak konsisten|Ukuran ciphertext hasil download/i.test(message)) {
    return "Salah satu bagian file tidak lengkap atau tidak konsisten. Silakan ulangi download.";
  }
  if (/ciphertext harus berupa Uint8Array|chunkSize tidak valid/i.test(message)) {
    return CONTEXT_ERROR_MESSAGE[context]
      || "File tidak dapat diproses oleh browser.";
  }
  if (message && !/^HTTP\s+\d+/i.test(message)) return message;
  return CONTEXT_ERROR_MESSAGE[context] || "Terjadi kesalahan. Silakan coba kembali.";
}

function handleUiError(error, {context = "generic", form = null} = {}) {
  console.error(`[UI:${context}]`, error);
  const message = humanizeError(error, context);
  if (form) {
    showFormFeedback(form, message, "error");
  } else {
    showNotice(message, "error", 7000);
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "\"": "&quot;",
    "'": "&#39;",
  }[ch]));
}

function canEdit(file) {
  return file.permission === "owner" || file.permission === "editor";
}

function canManage(file) {
  return file.permission === "owner" || file.owner === state.username;
}

function normalized(value) {
  return String(value || "").toLowerCase();
}

function bytesToB64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function b64ToBytes(text) {

    const binary = atob(text);

    const out = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        out[i] = binary.charCodeAt(i);
    }

    return out;

}

function chooseChunkSize(fileSize) {

    for (const profile of CHUNK_PROFILES) {

        if (fileSize <= profile.maxSize) {

            if (
                !Number.isFinite(profile.chunkSize) ||
                profile.chunkSize <= 0
            ) {
                return fileSize;
            }

            return Math.min(
                profile.chunkSize,
                fileSize
            );

        }

    }

    return Math.min(
        16 * 1024 * 1024,
        fileSize
    );

}

async function splitFileIntoChunks(file) {

    const chunkSize = chooseChunkSize(file.size);

    // File kecil → upload biasa
    if (chunkSize === null) {
        return [{
            index: 0,
            total: 1,
            size: file.size,
            blob: file
        }];
    }

    const chunks = [];
    let offset = 0;
    let index = 0;

    while (offset < file.size) {

        const end = Math.min(offset + chunkSize, file.size);

        chunks.push({
            index,
            total: Math.ceil(file.size / chunkSize),
            size: end - offset,
            blob: file.slice(offset, end)
        });

        offset = end;
        index++;
    }

    return chunks;
}

async function analyzeFileForUpload(file) {

    const chunks = await splitFileIntoChunks(file);

    return {
        fileName: file.name,
        fileSize: file.size,
        chunkSize: chooseChunkSize(file.size),
        totalChunks: chunks.length,
        chunks
    };
}

async function api(path, options = {}) {

    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    if (state.token) {
        headers.Authorization = `Bearer ${state.token}`;
    }

    const res = await fetch(
        path,
        {
            ...options,
            headers
        }
    );

    const data = await res.json().catch(() => ({}));


    if (!res.ok) {

      console.error("HTTP ERROR", res.status);

      console.error(data);

      throw apiErrorFromResponse(res, data, path);

    }

    return data;

}

async function apiBinary(path) {
  const headers = {};
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, {headers});
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw apiErrorFromResponse(response, data, path);
  }
  return {
    bytes: new Uint8Array(await response.arrayBuffer()),
    headers: response.headers,
  };
}

async function pendingLoginApi(
    path,
    loginToken,
    options = {}
) {
    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {}),
        Authorization: `Bearer ${loginToken}`
    };

    const res = await fetch(path, {
        ...options,
        headers
    });

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
        throw apiErrorFromResponse(res, data, path);
    }

    return data;
}

async function adminApi(path, options = {}) {

    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    if (state.adminToken) {
        headers.Authorization = `Bearer ${state.adminToken}`;
    }

    const res = await fetch(
        path,
        {
            ...options,
            headers
        }
    );

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {

        if (res.status === 401 && state.adminToken) {
            clearAdminSession();
            renderAuth();
            refreshAdminSetupStatus();
        }

        throw apiErrorFromResponse(res, data, path);
    }

    return data;

}


const DIPP_ALGORITHM_NAME = "DIPP Ephemeral-R Standalone";
const DIPP_VERSION = 7;
const DIPP_PARAMS = OneMindDippEphemeralR.PARAMS;

function rejectLegacyDippCall() {
  throw new Error("DIPP legacy ditolak. Gunakan Ephemeral-R DIPP v1.");
}

async function generatePKIKeypair() {

    const pair = await crypto.subtle.generateKey(

        {

            name: "RSASSA-PKCS1-v1_5",

            modulusLength: PKI_RSA_BITS,

            publicExponent: new Uint8Array([1, 0, 1]),

            hash: PKI_HASH

        },

        true,

        [

            "sign",

            "verify"

        ]

    );

    rsaEnrollmentSession.privateKey = pair.privateKey;

    rsaEnrollmentSession.publicKey = pair.publicKey;

    rsaEnrollmentSession.username = state.username;

    return pair;

}

function arrayBufferToBase64(buffer) {

    const bytes = new Uint8Array(buffer);

    let binary = "";

    for (const b of bytes) {
        binary += String.fromCharCode(b);
    }

    return btoa(binary);

}

function base64ToArrayBuffer(base64) {

    const binary = atob(base64);

    const bytes = new Uint8Array(
        binary.length
    );

    for (let i = 0; i < binary.length; i++) {

        bytes[i] =
            binary.charCodeAt(i);

    }

    return bytes.buffer;

}

async function signChallenge(nonceHex) {

    if (!rsaEnrollmentSession.privateKey) {
        throw new Error("PKI Private Key belum tersedia.");
    }

    const nonceBytes = new TextEncoder().encode(nonceHex);

    const signature = await crypto.subtle.sign(
        {
            name: "RSASSA-PKCS1-v1_5"
        },
        rsaEnrollmentSession.privateKey,
        nonceBytes
    );

    return arrayBufferToBase64(signature);

}

async function exportPKIPrivateKey() {

    if (!rsaEnrollmentSession.privateKey) {

        throw new Error(
            "PKI Private Key belum tersedia."
        );

    }

    const pkcs8 = await crypto.subtle.exportKey(

        "pkcs8",

        rsaEnrollmentSession.privateKey

    );

    return new Uint8Array(pkcs8);

}


async function exportRSAEnrollmentKey(
    username
) {

    if (!rsaEnrollmentSession.privateKey) {

        throw new Error(
            "RSA Login Private Key belum tersedia."
        );

    }

    const privateKey =
        await exportPKIPrivateKey();

    const identity = {

        version: 1,

        type: "ONE_MIND_RSA_ENROLLMENT",

        username,

        created_at:
            new Date().toISOString(),

        public_key:
            await exportPKIPublicKey(),

        private_key:
            arrayBufferToBase64(
                privateKey.buffer
            )

    };

    const blob = new Blob(

        [
            JSON.stringify(
                identity,
                null,
                2
            )
        ],

        {
            type:
                "application/json"
        }

    );

    const url =
        URL.createObjectURL(
            blob
        );

    const a =
        document.createElement(
            "a"
        );

    a.href = url;

    a.download =
        `ONE_MIND_RSA_${username}.key`;

    a.click();

    URL.revokeObjectURL(
        url
    );

}

function pemToArrayBuffer(
    pem
) {

    const base64 = pem

        .replace(
            "-----BEGIN PUBLIC KEY-----",
            ""
        )

        .replace(
            "-----END PUBLIC KEY-----",
            ""
        )

        .replace(/\s/g, "");

    return base64ToArrayBuffer(
        base64
    );

}


async function requestRSAEnrollmentKey(
    expectedUsername
) {
    return new Promise((resolve, reject) => {
        const input = document.createElement("input");
        input.type = "file";
        input.accept = ".key";

        input.onchange = async () => {
            const file = input.files?.[0];

            if (!file) {
                reject(new Error("RSA Login Key tidak dipilih."));
                return;
            }

            try {
                await importRSAEnrollmentKey(file, expectedUsername);
                resolve();
            }
            catch (err) {
                reject(err);
            }
        };

        input.click();
    });
}


async function importRSAEnrollmentKey(
    file,
    expectedUsername = state.username
) {

    if (!file || file.size > MAX_IDENTITY_FILE_BYTES) {
        throw new Error("File RSA Login melebihi batas 1 MiB.");
    }

    const text =
        await file.text();

    const identity =
        JSON.parse(text);

    if (
        identity.type !==
        "ONE_MIND_RSA_ENROLLMENT"
    ) {

        throw new Error(
            "File RSA Login tidak valid."
        );

    }

    if (
        expectedUsername &&
        identity.username !== expectedUsername
    ) {
        throw new Error(
            "RSA Login Key bukan milik user ini."
        );
    }

    if (
        !identity.private_key
    ) {

        throw new Error(
            "Private Key tidak ditemukan pada RSA Login Key."
        );

    }

    if (
        !identity.public_key
    ) {

        throw new Error(
            "Public Key tidak ditemukan pada RSA Login Key."
        );

    }

    const privateKey =
        await crypto.subtle.importKey(

            "pkcs8",

            base64ToArrayBuffer(
                identity.private_key
            ),

            {

                name:
                    "RSASSA-PKCS1-v1_5",

                hash:
                    PKI_HASH

            },

            true,

            [

                "sign"

            ]

        );

    const publicKey =
        await crypto.subtle.importKey(

            "spki",

            pemToArrayBuffer(
                identity.public_key
            ),

            {

                name:
                    "RSASSA-PKCS1-v1_5",

                hash:
                    PKI_HASH

            },

            true,

            [

                "verify"

            ]

        );

    rsaEnrollmentSession.privateKey =
        privateKey;

    rsaEnrollmentSession.publicKey =
        publicKey;

    rsaEnrollmentSession.username =
        identity.username;

}


function dippWrapBytes() { return rejectLegacyDippCall(); }
function dippUnwrapBytes() { return rejectLegacyDippCall(); }

async function exportPKIPublicKey() {

    if (!rsaEnrollmentSession.publicKey) {
        throw new Error("PKI Public Key belum tersedia.");
    }

    const spki = await crypto.subtle.exportKey(
        "spki",
        rsaEnrollmentSession.publicKey
    );

    const bytes = new Uint8Array(spki);

    let binary = "";

    for (const b of bytes) {
        binary += String.fromCharCode(b);
    }

    const base64 = btoa(binary);

    const lines = base64.match(/.{1,64}/g).join("\n");

    return (
        "-----BEGIN PUBLIC KEY-----\n" +
        lines +
        "\n-----END PUBLIC KEY-----"
    );

}

function dippVaultCacheKey(username) {
  return `om_dipp_ephemeral_r_vault_${username}`;
}

function downloadDippPackage(username, packageValue) {
  downloadJson(`ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE_${username}.dipp`, packageValue);
}

async function persistCurrentDippVault() {
  if (!dippSession.privateKey || !dippSession.username) return;
  const sealed = await OneMindDippEphemeralR.sealIdentity(dippSession.privateKey);
  localStorage.setItem(
    dippVaultCacheKey(dippSession.username),
    JSON.stringify(sealed)
  );
}

function activateDippIdentity(identity) {
  dippSession.privateKey = identity;
  dippSession.publicKey = identity.public;
  dippSession.username = identity.username;
  dippSession.runtime = null;
  state.unlockedPrivateKey = identity;
  updateLocalKeyStatus();
  return identity;
}

async function exportDippIdentity(username, dipp) {
  if (!dipp || dipp.username !== username) {
    throw new Error("Vault DIPP aktif tidak cocok dengan user.");
  }
  const sealed = await OneMindDippEphemeralR.sealIdentity(dipp);
  localStorage.setItem(dippVaultCacheKey(username), JSON.stringify(sealed));
  downloadDippPackage(username, sealed);
}

async function importDippIdentity(file, username, password) {
  if (!password) throw new Error("Password diperlukan untuk membuka vault DIPP.");
  if (!file || file.size > MAX_IDENTITY_FILE_BYTES) throw new Error("File vault DIPP melebihi batas 1 MiB.");
  const filePackage = JSON.parse(await file.text());
  let identity = await OneMindDippEphemeralR.openIdentity(filePackage, username, password);

  const cachedText = localStorage.getItem(dippVaultCacheKey(username));
  if (cachedText) {
    try {
      const cachedPackage = JSON.parse(cachedText);
      const samePublicIdentity = JSON.stringify(cachedPackage.public_key)
        === JSON.stringify(filePackage.public_key);
      if (samePublicIdentity) {
        identity = await OneMindDippEphemeralR.openIdentity(cachedPackage, username, password);
      }
    } catch (error) {
      console.warn("Cache vault DIPP terenkripsi tidak dapat dibuka; memakai file import.", error);
    }
  }

  return activateDippIdentity(identity);
}

function hasLocalPrivateKey(username = state.username) {

    return Boolean(
        dippSession.privateKey &&
        dippSession.username === username
    );

}

async function ensureUnlockedPrivateKey() {

    if (state.unlockedPrivateKey) {

        return state.unlockedPrivateKey;

    }

    throw new Error(
        "Private Key DIPP belum diimport. Silakan import file .dipp terlebih dahulu."
    );

}

function updateLocalKeyStatus() {

    const status =
        $("localKeyStatus");

    if (!status)
        return;

    if (!state.username) {

        status.textContent =
            "Belum login.";

        return;

    }

    const loaded =
        Boolean(
            dippSession.privateKey
        );

    if (!loaded) {

        status.textContent =
            "Vault DIPP Ephemeral-R belum dibuka.";

        status.className =
            "keyStatus missing";

    }

    else {

        status.textContent =
            "Vault DIPP Ephemeral-R terenkripsi berhasil dibuka; state aktif berada di RAM.";

        status.className =
            "keyStatus unlocked";

    }

}

function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}


async function wrapFileKey(fileKey, recipientPublicKey, fileContextId) {
  if (!fileContextId) throw new Error("file_context_id diperlukan untuk pembungkus DIPP.");
  const identity = await ensureUnlockedPrivateKey();
  OneMindDippEphemeralR.validatePublicKey(recipientPublicKey);
  if (!rsaEnrollmentSession.privateKey || rsaEnrollmentSession.username !== identity.username) {
    throw new Error("RSA Login Key aktif diperlukan untuk menandatangani transcript Ephemeral-R.");
  }
  const rawFileKey = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
  try {
    return await OneMindDippEphemeralR.wrapFileKey(recipientPublicKey, rawFileKey, {
      file_context_id: fileContextId,
      sender_id: identity.username,
      recipient_id: recipientPublicKey.user_id,
    }, async transcriptHash => new Uint8Array(await crypto.subtle.sign(
      {name: "RSASSA-PKCS1-v1_5"},
      rsaEnrollmentSession.privateKey,
      transcriptHash
    )));
  } finally {
    rawFileKey.fill(0);
  }
}

async function unwrapFileKey(wrapped, privateKey) {
  if (!privateKey) throw new Error("Vault DIPP Ephemeral-R belum dibuka.");
  OneMindDippEphemeralR.validateEnvelope(wrapped);
  const senderPki = await api(
    `/api/users/${encodeURIComponent(wrapped.sender_id)}/pki-public-key`
  );
  const signingKey = await crypto.subtle.importKey(
    "spki",
    pemToArrayBuffer(senderPki.pki_public_key),
    {name: "RSASSA-PKCS1-v1_5", hash: PKI_HASH},
    false,
    ["verify"]
  );
  const raw = await OneMindDippEphemeralR.unwrapFileKey(
    privateKey,
    wrapped,
    (hash, signature) => crypto.subtle.verify(
      {name: "RSASSA-PKCS1-v1_5"},
      signingKey,
      signature,
      hash
    )
  );
  try {
    return await crypto.subtle.importKey("raw", raw, {name: "AES-GCM"}, true, ["encrypt", "decrypt"]);
  } finally {
    raw.fill(0);
  }
}

async function encryptBlob(blob, fileName, mimeType, key = null) {

    if (!key) {
        key = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,
            ["encrypt", "decrypt"]
        );
    }

    const iv = crypto.getRandomValues(
        new Uint8Array(12)
    );

    const data = new Uint8Array(
        await blob.arrayBuffer()
    );

    const aad = enc.encode(
        JSON.stringify({
            filename: fileName,
            type: mimeType || "application/octet-stream"
        })
    );

    const cipher = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
            additionalData: aad
        },
        key,
        data
    );

    const ciphertext = new Uint8Array(cipher);

    // ===== BARU =====

    const digest = await crypto.subtle.digest(
        "SHA-256",
        ciphertext
    );

    const ciphertext_sha256 = bytesToB64(
        new Uint8Array(digest)
    );

    // ================

    return {

        key,

        envelope: {

            version: 2,

            algorithm: "AES-256-GCM",

            protocol_version: "ONE_MIND_DIPP_EPHEMERAL_R_WEIGHTED_V2",

            file_context_id: OneMindDippEphemeralR.b64url(
                crypto.getRandomValues(new Uint8Array(24))
            ),

            filename: fileName,

            mime: mimeType || "application/octet-stream",

            aad_b64: bytesToB64(aad),

            iv_b64: bytesToB64(iv)

        },

        ciphertext,

        ciphertext_sha256

    };

}

async function encryptFile(file) {
    return encryptBlob(
        file,
        file.name,
        file.type || "application/octet-stream"
    );
}

function splitCiphertext(
    ciphertext,
    chunkSize
) {

    if (!(ciphertext instanceof Uint8Array)) {
        throw new Error(
            "ciphertext harus berupa Uint8Array."
        );
    }

    if (
        !Number.isFinite(chunkSize) ||
        chunkSize <= 0
    ) {
        throw new Error(
            `chunkSize tidak valid: ${chunkSize}`
        );
    }

    const chunks = [];

    const totalChunks = Math.ceil(
        ciphertext.length / chunkSize
    );

    for (
        let index = 0, offset = 0;
        offset < ciphertext.length;
        index++, offset += chunkSize
    ) {

        const end = Math.min(
            offset + chunkSize,
            ciphertext.length
        );

        chunks.push({

            index,

            total: totalChunks,

            bytes: ciphertext.slice(
                offset,
                end
            )

        });

    }

    return chunks;

}

async function uploadCiphertext(
    encrypted,
    wrappedKey,
    file
) {

    const chunkSize =
        chooseChunkSize(
            encrypted.ciphertext.length
        );

    const chunks =
        splitCiphertext(
            encrypted.ciphertext,
            chunkSize
        );

    const session =
        await api(
            "/api/upload/start",
            {
                method: "POST",
                body: JSON.stringify({

                    filename: file.name,

                    file_size: encrypted.ciphertext.length,

                    chunk_size: chunkSize,

                    total_chunks: chunks.length

                })
            }
        );

    return {

        session,

        chunks

    };

}

async function uploadChunks(session, chunks) {
    const totalBytes = chunks.reduce(
        (total, chunk) => total + chunk.bytes.length,
        0
    );
    let uploadedBytes = 0;

    for (const chunk of chunks) {
        await api(
            "/api/upload/chunk",
            {
                method: "POST",
                body: JSON.stringify({
                    upload_id: session.upload_id,
                    chunk_index: chunk.index,
                    total_chunks: chunk.total,
                    data_b64: bytesToB64(chunk.bytes)
                })
            }
        );

        uploadedBytes += chunk.bytes.length;
        const percent = Math.floor((uploadedBytes / totalBytes) * 100);
        setUploadProgress(
            `Mengirim chunk ${chunk.index + 1} dari ${chunk.total} - ${percent}%`,
            percent
        );

    }
}

async function uploadFinish(
    session,
    encrypted,
    wrappedKey,
    isHidden
) {

    return await api(
        "/api/upload/finish",
        {
            method: "POST",
            body: JSON.stringify({

                upload_id: session.upload_id,

                envelope: encrypted.envelope,

                wrapped_key_for_owner: wrappedKey,

                is_hidden: isHidden,

                ciphertext_sha256:
                    encrypted.ciphertext_sha256

            })
        }
    );
}

function setUploadProgress(message, percent = null) {
  const root = $("uploadProgress");
  const bar = $("uploadProgressBar");
  const text = $("uploadProgressText");
  root?.classList.remove("hidden");
  if (text) text.textContent = message;
  if (bar) {
    if (percent === null) {
      bar.removeAttribute("value");
    } else {
      bar.value = Math.max(0, Math.min(100, percent));
    }
  }
}

function clearUploadProgress() {
  $("uploadProgress")?.classList.add("hidden");
}

function setDownloadProgress(received, total, chunkIndex, totalChunks) {
  const root = $("downloadProgress");
  const bar = $("downloadProgressBar");
  const text = $("downloadProgressText");
  const percent = total > 0 ? Math.floor((received / total) * 100) : 0;
  root?.classList.remove("hidden");
  if (bar) bar.value = percent;
  if (text) {
    text.textContent = `Mengambil chunk ${chunkIndex + 1} dari ${totalChunks} - ${percent}%`;
  }
}

function clearDownloadProgress() {
  $("downloadProgress")?.classList.add("hidden");
}

async function fetchCiphertextChunks(file) {
  const descriptor = file.download || {};
  const totalChunks = Number(descriptor.total_chunks);
  const chunkSize = Number(descriptor.chunk_size);
  const ciphertextSize = Number(descriptor.ciphertext_size);

  if (
    descriptor.storage_format !== "chunked-v1" ||
    !Number.isSafeInteger(totalChunks) || totalChunks <= 0 ||
    !Number.isSafeInteger(chunkSize) || chunkSize <= 0 ||
    !Number.isSafeInteger(ciphertextSize) || ciphertextSize <= 0
  ) {
    throw new Error("Metadata download chunk tidak valid.");
  }

  const ciphertext = new Uint8Array(ciphertextSize);
  let offset = 0;
  for (let index = 0; index < totalChunks; index++) {
    let chunkResult = null;
    let lastError = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        chunkResult = await apiBinary(`/api/files/${file.id}/chunks/${index}`);
        break;
      } catch (err) {
        lastError = err;
        if (err.status && err.status < 500 && err.status !== 429) {
          throw err;
        }
      }
    }
    if (!chunkResult) {
      throw new Error(
        `Gagal mengambil chunk ${index + 1} setelah 3 percobaan: ${lastError?.message || "error"}`
      );
    }

    const expectedSize = Math.min(chunkSize, ciphertextSize - offset);
    const headerIndex = Number(chunkResult.headers.get("X-Chunk-Index"));
    const headerTotal = Number(chunkResult.headers.get("X-Total-Chunks"));
    const headerCiphertextSize = Number(
      chunkResult.headers.get("X-Ciphertext-Size")
    );
    if (
      chunkResult.bytes.length !== expectedSize ||
      headerIndex !== index ||
      headerTotal !== totalChunks ||
      headerCiphertextSize !== ciphertextSize
    ) {
      throw new Error(`Chunk ${index + 1} tidak konsisten dengan metadata file.`);
    }
    ciphertext.set(chunkResult.bytes, offset);
    offset += chunkResult.bytes.length;
    setDownloadProgress(offset, ciphertextSize, index, totalChunks);
  }

  if (offset !== ciphertextSize) {
    throw new Error("Ukuran ciphertext hasil download tidak sesuai metadata.");
  }
  const digest = bytesToB64(
    new Uint8Array(await crypto.subtle.digest("SHA-256", ciphertext))
  );
  if (digest !== descriptor.ciphertext_sha256) {
    throw new Error("SHA-256 ciphertext hasil download tidak cocok.");
  }
  return ciphertext;
}

async function decryptEnvelope(envelope, key, ciphertext) {
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: b64ToBytes(envelope.iv_b64), additionalData: b64ToBytes(envelope.aad_b64)},
    key,
    ciphertext
  );
  return new Blob([plain], {type: envelope.mime || "application/octet-stream"});
}

async function getFileKey(fileId) {

    const file =
        await api(`/api/files/${fileId}`);

    const privateKey =
        await ensureUnlockedPrivateKey();

    const fileKey =
        await unwrapFileKey(
            file.wrapped_key,
            privateKey
        );

    return {

        file,

        fileKey

    };

}

async function wrapKeyForAccess(fileKey, fileId, fileContextId) {
  const access = await api(`/api/files/${fileId}/access`);
  const wrapped_keys = [];
  for (const entry of access) {
    wrapped_keys.push({
      recipient: entry.username,
      wrapped_key: await wrapFileKey(fileKey, entry.public_key, fileContextId),
    });
  }
  return wrapped_keys;
}

async function renderAccess(fileId) {
  const list = $("accessList");
  if (!list) return;
  const access = await api(`/api/files/${fileId}/access`);
  list.innerHTML = "";
  if (!access.length) {
    list.innerHTML = `<div class="emptyState"><strong>Belum ada akses</strong></div>`;
    return;
  }
  for (const entry of access) {
    const row = document.createElement("div");
    row.className = "item compact";
    const revokeButton = entry.permission === "owner" ? "" : `<button class="danger" data-revoke="${entry.username}" data-file="${fileId}">Cabut</button>`;
    row.innerHTML = `
      <div>
        <strong>${escapeHtml(entry.display_name)} (${escapeHtml(entry.username)})</strong>
        <span class="meta">Role: ${escapeHtml(entry.permission)}</span>
      </div>
      <div class="itemActions">${revokeButton}</div>
    `;
    list.appendChild(row);
  }
}

async function renameFile(fileId) {
  const file = state.files.find(f => f.id === fileId);
  const nextName = prompt("Nama file baru:", file?.filename || "");
  if (!nextName) return;
  await api(`/api/files/${fileId}`, {method: "PATCH", body: JSON.stringify({filename: nextName})});
  await refreshAll();
  showNotice("Nama file berhasil diupdate.");
}

async function deleteFile(fileId) {
  const file = state.files.find(f => f.id === fileId);
  if (!confirm(`Hapus file "${file?.filename || fileId}" untuk semua user?`)) return;
  await api(`/api/files/${fileId}`, {method: "DELETE"});
  await refreshAll();
  showNotice("File berhasil dihapus.");
}

async function updateFileWithRotation(fileId, replacementFile) {

    if (!replacementFile || !replacementFile.size)
        return;
    if (replacementFile.size + 16 > MAX_INLINE_UPDATE_BYTES) {
        throw new Error("Update langsung dibatasi 128 MiB. Upload sebagai file baru untuk ukuran lebih besar.");
    }

    const current = await getFileKey(fileId);

    const currentCiphertext = await fetchCiphertextChunks(current.file);

    await decryptEnvelope(
        current.file.envelope,
        current.fileKey,
        currentCiphertext
    );

    const encrypted = await encryptFile(
        replacementFile
    );

    encrypted.envelope.ciphertext_b64 =
        bytesToB64(encrypted.ciphertext);

    encrypted.envelope.file_id =
        current.file.envelope.file_id;

    encrypted.envelope.uploaded_at =
        current.file.envelope.uploaded_at;

    encrypted.envelope.version =
        (current.file.envelope.version || 1) + 1;

    const wrapped_keys =
        await wrapKeyForAccess(
            encrypted.key,
            fileId,
            encrypted.envelope.file_context_id
        );

    await api(
        `/api/files/${fileId}`,
        {
            method: "PUT",
            body: JSON.stringify({
                filename: replacementFile.name,
                envelope: encrypted.envelope,
                wrapped_keys
            })
        }
    );

    await refreshAll();

    showNotice("Update selesai.");
}

async function rotateCurrentFileKey(fileId) {

    const current = await getFileKey(fileId);

    const currentCiphertext = await fetchCiphertextChunks(current.file);

    if (currentCiphertext.length > MAX_INLINE_UPDATE_BYTES) {
        throw new Error("Rotasi langsung dibatasi 128 MiB. Gunakan upload ulang untuk file lebih besar.");
    }

    const blob = await decryptEnvelope(
        current.file.envelope,
        current.fileKey,
        currentCiphertext
    );

    const sameFile = new File(
        [blob],
        current.file.filename,
        {
            type: current.file.envelope.mime || "application/octet-stream"
        }
    );

    const encrypted = await encryptFile(
        sameFile
    );

    encrypted.envelope.ciphertext_b64 =
        bytesToB64(
            encrypted.ciphertext
        );

    // =====================================
    // Pertahankan Identitas File
    // =====================================

    encrypted.envelope.file_id =
        current.file.envelope.file_id;

    encrypted.envelope.version =
        (current.file.envelope.version || 1) + 1;

    encrypted.envelope.uploaded_at =
        current.file.envelope.uploaded_at;

    // =====================================

    const wrapped_keys = await wrapKeyForAccess(
        encrypted.key,
        fileId,
        encrypted.envelope.file_context_id
    );

    await api(
        `/api/files/${fileId}`,
        {
            method: "PUT",
            body: JSON.stringify({
                filename: current.file.filename,
                envelope: encrypted.envelope,
                wrapped_keys
            })
        }
    );

    await refreshAll();

    await renderAccess(fileId);

    showNotice(
        `AES Key berhasil dirotasi.\n\nVersi file sekarang: ${encrypted.envelope.version}`
    );

}

function renderAuth() {

    const loggedIn = Boolean(state.token);
    const adminLoggedIn = Boolean(state.adminToken);

    $("authView")?.classList.toggle("hidden", loggedIn || adminLoggedIn);

    $("appView")?.classList.toggle("hidden", !loggedIn || adminLoggedIn);

    $("adminView")?.classList.toggle("hidden", !adminLoggedIn);

    $("logoutBtn")?.classList.toggle("hidden", !loggedIn || adminLoggedIn);

    $("adminLogoutBtn")?.classList.toggle("hidden", !adminLoggedIn);

    if ($("sessionText")) {
        $("sessionText").textContent = adminLoggedIn
            ? `Admin: ${state.adminUsername}`
            : loggedIn
            ? `Login sebagai ${state.username}`
            : "Belum login";
    }

    if (loggedIn && !adminLoggedIn) {

        // Sembunyikan semua tab
        document.querySelectorAll(".tab").forEach(tab => {
            tab.classList.add("hidden");
        });

        // Reset tombol aktif
        document.querySelectorAll(".tabs button").forEach(btn => {
            btn.classList.remove("active");
        });

        // Aktifkan File Saya sebagai tab default
        $("filesTab")?.classList.remove("hidden");

        document
            .querySelector('[data-tab="files"]')
            ?.classList.add("active");

    }

    updateLocalKeyStatus();

}

function resetAuthInputs() {

    $("registerForm")?.reset();

    $("loginForm")?.reset();

    selectedDippFile = null;

}

function resetAdminInputs() {

    $("adminSetupForm")?.reset();

    $("adminLoginForm")?.reset();

    $("adminPasswordForm")?.reset();

}

function clearAdminSession() {

    localStorage.removeItem("om_admin_token");

    localStorage.removeItem("om_admin_username");

    state.adminToken = null;

    state.adminUsername = null;

    state.adminUsers = [];

    state.adminAccountGroups = {};

    state.adminCertificateGroups = {};

}

function renderAdminAuth() {

    const setupBox = $("adminSetupBox");

    const loginForm = $("adminLoginForm");

    if (!setupBox || !loginForm)
        return;

    setupBox.classList.toggle(
        "hidden",
        state.adminSetupRequired !== true
    );

    loginForm.classList.toggle(
        "hidden",
        state.adminSetupRequired !== false
    );

}

async function refreshAdminSetupStatus() {

    if (state.adminToken) {
        return;
    }

    const status = await adminApi(
        "/api/admin/setup-status"
    );

    state.adminSetupRequired =
        Boolean(status.setup_required);

    renderAdminAuth();

}

function adminUserActions(user) {

    const username =
        escapeHtml(user.username);

    if (user.account_status === "DELETED") {
        return [
            `<button class="ghost" data-admin-action="restore" data-admin-user="${username}">Restore</button>`
        ].join("");
    }

    return [
        `<button class="ghost" data-admin-edit="${username}">Edit</button>`,
        user.account_status === "PENDING"
            ? `<button data-admin-action="approve" data-admin-user="${username}">Approve</button>`
            : "",
        user.account_status === "PENDING"
            ? `<button class="ghost" data-admin-action="reject" data-admin-user="${username}">Reject</button>`
            : "",
        user.account_status === "ACTIVE"
            ? `<button class="ghost" data-admin-action="revoke" data-admin-user="${username}">Revoke</button>`
            : "",
        user.account_status === "REJECTED"
            ? `<button class="ghost" data-admin-action="restore" data-admin-user="${username}">Restore</button>`
            : "",
        user.account_status !== "DELETED"
            ? `<button class="danger" data-admin-action="soft-delete" data-admin-user="${username}">Soft Delete</button>`
            : ""
    ].join("");

}

function renderAdminUser(user) {

    const row =
        document.createElement("div");

    row.className =
        "item adminUserItem";

    row.innerHTML = `
        <div>
            <strong>${escapeHtml(user.display_name)} (${escapeHtml(user.username)})</strong>
            <div class="adminUserMeta">
                <span>NIP: ${escapeHtml(user.nip || "-")}</span>
                <span>Pangkat: ${escapeHtml(user.rank || "-")}</span>
                <span>Jabatan: ${escapeHtml(user.position || "-")}</span>
                <span>Akun: <b>${escapeHtml(user.account_status)}</b></span>
                <span>Certificate: <b>${escapeHtml(user.certificate_status)}</b></span>
                <span>DIPP: ${user.has_dipp_public_key ? "Public key ada" : "Belum ada"}</span>
                <span>PKI: ${user.has_pki_public_key ? "Public key ada" : "Belum ada"}</span>
            </div>
        </div>
        <div class="itemActions">
            ${adminUserActions(user)}
        </div>
    `;

    return row;

}

function renderAdminDashboard() {

    const accountRoot =
        $("adminAccountGroups");

    const certificateRoot =
        $("adminCertificateGroups");

    if (!accountRoot || !certificateRoot)
        return;

    const pending =
        state.adminAccountGroups.PENDING || [];

    const active =
        state.adminAccountGroups.ACTIVE || [];

    const rejected =
        state.adminAccountGroups.REJECTED || [];

    const deleted =
        state.adminAccountGroups.DELETED || [];

    if ($("adminPendingCount"))
        $("adminPendingCount").textContent = String(pending.length);

    if ($("adminActiveCount"))
        $("adminActiveCount").textContent = String(active.length);

    if ($("adminRejectedCount"))
        $("adminRejectedCount").textContent = String(rejected.length);

    if ($("adminDeletedCount"))
        $("adminDeletedCount").textContent = String(deleted.length);

    accountRoot.innerHTML = "";

    for (const status of ["PENDING", "ACTIVE", "REJECTED", "DELETED"]) {

        const group =
            state.adminAccountGroups[status] || [];

        const section =
            document.createElement("section");

        section.className =
            "lifecycleSection";

        section.innerHTML = `
            <div class="lifecycleHead">
                <h3>${status}</h3>
                <span class="statusBadge">${group.length}</span>
            </div>
            <div class="list"></div>
        `;

        const list =
            section.querySelector(".list");

        if (!group.length) {
            list.innerHTML =
                `<div class="emptyState"><strong>Tidak ada user ${status}</strong></div>`;
        } else {
            for (const user of group) {
                list.appendChild(
                    renderAdminUser(user)
                );
            }
        }

        accountRoot.appendChild(section);

    }

    certificateRoot.innerHTML = "";

    for (const status of ["NONE", "ISSUED", "REVOKED", "EXPIRED", "REPLACED"]) {

        const group =
            state.adminCertificateGroups[status] || [];

        const item =
            document.createElement("div");

        item.className =
            "statusCard";

        item.innerHTML = `
            <span>${status}</span>
            <strong>${group.length}</strong>
        `;

        certificateRoot.appendChild(item);

    }

}

async function refreshAdminDashboard() {

    if (!state.adminToken) {
        return;
    }

    const data =
        await adminApi("/api/admin/users");

    state.adminUsers =
        data.users || [];

    state.adminAccountGroups =
        data.account_groups || {};

    state.adminCertificateGroups =
        data.certificate_groups || {};

    renderAdminDashboard();

}

async function refreshAll() {
  if (!state.token) return;
  const [files, users, catalog, requests] = await Promise.all([
    api("/api/files"),
    api("/api/users"),
    api("/api/file-catalog"),
    api("/api/file-requests"),
  ]);
  state.files = files;
  state.users = users;
  state.fileCatalog = catalog;
  state.fileRequests = requests;
  renderFiles();
  renderUsers();
  renderFileRequests();
  renderSelects();
}

function renderFiles() {

    const list = $("fileList");

    if (!list) return;

    list.innerHTML = "";

    if ($("totalFiles"))
        $("totalFiles").textContent = String(state.files.length);

    if ($("ownedFiles"))
        $("ownedFiles").textContent = String(
            state.files.filter(f => f.owner === state.username).length
        );

    if ($("sharedFiles"))
        $("sharedFiles").textContent = String(
            state.files.filter(f => f.owner !== state.username).length
        );

    if ($("userCount"))
        $("userCount").textContent = String(state.users.length);

    const query = normalized(state.fileQuery);

    const filtered = state.files.filter(file => {

        const role =
            file.permission ||
            (file.owner === state.username ? "owner" : "viewer");

        const haystack = normalized(
            `${file.filename} ${file.owner} ${role} ${file.created_at}`
        );

        const matchesQuery =
            !query || haystack.includes(query);

        const matchesScope =
            state.fileScope === "all" ||
            (state.fileScope === "owned" && file.owner === state.username) ||
            (state.fileScope === "shared" && file.owner !== state.username) ||
            (state.fileScope === "editor" && role === "editor") ||
            (state.fileScope === "viewer" && role === "viewer");

        return matchesQuery && matchesScope;

    });

    if (!state.files.length) {

        list.innerHTML =
            `<div class="emptyState">
                <strong>Belum ada file</strong>
                <p>Upload file pertama dari tab Upload Terenkripsi.</p>
            </div>`;

        return;

    }

    if (!filtered.length) {

        list.innerHTML =
            `<div class="emptyState">
                <strong>Tidak ada hasil</strong>
                <p>Ubah kata kunci search atau filter file.</p>
            </div>`;

        return;

    }

    for (const file of filtered) {

        const row = document.createElement("div");

        row.className = "item";

        const role =
            file.permission ||
            (file.owner === state.username ? "owner" : "viewer");

        const env = file.envelope || {};

        const fileId =
            env.file_id || file.id;

        const version =
            env.version ?? "-";

        const uploaded =
            env.uploaded_at
                ? new Date(env.uploaded_at).toLocaleString()
                : "-";

        const actions = [

            `<button data-download="${file.id}">Unduh</button>`,

            canEdit(file)
                ? `<button class="ghost" data-update="${file.id}">Update & Rotate Key</button>`
                : "",

            canEdit(file)
                ? `<button class="ghost" data-rename="${file.id}">Rename</button>`
                : "",

            canManage(file)
                ? `<button class="ghost" data-access="${file.id}">Akses</button>`
                : "",

            canManage(file)
                ? `<button class="ghost" data-visibility="${file.id}" data-hidden="${file.is_hidden ? "true" : "false"}">${file.is_hidden ? "Tampilkan di katalog" : "Hide dari katalog"}</button>`
                : "",

            canManage(file)
                ? `<button class="danger" data-delete="${file.id}">Delete</button>`
                : ""

        ].join("");

        row.innerHTML = `

            <div>

                <strong>${escapeHtml(file.filename)}</strong>

                <div class="meta">

                    <div><b>🆔 File ID</b> :
                        <code>${escapeHtml(fileId)}</code>
                    </div>

                    <div><b>📝 Version</b> :
                        ${escapeHtml(String(version))}
                    </div>

                    <div><b>📅 Uploaded</b> :
                        ${escapeHtml(uploaded)}
                    </div>

                    <div><b>👤 Owner</b> :
                        ${escapeHtml(file.owner)}
                    </div>

                    <div><b>🔐 Role</b> :
                        ${escapeHtml(role)}
                    </div>

                    <div><b>💾 Size</b> :
                        ${Number(file.encrypted_size).toLocaleString()} byte
                    </div>

                </div>

            </div>

            <div class="itemActions">

                ${actions}

            </div>

        `;

        list.appendChild(row);

    }

}

function renderUsers() {
  const list = $("userList");
  if (!list) return;
  const query = normalized(state.userQuery);
  const users = state.users.filter(user => {
    const visibleFiles = state.fileCatalog.filter(file => file.owner === user.username);
    return normalized(
      `${user.display_name} ${user.username} ${visibleFiles.map(file => file.filename).join(" ")}`
    ).includes(query);
  });
  list.innerHTML = "";
  if (!state.users.length) {
    list.innerHTML = `<div class="emptyState"><strong>Belum ada user lain</strong><p>Buat akun lain dulu untuk mencoba sharing.</p></div>`;
    return;
  }
  if (!users.length) {
    list.innerHTML = `<div class="emptyState"><strong>User tidak ditemukan</strong><p>Ubah kata kunci pencarian.</p></div>`;
    return;
  }
  for (const user of users) {
    const visibleFiles = state.fileCatalog.filter(file => file.owner === user.username);
    const catalogHtml = visibleFiles.length
      ? visibleFiles.map(file => {
          let action;
          if (file.has_access) {
            action = `<button class="ghost" type="button" disabled>Sudah punya akses</button>`;
          } else if (file.request_status === "PENDING") {
            action = `<button class="ghost" type="button" disabled>Menunggu persetujuan</button>`;
          } else {
            const label = file.request_status === "REJECTED" || file.request_status === "CANCELLED"
              ? "Minta lagi"
              : "Minta file";
            action = `<button type="button" data-request-file="${file.id}">${label}</button>`;
          }
          return `
            <div class="catalogFile">
              <div>
                <strong>${escapeHtml(file.filename)}</strong>
                <span class="meta">${Number(file.encrypted_size).toLocaleString()} byte · ${new Date(file.created_at).toLocaleString()}</span>
              </div>
              <div class="itemActions">${action}</div>
            </div>
          `;
        }).join("")
      : `<div class="muted">Tidak ada file yang ditampilkan oleh user ini.</div>`;
    const row = document.createElement("div");
    row.className = "item userItem";
    row.innerHTML = `
      <div class="userCatalog">
        <div class="userCatalogHead">
          <div>
            <strong>${escapeHtml(user.display_name)} (${escapeHtml(user.username)})</strong>
            <span class="meta">Public key tersedia · ${visibleFiles.length} file ditampilkan</span>
          </div>
          <div class="itemActions">
            <button class="ghost" type="button" data-copy-user="${escapeHtml(user.username)}">Pakai untuk share</button>
          </div>
        </div>
        <div class="catalogFiles">${catalogHtml}</div>
      </div>
    `;
    list.appendChild(row);
  }
}

function requestStatusLabel(status) {
  return ({
    PENDING: "Menunggu",
    APPROVED: "Disetujui",
    REJECTED: "Ditolak",
    CANCELLED: "Dibatalkan karena file disembunyikan",
  })[status] || status;
}

function renderFileRequests() {
  const incomingList = $("incomingRequestList");
  const outgoingList = $("outgoingRequestList");
  const incoming = state.fileRequests?.incoming || [];
  const outgoing = state.fileRequests?.outgoing || [];
  const badge = $("requestBadge");

  if (badge) {
    badge.textContent = String(incoming.length);
    badge.classList.toggle("hidden", incoming.length === 0);
  }

  if (incomingList) {
    incomingList.innerHTML = incoming.length
      ? incoming.map(request => `
          <div class="item compact">
            <div>
              <strong>${escapeHtml(request.filename)}</strong>
              <span class="meta">Diminta oleh ${escapeHtml(request.requester_display_name)} (${escapeHtml(request.requester)}) · ${new Date(request.requested_at).toLocaleString()}</span>
            </div>
            <div class="itemActions">
              <button type="button" data-approve-request="${request.id}">Setujui & kirim kunci</button>
              <button class="danger" type="button" data-reject-request="${request.id}">Tolak</button>
            </div>
          </div>
        `).join("")
      : `<div class="emptyState"><strong>Tidak ada permintaan masuk</strong><p>Permintaan baru akan muncul di sini.</p></div>`;
  }

  if (outgoingList) {
    outgoingList.innerHTML = outgoing.length
      ? outgoing.map(request => `
          <div class="item compact">
            <div>
              <strong>${escapeHtml(request.filename)}</strong>
              <span class="meta">Pemilik ${escapeHtml(request.owner_display_name)} (${escapeHtml(request.owner)}) · ${new Date(request.requested_at).toLocaleString()}</span>
            </div>
            <span class="statusBadge">${escapeHtml(requestStatusLabel(request.status))}</span>
          </div>
        `).join("")
      : `<div class="emptyState"><strong>Belum ada permintaan keluar</strong><p>Pilih file dari Direktori User untuk meminta akses.</p></div>`;
  }
}

function renderSelects() {
  const fileSelect = document.querySelector("#shareForm select[name=file_id]");
  const userSelect = document.querySelector("#shareForm select[name=recipient]");
  if (!fileSelect || !userSelect) return;
  const manageableFiles = state.files.filter(f => f.owner === state.username);
  fileSelect.innerHTML = manageableFiles.map(f => `<option value="${f.id}">${escapeHtml(f.filename)}</option>`).join("");
  userSelect.innerHTML = state.users.map(u => `<option value="${escapeHtml(u.username)}">${escapeHtml(u.display_name)} (${escapeHtml(u.username)})</option>`).join("");
}

document.querySelectorAll(".tabs button").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tabs button").forEach(b => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach(t => t.classList.add("hidden"));
    btn.classList.add("active");
    $(`${btn.dataset.tab}Tab`)?.classList.remove("hidden");
  });
});

on("adminSetupForm", "submit", async (evt) => {

    evt.preventDefault();

    const form =
        new FormData(evt.currentTarget);

    const result =
        await adminApi(
            "/api/admin/setup",
            {
                method: "POST",
                body: JSON.stringify({
                    username: form.get("username").trim(),
                    password: form.get("password")
                })
            }
        );

    state.adminToken =
        result.token;

    state.adminUsername =
        result.username;

    state.adminSetupRequired =
        false;

    localStorage.setItem(
        "om_admin_token",
        state.adminToken
    );

    localStorage.setItem(
        "om_admin_username",
        state.adminUsername
    );

    resetAdminInputs();

    renderAuth();

    await refreshAdminDashboard();

    showNotice("Administrator berhasil diinisialisasi.");

});

on("adminLoginForm", "submit", async (evt) => {

    evt.preventDefault();

    const form =
        new FormData(evt.currentTarget);

    const result =
        await adminApi(
            "/api/admin/login",
            {
                method: "POST",
                body: JSON.stringify({
                    username: form.get("username").trim(),
                    password: form.get("password")
                })
            }
        );

    state.adminToken =
        result.token;

    state.adminUsername =
        result.username;

    localStorage.setItem(
        "om_admin_token",
        state.adminToken
    );

    localStorage.setItem(
        "om_admin_username",
        state.adminUsername
    );

    resetAdminInputs();

    renderAuth();

    await refreshAdminDashboard();

    showNotice("Login administrator berhasil.");

});

on("adminLogoutBtn", "click", () => {

    clearAdminSession();

    resetAdminInputs();

    renderAuth();

    refreshAdminSetupStatus();

});

on("refreshAdminBtn", "click", refreshAdminDashboard);

on("adminPasswordForm", "submit", async (evt) => {

    evt.preventDefault();

    const form =
        new FormData(evt.currentTarget);

    await adminApi(
        "/api/admin/change-password",
        {
            method: "POST",
            body: JSON.stringify({
                current_password: form.get("current_password"),
                new_password: form.get("new_password")
            })
        }
    );

    evt.currentTarget.reset();

    showNotice("Password admin berhasil diubah.");

});

on("adminAccountGroups", "click", async (evt) => {

    const editButton =
        evt.target.closest("[data-admin-edit]");

    if (editButton) {

        const username =
            editButton.dataset.adminEdit;

        const user =
            state.adminUsers.find(item => item.username === username);

        if (!user) {
            return;
        }

        const displayName =
            prompt("Nama lengkap:", user.display_name || "");

        if (displayName === null)
            return;

        const nip =
            prompt("NIP:", user.nip || "");

        if (nip === null)
            return;

        const rank =
            prompt("Pangkat:", user.rank || "");

        if (rank === null)
            return;

        const position =
            prompt("Jabatan:", user.position || "");

        if (position === null)
            return;

        await adminApi(
            `/api/admin/users/${encodeURIComponent(username)}`,
            {
                method: "PATCH",
                body: JSON.stringify({
                    display_name: displayName.trim(),
                    nip: nip.trim(),
                    rank: rank.trim(),
                    position: position.trim()
                })
            }
        );

        await refreshAdminDashboard();

        showNotice("Metadata user berhasil diperbarui.");

        return;

    }

    const actionButton =
        evt.target.closest("[data-admin-action]");

    if (!actionButton) {
        return;
    }

    const username =
        actionButton.dataset.adminUser;

    const action =
        actionButton.dataset.adminAction;

    let body = {};

    if (action === "reject" || action === "revoke") {

        const reason =
            prompt("Alasan tindakan:", "");

        if (reason === null)
            return;

        body.reason =
            reason.trim();

    }

    if (action === "soft-delete") {

        if (!confirm(`Soft delete user ${username}?`)) {
            return;
        }

    }

    await adminApi(
        `/api/admin/users/${encodeURIComponent(username)}/${action}`,
        {
            method: "POST",
            body: JSON.stringify(body)
        }
    );

    await refreshAdminDashboard();

    showNotice(`Aksi ${action} berhasil dijalankan untuk ${username}.`);

});

on("registerForm", "submit", async (evt) => {

    evt.preventDefault();

    const formElement = evt.currentTarget;

    const form = new FormData(formElement);

    const username = form.get("username").trim();

    const password = form.get("password");

    // ============================
    // Generate encrypted DIPP Ephemeral-R identity vault
    // ============================

    const dipp = await OneMindDippEphemeralR.generateIdentity(username, password);

    // ============================
    // Generate RSA Login Keypair
    // ============================

    await generatePKIKeypair();

    // ============================
    // Export RSA Login Public Key
    // ============================

    const rsaEnrollmentPublicKey =
        await exportPKIPublicKey();

    // ============================
    // Register ke Server
    // ============================

    await api(
        "/api/register",
        {
            method: "POST",
            body: JSON.stringify({

                username,

                display_name:
                    form.get("display_name").trim(),

                password,

                nip:
                    form.get("nip").trim(),

                rank:
                    form.get("rank").trim(),

                position:
                    form.get("position").trim(),

                // DIPP Public Key
                public_key:
                    dipp.public,

                // RSA Login Public Key
                pki_public_key:
                    rsaEnrollmentPublicKey

            }),
        }
    );

    // ============================
    // Simpan DIPP Session
    // ============================

    activateDippIdentity(dipp);

    // ============================
    // Simpan RSA Login Session
    // ============================

    rsaEnrollmentSession.username = username;

    // ============================
    // Export Identity
    // ============================

    let dippExport = false;

    let pkiExport = false;

    try {

        await exportDippIdentity(
            username,
            dipp
        );

        dippExport = true;

    } catch (err) {

        console.error(
            "Export DIPP gagal:",
            err
        );

    }

    try {

        await exportRSAEnrollmentKey(
            username
        );

        pkiExport = true;

    } catch (err) {

        console.error(
            "Export RSA Login Key gagal:",
            err
        );

    }

    // ============================
    // Notifikasi
    // ============================

    if (dippExport && pkiExport) {

        showNotice(
            "Registrasi berhasil.\n\nIdentitas DIPP dan RSA Login Key berhasil diunduh.\nSimpan kedua file tersebut di tempat yang aman.\n\nAkun masih PENDING dan menunggu approval Administrator.\n\nRSA Login Key wajib digunakan pada setiap login dan juga mengaktifkan certificate pada login pertama."
        );

    } else if (dippExport) {

        showNotice(
            "Registrasi berhasil.\n\nIdentitas DIPP berhasil diunduh namun RSA Login Key gagal diunduh.\n\nJangan tutup browser sebelum RSA Login Key berhasil diekspor."
        );

    } else if (pkiExport) {

        showNotice(
            "Registrasi berhasil.\n\nRSA Login Key berhasil diunduh namun Identitas DIPP gagal diunduh.\n\nJangan tutup browser sebelum Identitas DIPP berhasil diekspor."
        );

    } else {

        showNotice(
            "Registrasi berhasil.\n\nNamun export Identitas DIPP maupun RSA Login Key gagal.\n\nJangan tutup browser sebelum kedua file berhasil diekspor."
        );

    }

    formElement.reset();

    renderAuth();

});

on(
    "importRsaInput",
    "change",
    async (evt) => {
        const input = evt.currentTarget;
        const file = input?.files?.[0];

        if (!file) return;

        try {
            await importRSAEnrollmentKey(file, state.username);
            showNotice("RSA Login Key berhasil dimuat ke RAM.");
        }
        catch (err) {
            console.error(err);
            handleUiError(err, {context: "keyImport"});
        }

        input.value = "";
    }
);

on("importDippInput", "change", async (evt) => {

    const input = evt.currentTarget;

    const file = input.files?.[0];

    if (!file) return;

    try {

        await importDippIdentity(
            file,
            state.username,
            $("dippVaultPassword")?.value
        );

        showNotice(
            "Identitas DIPP berhasil dimuat."
        );

        updateLocalKeyStatus();

    } catch (err) {

        console.error(err);

        handleUiError(err, {context: "keyImport"});

    }

    input.value = "";
    if ($("dippVaultPassword")) $("dippVaultPassword").value = "";

});

on("exportDippBtn", "click", async () => {
    try {
        const identity = await ensureUnlockedPrivateKey();
        await exportDippIdentity(state.username, identity);
        showNotice("Vault DIPP Ephemeral-R terbaru berhasil diekspor dalam keadaan terenkripsi.");
    } catch (err) {
        console.error(err);
        handleUiError(err, {context: "keyExport"});
    }
});

on("loginForm", "submit", async (evt) => {

    evt.preventDefault();

    const formElement = evt.currentTarget;
    const form = new FormData(formElement);
    const username = form.get("username").trim();
    const password = form.get("password");

    if (!selectedDippFile) {
        showFormFeedback(
            formElement,
            "Silakan pilih file Identitas DIPP terlebih dahulu.",
            "error"
        );
        return;
    }

    try {
        // DIPP tetap menjadi identitas untuk seluruh operasi di aplikasi.
        await importDippIdentity(
            selectedDippFile,
            username,
            password
        );

        // Tahap password: server hanya memberi token login sementara.
        const started = await api(
            "/api/login",
            {
                method: "POST",
                body: JSON.stringify({
                    username,
                    password
                })
            }
        );

        // RSA Login Key wajib pada login pertama maupun login berikutnya.
        await requestRSAEnrollmentKey(username);

        const challenge = await pendingLoginApi(
            "/api/login/challenge",
            started.login_token,
            { method: "POST" }
        );

        const signature = await signChallenge(
            challenge.nonce
        );

        const publicKey = await exportPKIPublicKey();

        const verified = await pendingLoginApi(
            "/api/login/verify",
            started.login_token,
            {
                method: "POST",
                body: JSON.stringify({
                    nonce: challenge.nonce,
                    signature,
                    public_key_pem: publicKey
                })
            }
        );

        // JWT utama baru disimpan setelah RSA challenge berhasil.
        state.token = verified.token;
        state.username = verified.username;

        localStorage.setItem("om_token", state.token);
        localStorage.setItem("om_username", state.username);
        localStorage.removeItem("om_last_password_hint");

        renderAuth();
        await refreshAll();
        updateLocalKeyStatus();

        if (verified.certificate_issued) {
            showNotice(
                "Login berhasil.\n\nRSA challenge valid dan certificate akun berhasil diaktifkan."
            );
        }
        else {
            showNotice(
                "Login berhasil.\n\nRSA challenge valid dan certificate akun aktif."
            );
        }

        formElement.reset();
        selectedDippFile = null;
    }
    catch (err) {
        console.error(err);

        state.token = null;
        state.username = null;
        state.unlockedPrivateKey = null;

        dippSession.privateKey = null;
        dippSession.publicKey = null;
        dippSession.username = null;
        dippSession.runtime = null;

        rsaEnrollmentSession.privateKey = null;
        rsaEnrollmentSession.publicKey = null;
        rsaEnrollmentSession.username = null;

        localStorage.removeItem("om_token");
        localStorage.removeItem("om_username");

        renderAuth();
        updateLocalKeyStatus();

        handleUiError(err, {context: "login", form: formElement});
    }

});

on("uploadForm", "submit", async (evt) => {

    evt.preventDefault();

    const form = evt.currentTarget;
    const submitButton = form.querySelector('button[type="submit"]');

    try {

        // =====================================
        // WAJIB IMPORT IDENTITAS DIPP DAHULU
        // =====================================

        await ensureUnlockedPrivateKey();

        const formData = new FormData(form);

        const file = formData.get("file");

        const isHidden = formData.get("visibility") !== "visible";

        if (!file || !file.size) {
            return;
        }
        if (file.size + 16 > MAX_FILE_BYTES) {
            throw new Error("Ukuran file melebihi batas 20 GiB.");
        }

        form.setAttribute("aria-busy", "true");
        if (submitButton) submitButton.disabled = true;
        setUploadProgress("Menyiapkan enkripsi file...");

        const me = await api("/api/me");

        setUploadProgress("Mengenkripsi file di browser...");

        const encrypted = await encryptFile(file);

        setUploadProgress("Membungkus kunci file untuk pemilik...");

        const wrapped = await wrapFileKey(
            encrypted.key,
            me.public_key,
            encrypted.envelope.file_context_id
        );

        setUploadProgress("Membuat sesi upload terenkripsi...");

        const upload = await uploadCiphertext(
            encrypted,
            wrapped,
            file
        );

        await uploadChunks(
            upload.session,
            upload.chunks
        );

        setUploadProgress("Memverifikasi dan menyimpan ciphertext...", 100);

        const result = await uploadFinish(
            upload.session,
            encrypted,
            wrapped,
            isHidden
        );

        showNotice("Upload selesai.");

        await refreshAll();

    }
    catch (err) {

        console.error(err);

        handleUiError(err, {context: "upload", form});

    }
    finally {

        clearUploadProgress();
        form.removeAttribute("aria-busy");
        if (submitButton) submitButton.disabled = false;
        form.reset();

    }

});

on("shareForm", "submit", async (evt) => {
  evt.preventDefault();
  const form = new FormData(evt.currentTarget);
  const fileId = form.get("file_id");
  const recipient = form.get("recipient");
  const permission = form.get("permission");
  const {file, fileKey} = await getFileKey(fileId);
  const recipientUser = await api(`/api/users/${encodeURIComponent(recipient)}/public-key`);
  const wrapped = await wrapFileKey(fileKey, recipientUser.public_key, file.envelope.file_context_id);
  await api("/api/share", {method: "POST", body: JSON.stringify({file_id: fileId, recipient, permission, wrapped_key: wrapped})});
  await refreshAll();
  await renderAccess(fileId);
  showNotice("Public key penerima diambil, pre-key DIPP dibentuk ulang oleh penerima, dan AES file key berhasil dibungkus.");
});

on("fileList", "click", async (evt) => {
  const btn = evt.target.closest("button");
  if (!btn) return;
  if (btn.dataset.rename) {
    await renameFile(btn.dataset.rename);
    return;
  }
  if (btn.dataset.delete) {
    await deleteFile(btn.dataset.delete);
    return;
  }
  if (btn.dataset.update) {
    state.pendingUpdateFileId = btn.dataset.update;
    $("updateFileInput")?.click();
    return;
  }
  if (btn.dataset.access) {
    const shareTab = document.querySelector('.tabs button[data-tab="share"]');
    shareTab?.click();
    const fileSelect = document.querySelector("#shareForm select[name=file_id]");
    if (fileSelect) fileSelect.value = btn.dataset.access;
    await renderAccess(btn.dataset.access);
    return;
  }
  if (btn.dataset.visibility) {
    const isCurrentlyHidden = btn.dataset.hidden === "true";
    const nextHidden = !isCurrentlyHidden;
    const action = nextHidden ? "menyembunyikan" : "menampilkan";
    if (!confirm(`Yakin ingin ${action} file ini dari katalog user?`)) return;
    const result = await api(`/api/files/${btn.dataset.visibility}/visibility`, {
      method: "PATCH",
      body: JSON.stringify({is_hidden: nextHidden}),
    });
    await refreshAll();
    const suffix = result.cancelled_requests
      ? ` ${result.cancelled_requests} permintaan yang masih menunggu dibatalkan.`
      : "";
    showNotice(`Visibilitas file diperbarui.${suffix}`);
    return;
  }
  if (!btn.dataset.download) return;
  try {
    const {file, fileKey} = await getFileKey(btn.dataset.download);
    const ciphertext = await fetchCiphertextChunks(file);
    const blob = await decryptEnvelope(file.envelope, fileKey, ciphertext);
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = file.filename;
    a.click();
    URL.revokeObjectURL(url);
    showNotice("Download dan dekripsi file selesai.");
  } catch (err) {
    handleUiError(err, {context: "download"});
  } finally {
    clearDownloadProgress();
  }
});

on("refreshFilesBtn", "click", refreshAll);
on("fileSearch", "input", (evt) => {
  state.fileQuery = evt.currentTarget.value;
  renderFiles();
});
on("fileScope", "change", (evt) => {
  state.fileScope = evt.currentTarget.value;
  renderFiles();
});
on("userSearch", "input", (evt) => {
  state.userQuery = evt.currentTarget.value;
  renderUsers();
});
on("userList", "click", async (evt) => {
  const requestButton = evt.target.closest("[data-request-file]");
  if (requestButton) {
    try {
      await api(`/api/files/${requestButton.dataset.requestFile}/requests`, {
        method: "POST",
      });
      await refreshAll();
      showNotice("Permintaan file dikirim kepada pemilik.");
    } catch (err) {
      handleUiError(err, {context: "fileRequest"});
    }
    return;
  }

  const shareButton = evt.target.closest("[data-copy-user]");
  if (!shareButton) return;
  const shareTab = document.querySelector('.tabs button[data-tab="share"]');
  shareTab?.click();
  const userSelect = document.querySelector("#shareForm select[name=recipient]");
  if (userSelect) userSelect.value = shareButton.dataset.copyUser;
  showNotice(`User ${shareButton.dataset.copyUser} dipilih sebagai penerima share.`);
});
on("refreshRequestsBtn", "click", refreshAll);
on("incomingRequestList", "click", async (evt) => {
  const approveButton = evt.target.closest("[data-approve-request]");
  const rejectButton = evt.target.closest("[data-reject-request]");
  if (!approveButton && !rejectButton) return;

  try {
    if (approveButton) {
      const requestId = approveButton.dataset.approveRequest;
      const request = (state.fileRequests?.incoming || []).find(item => item.id === requestId);
      if (!request) throw new Error("Permintaan tidak ditemukan. Muat ulang halaman.");

      const {file, fileKey} = await getFileKey(request.file_id);
      const requester = await api(`/api/users/${encodeURIComponent(request.requester)}/public-key`);
      const wrappedKey = await wrapFileKey(fileKey, requester.public_key, file.envelope.file_context_id);
      await api(`/api/file-requests/${requestId}/approve`, {
        method: "POST",
        body: JSON.stringify({wrapped_key: wrappedKey}),
      });
      await refreshAll();
      showNotice("Permintaan disetujui. Wrapped key dikirim dan akses viewer aktif.");
      return;
    }

    if (!confirm("Tolak permintaan file ini?")) return;
    await api(`/api/file-requests/${rejectButton.dataset.rejectRequest}/reject`, {
      method: "POST",
    });
    await refreshAll();
    showNotice("Permintaan file ditolak.");
  } catch (err) {
    handleUiError(err, {context: "fileRequest"});
  }
});
on("loadAccessBtn", "click", async () => {
  const fileId = document.querySelector("#shareForm select[name=file_id]")?.value;
  if (!fileId) {
    showNotice("Pilih file terlebih dahulu.", "warning");
    return;
  }
  await renderAccess(fileId);
});
on("rotateKeyBtn", "click", async () => {
  const fileId = document.querySelector("#shareForm select[name=file_id]")?.value;
  if (!fileId) {
    showNotice("Pilih file terlebih dahulu.", "warning");
    return;
  }
  try {
    await rotateCurrentFileKey(fileId);
  } catch (err) {
    handleUiError(err, {context: "rotate"});
  } finally {
    clearDownloadProgress();
  }
});
on("accessList", "click", async (evt) => {
  const btn = evt.target.closest("[data-revoke]");
  if (!btn) return;
  if (!confirm(`Cabut akses ${btn.dataset.revoke}?`)) return;
  await api(`/api/files/${btn.dataset.file}/shares/${encodeURIComponent(btn.dataset.revoke)}`, {method: "DELETE"});
  await refreshAll();
  await renderAccess(btn.dataset.file);
  showNotice("Akses berhasil dicabut. Untuk keamanan penuh, update file agar AES key dirotasi.");
});

on("updateFileInput", "change", async (evt) => {

    const input = evt.currentTarget;

    const file = input?.files?.[0];

    const fileId = state.pendingUpdateFileId;

    try {

        if (fileId && file) {

            await updateFileWithRotation(
                fileId,
                file
            );

        }

    }

    finally {

        state.pendingUpdateFileId = null;

        clearDownloadProgress();

        if (input) {

            input.value = "";

        }

    }

});

on(
    "exportRsaBtn",
    "click",
    async () => {

        if (!state.username) {

            showNotice(
                "Login terlebih dahulu."
            );

            return;

        }

        try {

            await exportRSAEnrollmentKey(
                state.username
            );

            showNotice(
                "RSA Login Key berhasil diekspor."
            );

        }

        catch (err) {

            console.error(err);

            handleUiError(err, {context: "keyExport"});

        }

    }
);

on("logoutBtn", "click", () => {

  // ============================
  // Hapus DIPP dari RAM
  // ============================

  dippSession.privateKey = null;
  dippSession.publicKey = null;
  dippSession.username = null;
  dippSession.runtime = null;

  // ============================
  // Hapus PKI dari RAM
  // ============================

  rsaEnrollmentSession.privateKey = null;
  rsaEnrollmentSession.publicKey = null;
  rsaEnrollmentSession.username = null;

  // ============================
  // Hapus session login
  // ============================

  localStorage.removeItem("om_token");
  localStorage.removeItem("om_username");
  localStorage.removeItem("om_last_password_hint");

  state.token = null;
  state.username = null;
  state.unlockedPrivateKey = null;

  resetAuthInputs();

  updateLocalKeyStatus();

  renderAuth();

});

window.addEventListener("unhandledrejection", evt => {
  evt.preventDefault();
  handleUiError(evt.reason);
});
document.addEventListener("input", evt => {
  const form = evt.target?.closest?.("form");
  if (form) clearFormFeedback(form);
});
renderAuth();
refreshAll();
refreshAdminSetupStatus();
refreshAdminDashboard();

// Sinkronkan badge permintaan dan akses yang baru disetujui tanpa menyimpan key.
setInterval(() => {
  if (!state.token) return;
  refreshAll().catch(err => console.warn("Gagal menyegarkan permintaan file:", err));
}, 30000);

on("dippFile", "change", (evt) => {

    selectedDippFile = evt.target.files[0] || null;

});
