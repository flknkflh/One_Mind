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

    username: null

};

const pkiSession = {

    privateKey: null,

    publicKey: null,

    username: null,

    csr: null,

    certificate: null

};

const PKI_RSA_BITS = 4096;
const PKI_HASH = "SHA-512";
const enc = new TextEncoder();
const dec = new TextDecoder();
const BACKUP_KEY_ITERATIONS = 600000;
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

function on(id, event, handler) {
  const el = $(id);
  if (el) el.addEventListener(event, handler);
}

function showNotice(message) {
  const notice = $("notice");
  if (!notice) return;
  notice.textContent = message;
  notice.classList.remove("hidden");
  setTimeout(() => notice.classList.add("hidden"), 4200);
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

    console.log("BASE64 INPUT =", text);

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

    // ============================
    // DEBUG
    // ============================
    console.log("API:", path);
    console.log(data);

    if (!res.ok) {

        console.error("HTTP ERROR", res.status);

        console.error(data);

        throw new Error(
            "HTTP " +
            res.status +
            "\n\n" +
            JSON.stringify(
                data,
                null,
                2
            )
        );

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

    console.log("ADMIN API:", path);
    console.log(data);

    if (!res.ok) {

        if (res.status === 401 && state.adminToken) {
            clearAdminSession();
            renderAuth();
            refreshAdminSetupStatus();
        }

        throw new Error(
            "HTTP " +
            res.status +
            "\n\n" +
            JSON.stringify(
                data,
                null,
                2
            )
        );
    }

    return data;

}


const DIPP_PARAMS = {
  dim: 3,
  n_pub: 40,
  coord_max: 1000,
  w_range: [0.01, 0.15],
  delta_range: [-0.1, 0.1],
  q: 2 ** 16,
  scale: 100,
  error_bound: 50,
  error_geser: 10,
  repeat: 5,
};

function randU32() {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0];
}

function randFloat() {
  return randU32() / 0x100000000;
}

function randInt(min, maxInclusive) {
  return min + Math.floor(randFloat() * (maxInclusive - min + 1));
}

function randUniform(min, max) {
  return min + randFloat() * (max - min);
}

function randNormal() {
  const u1 = Math.max(randFloat(), Number.EPSILON);
  const u2 = randFloat();
  return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
}

function vectorNorm(v) {
  return Math.sqrt(v.reduce((sum, x) => sum + x * x, 0));
}

function distance(a, b) {
  let sum = 0;
  for (let i = 0; i < a.length; i++) sum += (a[i] - b[i]) ** 2;
  return Math.sqrt(sum);
}

function weightedWeiszfeld(points, weights, tol = 1e-9, maxIter = 500) {
  const dim = points[0].length;
  let y = Array(dim).fill(0);
  const weightSum = weights.reduce((a, b) => a + b, 0);
  for (let i = 0; i < points.length; i++) {
    for (let d = 0; d < dim; d++) y[d] += points[i][d] * weights[i] / weightSum;
  }
  for (let iter = 0; iter < maxIter; iter++) {
    const scaled = Array(dim).fill(0);
    let denom = 0;
    for (let i = 0; i < points.length; i++) {
      const dist = Math.max(distance(points[i], y), 1e-12);
      const w = weights[i] / dist;
      denom += w;
      for (let d = 0; d < dim; d++) scaled[d] += points[i][d] * w;
    }
    const yNew = scaled.map(x => x / denom);
    if (distance(yNew, y) < tol) return yNew;
    y = yNew;
  }
  return y;
}

function avgDist(point, points) {
  return points.reduce((sum, p) => sum + distance(p, point), 0) / points.length;
}

function geserTitik(point, jarak) {
  if (jarak === 0) return point.slice();
  const arah = point.map(() => randNormal());
  const norm = vectorNorm(arah);
  if (norm < 1e-12) return point.slice();
  return point.map((x, i) => x + (arah[i] / norm) * jarak);
}

function dippKeygenInt(aPoints, params) {
  const x = Array.from({length: params.dim}, () => randInt(0, params.coord_max - 1));
  const w = randUniform(params.w_range[0], params.w_range[1]);
  const delta = Array.from({length: aPoints.length}, () => randUniform(params.delta_range[0], params.delta_range[1]));
  const weights = delta.map(d => 1.0 + d).concat([w]);
  const b = geserTitik(weightedWeiszfeld(aPoints.concat([x]), weights), params.error_geser);
  return {x, w, delta, b};
}

function dippComputeF(aPoints, bPeer, xSelf, wSelf, deltaSelf) {
  const weights = deltaSelf.map(d => 1.0 + d).concat([1.0, wSelf]);
  const med = weightedWeiszfeld(aPoints.concat([bPeer, xSelf]), weights);
  return avgDist(med, aPoints);
}

function bytesToBits(data) {
  const bits = [];
  for (const byte of data) {
    for (let i = 7; i >= 0; i--) bits.push((byte >> i) & 1);
  }
  return bits;
}

function bitsToBytes(bits) {
  if (bits.length % 8 !== 0) throw new Error("Jumlah bit DIPP tidak kelipatan 8.");
  const out = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (const bit of bits.slice(i, i + 8)) byte = (byte << 1) | bit;
    out[i / 8] = byte;
  }
  return out;
}

function generateDippKeypair(params = DIPP_PARAMS) {
  const aPoints = Array.from({length: params.n_pub}, () =>
    Array.from({length: params.dim}, () => randInt(0, params.coord_max - 1))
  );
  const kg = dippKeygenInt(aPoints, params);
  const publicKey = {
    algorithm: "DIPP-KEM-v1 (Weiszfeld, mirip FrodoKEM)",
    version: 1,
    dim: params.dim,
    n_pub: params.n_pub,
    coord_max: params.coord_max,
    w_range: params.w_range,
    delta_range: params.delta_range,
    q: params.q,
    scale: params.scale,
    error_bound: params.error_bound,
    error_geser: params.error_geser,
    repeat: params.repeat,
    A_points: aPoints,
    B: kg.b,
  };
  return {public: publicKey, private: {x: kg.x, w: kg.w, delta: kg.delta}};
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

    pkiSession.privateKey = pair.privateKey;

    pkiSession.publicKey = pair.publicKey;

    pkiSession.username = state.username;

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

async function signChallenge(nonceHex) {

    if (!pkiSession.privateKey) {
        throw new Error("PKI Private Key belum tersedia.");
    }

    const nonceBytes = new TextEncoder().encode(nonceHex);

    const signature = await crypto.subtle.sign(
        {
            name: "RSASSA-PKCS1-v1_5"
        },
        pkiSession.privateKey,
        nonceBytes
    );

    return arrayBufferToBase64(signature);

}

async function exportPKIPrivateKey() {

    if (!pkiSession.privateKey) {

        throw new Error(
            "PKI Private Key belum tersedia."
        );

    }

    const pkcs8 = await crypto.subtle.exportKey(

        "pkcs8",

        pkiSession.privateKey

    );

    return new Uint8Array(pkcs8);

}

function downloadPKIPrivateKey(

    username,

    bytes

) {

    const blob = new Blob(

        [bytes],

        {

            type: "application/octet-stream"

        }

    );

    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");

    a.href = url;

    a.download = `${username}.key`;

    a.click();

    URL.revokeObjectURL(url);

}

async function exportPKIIdentity() {

    const bytes =
        await exportPKIPrivateKey();

    downloadPKIPrivateKey(

        state.username,

        bytes

    );

}

function dippWrapBytes(publicKey, keyBytes) {
  const params = {
    dim: publicKey.dim,
    coord_max: publicKey.coord_max,
    w_range: publicKey.w_range,
    delta_range: publicKey.delta_range,
    q: publicKey.q,
    scale: publicKey.scale,
    error_bound: publicKey.error_bound,
    error_geser: publicKey.error_geser,
    repeat: publicKey.repeat,
  };
  const sender = dippKeygenInt(publicKey.A_points, params);
  const fInt = Math.round(dippComputeF(publicKey.A_points, publicKey.B, sender.x, sender.w, sender.delta) * params.scale) % params.q;
  const vList = [];
  for (const bit of bytesToBits(keyBytes)) {
    for (let i = 0; i < params.repeat; i++) {
      const err = randInt(-params.error_bound, params.error_bound);
      vList.push((fInt + err + bit * Math.floor(params.q / 2) + params.q) % params.q);
    }
  }
  return {
    algorithm: "DIPP-KEM-v1 (Weiszfeld, mirip FrodoKEM)",
    version: 1,
    created: new Date().toISOString(),
    n_bits: keyBytes.length * 8,
    repeat: params.repeat,
    q: params.q,
    scale: params.scale,
    B_s: sender.b,
    V: vList,
  };
}

function dippUnwrapBytes(privateEntry, wrapped) {
  const pub = privateEntry.public;
  const priv = privateEntry.private;
  const fInt = Math.round(dippComputeF(pub.A_points, wrapped.B_s, priv.x, priv.w, priv.delta) * wrapped.scale) % wrapped.q;
  if (wrapped.V.length !== wrapped.n_bits * wrapped.repeat) {
    throw new Error("Paket kunci DIPP tidak konsisten.");
  }
  const bits = [];
  for (let i = 0; i < wrapped.n_bits; i++) {
    let votes = 0;
    for (let j = 0; j < wrapped.repeat; j++) {
      const v = wrapped.V[i * wrapped.repeat + j];
      const diff = (v - fInt + wrapped.q) % wrapped.q;
      votes += Math.round(diff / Math.floor(wrapped.q / 2)) % 2;
    }
    bits.push(votes * 2 > wrapped.repeat ? 1 : 0);
  }
  return bitsToBytes(bits);
}

/*
async function createKeyBundle(username) {

    // ============================
    // Generate DIPP
    // ============================

    const dipp = generateDippKeypair();

    // ============================
    // Generate RSA PKI
    // ============================

    await generatePKIKeypair();

    // ============================
    // Simpan DIPP di RAM
    // ============================

    dippSession.privateKey = dipp;
    dippSession.publicKey = dipp.public;
    dippSession.username = username;

    state.unlockedPrivateKey = dipp;

    // ============================
    // Export Identitas DIPP
    // ============================

    await exportDippIdentity(
        username,
        dipp
    );

    // ============================
    // Return seluruh bundle
    // ============================

    return {
        dippPublic: dipp.public,
        pkiPublicKey: pkiSession.publicKey
    };

}
*/

async function exportPKIPublicKey() {

    if (!pkiSession.publicKey) {
        throw new Error("PKI Public Key belum tersedia.");
    }

    const spki = await crypto.subtle.exportKey(
        "spki",
        pkiSession.publicKey
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

async function exportDippIdentity(
    username,
    dipp
) {

    const identity = {

        version: 1,

        type: "ONE_MIND_DIPP",

        username,

        created_at:
            new Date().toISOString(),

        public_key:
            dipp.public,

        private_key:
            dipp.private

    };

    const blob =
        new Blob(

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
        `ONE_MIND_DIPP_${username}.dipp`;

    a.click();

    URL.revokeObjectURL(
        url
    );

}
async function importDippIdentity(
    file,
    username
) {

    const text =
        await file.text();

    const identity =
        JSON.parse(text);

    if (
        identity.type !==
        "ONE_MIND_DIPP"
    ) {

        throw new Error(
            "Bukan file Identitas DIPP ONE_MIND."
        );

    }

    if (
        identity.username !==
        username
    ) {

        throw new Error(
            "Identitas bukan milik user ini."
        );

    }

    const dipp = {

        public:
            identity.public_key,

        private:
            identity.private_key

    };

    dippSession.privateKey =
        dipp;

    dippSession.publicKey =
        dipp.public;

    dippSession.username =
        username;

    state.unlockedPrivateKey =
        dipp;

    updateLocalKeyStatus();

    return dipp;

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
            "Identitas DIPP belum diimport.";

        status.className =
            "keyStatus missing";

    }

    else {

        status.textContent =
            "Identitas DIPP berhasil dimuat ke RAM.";

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


async function wrapFileKey(fileKey, recipientPublicKey) {
  const rawFileKey = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
  return dippWrapBytes(recipientPublicKey, rawFileKey);
}

async function unwrapFileKey(wrapped, privateKey) {
  const raw = dippUnwrapBytes(privateKey, wrapped);
  return crypto.subtle.importKey("raw", raw, {name: "AES-GCM"}, true, ["encrypt", "decrypt"]);
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

    }
}

async function uploadFinish(
    session,
    encrypted,
    wrappedKey
) {

    return await api(
        "/api/upload/finish",
        {
            method: "POST",
            body: JSON.stringify({

                upload_id: session.upload_id,

                envelope: encrypted.envelope,

                wrapped_key_for_owner: wrappedKey,

                ciphertext_sha256:
                    encrypted.ciphertext_sha256

            })
        }
    );
}

async function decryptEnvelope(envelope, key) {
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: b64ToBytes(envelope.iv_b64), additionalData: b64ToBytes(envelope.aad_b64)},
    key,
    b64ToBytes(envelope.ciphertext_b64)
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

async function wrapKeyForAccess(fileKey, fileId) {
  const access = await api(`/api/files/${fileId}/access`);
  const wrapped_keys = [];
  for (const entry of access) {
    wrapped_keys.push({
      recipient: entry.username,
      wrapped_key: await wrapFileKey(fileKey, entry.public_key),
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

    console.log("1. UPDATE START");

    if (!replacementFile || !replacementFile.size)
        return;

    console.log("2. FILE OK");

    const current = await getFileKey(fileId);

    console.log("3. GET FILE OK");

    await decryptEnvelope(
        current.file.envelope,
        current.fileKey
    );

    console.log("4. DECRYPT OK");

    const encrypted = await encryptFile(
        replacementFile
    );

    console.log("5. ENCRYPT OK");

    encrypted.envelope.ciphertext_b64 =
        bytesToB64(encrypted.ciphertext);

    encrypted.envelope.file_id =
        current.file.envelope.file_id;

    encrypted.envelope.uploaded_at =
        current.file.envelope.uploaded_at;

    encrypted.envelope.version =
        (current.file.envelope.version || 1) + 1;

    console.log("6. ENVELOPE READY");

    const wrapped_keys =
        await wrapKeyForAccess(
            encrypted.key,
            fileId
        );

    console.log("7. WRAP OK");

    console.log("8. SEND PUT");

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

    console.log("9. PUT SUCCESS");

    await refreshAll();

    console.log("10. REFRESH OK");

    showNotice("Update selesai.");
}

async function rotateCurrentFileKey(fileId) {

    const current = await getFileKey(fileId);

    const blob = await decryptEnvelope(
        current.file.envelope,
        current.fileKey
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

    console.log("========== UPDATE ENVELOPE ==========");
    console.log(encrypted.envelope);
    console.log(Object.keys(encrypted.envelope));
    console.log(
        "ciphertext length =",
        encrypted.envelope.ciphertext_b64?.length
    );
    console.log("=====================================");

    const wrapped_keys = await wrapKeyForAccess(
        encrypted.key,
        fileId
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
  state.files = await api("/api/files");
  state.users = await api("/api/users");
  renderFiles();
  renderUsers();
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
  const users = state.users.filter(user => normalized(`${user.display_name} ${user.username}`).includes(query));
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
    const row = document.createElement("div");
    row.className = "item userItem";
    row.innerHTML = `
      <div>
        <strong>${escapeHtml(user.display_name)} (${escapeHtml(user.username)})</strong>
        <span class="meta">Public key tersedia | siap menerima share terenkripsi</span>
      </div>
      <div class="itemActions">
        <button class="ghost" data-copy-user="${escapeHtml(user.username)}">Pakai untuk share</button>
      </div>
    `;
    list.appendChild(row);
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

    const form = new FormData(evt.currentTarget);

    const username = form.get("username").trim();

    const password = form.get("password");

    // ============================
    // Generate DIPP Keypair
    // ============================

    const dipp = generateDippKeypair();

    // ============================
    // Generate PKI RSA Keypair
    // ============================

    await generatePKIKeypair();

    // ============================
    // Export PKI Public Key
    // ============================

    const pkiPublicKey = await exportPKIPublicKey();

    // ============================
    // Register ke Server
    // ============================

    const result = await api(
        "/api/register",
        {
            method: "POST",
            body: JSON.stringify({

                username,

                display_name: form.get("display_name").trim(),

                password,

                nip: form.get("nip").trim(),

                rank: form.get("rank").trim(),

                position: form.get("position").trim(),

                // DIPP Public Key
                public_key: dipp.public,

                // PKI RSA Public Key
                pki_public_key: pkiPublicKey

            }),
        }
    );

    // ============================
    // Simpan DIPP ke RAM
    // ============================

    dippSession.privateKey = dipp;

    dippSession.publicKey = dipp.public;

    dippSession.username = username;

    state.unlockedPrivateKey = dipp;

    // ============================
    // Lengkapi informasi PKI
    // ============================

    pkiSession.username = username;

    // ============================
    // Export Identitas DIPP
    // ============================

    let exportSuccess = false;

    try {

        await exportDippIdentity(
            username,
            dipp
        );

        exportSuccess = true;

    } catch (err) {

        console.error(
            "Export DIPP gagal:",
            err
        );

    }

    // ============================
    // Notifikasi
    // ============================

    if (exportSuccess) {

        showNotice(
            "Registrasi berhasil.\n\nIdentitas DIPP telah berhasil diunduh.\nSimpan file tersebut dengan aman.\n\nAkun masih PENDING dan menunggu approval administrator sebelum bisa login."
        );

    } else {

        showNotice(
            "Registrasi berhasil.\n\nNamun Identitas DIPP GAGAL diunduh.\n\nAkun masih PENDING dan menunggu approval administrator. JANGAN tutup browser ini jika perlu mencoba export ulang."
        );

    }

    evt.currentTarget.reset();

    renderAuth();

});

on("importDippInput", "change", async (evt) => {

    const file = evt.currentTarget.files[0];

    if (!file || !state.username) {
        return;
    }

    try {

        await importDippIdentity(
            file,
            state.username
        );

        updateLocalKeyStatus();

        showNotice(
            "Identitas DIPP berhasil diimport."
        );

    }

    catch (err) {

        console.error(err);

        showNotice(err.message);

    }

    finally {

        if (evt.currentTarget) {
            evt.currentTarget.value = "";
        }

    }

});

on("loginForm", "submit", async (evt) => {

  evt.preventDefault();

  const form = new FormData(evt.currentTarget);

  const username = form.get("username").trim();

  const password = form.get("password");

  // ============================
  // Pastikan file DIPP dipilih
  // ============================

  if (!selectedDippFile) {

    showNotice(
      "Silakan pilih file Identitas DIPP terlebih dahulu."
    );

    return;

  }

  // ============================
  // Login ke Server
  // ============================

  const result = await api(
    "/api/login",
    {
      method: "POST",
      body: JSON.stringify({
        username,
        password
      })
    }
  );

  state.token = result.token;

  state.username = result.username;

  localStorage.setItem(
    "om_token",
    state.token
  );

  localStorage.setItem(
    "om_username",
    state.username
  );

  localStorage.removeItem(
    "om_last_password_hint"
  );

  // ============================
  // Import Identitas DIPP
  // ============================

  await importDippIdentity(
    selectedDippFile,
    username
  );

  renderAuth();

  await refreshAll();

  updateLocalKeyStatus();

  showNotice(
    "Login berhasil."
  );

});

on("uploadForm", "submit", async (evt) => {

    evt.preventDefault();

    const form = evt.currentTarget;

    try {

        // =====================================
        // WAJIB IMPORT IDENTITAS DIPP DAHULU
        // =====================================

        await ensureUnlockedPrivateKey();

        const file = new FormData(form).get("file");

        if (!file || !file.size) {
            return;
        }

        const me = await api("/api/me");

        const encrypted = await encryptFile(file);

        const wrapped = await wrapFileKey(
            encrypted.key,
            me.public_key
        );

        const upload = await uploadCiphertext(
            encrypted,
            wrapped,
            file
        );

        await uploadChunks(
            upload.session,
            upload.chunks
        );

        const result = await uploadFinish(
            upload.session,
            encrypted,
            wrapped
        );

        console.log(result);

        showNotice("Upload selesai.");

        await refreshAll();

    }
    catch (err) {

        console.error(err);

        alert(err.message || err);

    }
    finally {

        form.reset();

    }

});

on("shareForm", "submit", async (evt) => {
  evt.preventDefault();
  const form = new FormData(evt.currentTarget);
  const fileId = form.get("file_id");
  const recipient = form.get("recipient");
  const permission = form.get("permission");
  const {fileKey} = await getFileKey(fileId);
  const recipientUser = await api(`/api/users/${encodeURIComponent(recipient)}/public-key`);
  const wrapped = await wrapFileKey(fileKey, recipientUser.public_key);
  await api("/api/share", {method: "POST", body: JSON.stringify({file_id: fileId, recipient, permission, wrapped_key: wrapped})});
  await refreshAll();
  await renderAccess(fileId);
  showNotice("Public key penerima diambil, shared secret file dibungkus, dan akses berhasil disimpan.");
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
  if (!btn.dataset.download) return;
  const {file, fileKey} = await getFileKey(btn.dataset.download);
  const blob = await decryptEnvelope(file.envelope, fileKey);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = file.filename;
  a.click();
  URL.revokeObjectURL(url);
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
on("userList", "click", (evt) => {
  const btn = evt.target.closest("[data-copy-user]");
  if (!btn) return;
  const shareTab = document.querySelector('.tabs button[data-tab="share"]');
  shareTab?.click();
  const userSelect = document.querySelector("#shareForm select[name=recipient]");
  if (userSelect) userSelect.value = btn.dataset.copyUser;
  showNotice(`User ${btn.dataset.copyUser} dipilih sebagai penerima share.`);
});
on("loadAccessBtn", "click", async () => {
  const fileId = document.querySelector("#shareForm select[name=file_id]")?.value;
  if (!fileId) {
    showNotice("Pilih file dulu.");
    return;
  }
  await renderAccess(fileId);
});
on("rotateKeyBtn", "click", async () => {
  const fileId = document.querySelector("#shareForm select[name=file_id]")?.value;
  if (!fileId) {
    showNotice("Pilih file dulu.");
    return;
  }
  await rotateCurrentFileKey(fileId);
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

        if (input) {

            input.value = "";

        }

    }

});

on("exportDippBtn", "click", async () => {

    if (!state.username) {

        showNotice(
            "Silakan login terlebih dahulu."
        );

        return;

    }

    if (!dippSession.privateKey) {

        showNotice(
            "Identitas DIPP belum tersedia di RAM."
        );

        return;

    }

    try {

        await exportDippIdentity(

            state.username,

            dippSession.privateKey

        );

        showNotice(
            "Identitas DIPP berhasil diexport."
        );

    }

    catch (err) {

        console.error(err);

        showNotice(
            "Export Identitas DIPP gagal."
        );

    }

});

on("logoutBtn", "click", () => {

  // ============================
  // Hapus DIPP dari RAM
  // ============================

  dippSession.privateKey = null;
  dippSession.publicKey = null;
  dippSession.username = null;

  // ============================
  // Hapus PKI dari RAM
  // ============================

  pkiSession.privateKey = null;
  pkiSession.publicKey = null;
  pkiSession.username = null;
  pkiSession.csr = null;
  pkiSession.certificate = null;

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

window.addEventListener("unhandledrejection", evt => showNotice(evt.reason?.message || "Terjadi kesalahan."));
renderAuth();
refreshAll();
refreshAdminSetupStatus();
refreshAdminDashboard();
on("dippFile", "change", (evt) => {

    selectedDippFile = evt.target.files[0] || null;

});
