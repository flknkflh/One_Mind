const state = {
  token: localStorage.getItem("om_token"),
  username: localStorage.getItem("om_username"),
  files: [],
  users: [],
  pendingUpdateFileId: null,
  fileQuery: "",
  fileScope: "all",
  userQuery: "",
  unlockedPrivateKey: null,
  keyUnlockedUntil: 0,
  keyLockTimer: null,
};

const enc = new TextEncoder();
const dec = new TextDecoder();
const BACKUP_KEY_ITERATIONS = 600000;
const SESSION_UNLOCK_MS = 15 * 60 * 1000;

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
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function api(path, options = {}) {
  const headers = {"Content-Type": "application/json", ...(options.headers || {})};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const res = await fetch(path, {...options, headers});
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || "Request gagal.");
  return data;
}

async function deriveLocalKey(password, username, saltB64 = null) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const base = await crypto.subtle.importKey("raw", enc.encode(`${username}:${password}`), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256"},
    base,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt", "decrypt"]
  );
  return {key, saltB64: bytesToB64(salt)};
}

async function deriveBackupKey(password, username, saltB64 = null, iterations = BACKUP_KEY_ITERATIONS) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const material = `ONE_MIND backup:${username}:${password}`;
  const base = await crypto.subtle.importKey("raw", enc.encode(material), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    {name: "PBKDF2", salt, iterations, hash: "SHA-256"},
    base,
    {name: "AES-GCM", length: 256},
    false,
    ["encrypt", "decrypt"]
  );
  return {key, saltB64: bytesToB64(salt)};
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

async function createKeyBundle(username, password) {
  const dipp = generateDippKeypair();
  await savePrivateKey(username, password, dipp);
  return dipp.public;
}

async function savePrivateKey(username, password, dipp) {
  const {key, saltB64} = await deriveLocalKey(password, username);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({name: "AES-GCM", iv}, key, enc.encode(JSON.stringify(dipp)));
  localStorage.setItem(`om_private_${username}`, JSON.stringify({
    salt: saltB64,
    iv: bytesToB64(iv),
    cipher: bytesToB64(new Uint8Array(cipher)),
  }));
}

async function loadPrivateKey(username, password) {
  const raw = localStorage.getItem(`om_private_${username}`);
  if (!raw) throw new Error("Private key lokal tidak ada di browser ini.");
  const bundle = JSON.parse(raw);
  const {key} = await deriveLocalKey(password, username, bundle.salt);
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: b64ToBytes(bundle.iv)},
    key,
    b64ToBytes(bundle.cipher)
  );
  return JSON.parse(dec.decode(plain));
}

function hasLocalPrivateKey(username = state.username) {
  return Boolean(username && localStorage.getItem(`om_private_${username}`));
}

function isKeyUnlocked() {
  return Boolean(state.unlockedPrivateKey && Date.now() < state.keyUnlockedUntil);
}

function lockPrivateKeySession(reason = "Kunci lokal dikunci dari memory.") {
  state.unlockedPrivateKey = null;
  state.keyUnlockedUntil = 0;
  if (state.keyLockTimer) clearTimeout(state.keyLockTimer);
  state.keyLockTimer = null;
  updateLocalKeyStatus();
  if (reason) showNotice(reason);
}

function armKeyLockTimer() {
  if (state.keyLockTimer) clearTimeout(state.keyLockTimer);
  const delay = Math.max(0, state.keyUnlockedUntil - Date.now());
  state.keyLockTimer = setTimeout(() => lockPrivateKeySession("Session key timeout. Unlock ulang untuk membuka file."), delay);
}

async function unlockPrivateKeySession(password) {
  if (!state.username) throw new Error("Login diperlukan.");
  const privateKey = await loadPrivateKey(state.username, password);
  state.unlockedPrivateKey = privateKey;
  state.keyUnlockedUntil = Date.now() + SESSION_UNLOCK_MS;
  armKeyLockTimer();
  updateLocalKeyStatus();
  return privateKey;
}

async function ensureUnlockedPrivateKey() {
  if (isKeyUnlocked()) return state.unlockedPrivateKey;
  const password = prompt("Unlock private key session: masukkan password akun:");
  if (!password) throw new Error("Unlock dibatalkan.");
  return unlockPrivateKeySession(password);
}

function updateLocalKeyStatus() {
  const status = $("localKeyStatus");
  if (!status || !state.username) return;
  const hasKey = hasLocalPrivateKey();
  const unlocked = isKeyUnlocked();
  if (!hasKey) {
    status.textContent = "Kunci lokal belum ada di browser ini. Import encrypted private key sebelum membuka atau membagikan file lama.";
  } else if (unlocked) {
    const minutes = Math.max(1, Math.ceil((state.keyUnlockedUntil - Date.now()) / 60000));
    status.textContent = `Kunci lokal tersedia dan sedang unlocked di memory tab ini. Auto-lock sekitar ${minutes} menit lagi.`;
  } else {
    status.textContent = "Kunci lokal tersedia, tetapi terkunci. Unlock session sebelum download, share, update, atau export key.";
  }
  status.classList.toggle("missing", !hasKey);
  status.classList.toggle("locked", hasKey && !unlocked);
  status.classList.toggle("unlocked", hasKey && unlocked);
  $("unlockKeyBtn")?.classList.toggle("hidden", !hasKey || unlocked);
  $("lockKeyBtn")?.classList.toggle("hidden", !hasKey || !unlocked);
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

async function exportPrivateKeyBackup() {
  if (!state.username) throw new Error("Login diperlukan.");
  if (!hasLocalPrivateKey()) throw new Error("Private key lokal belum ada di browser ini.");
  const privateKey = await ensureUnlockedPrivateKey();
  const backupPassword = prompt("Buat password backup khusus untuk file export:");
  if (!backupPassword || backupPassword.length < 12) throw new Error("Password backup minimal 12 karakter.");
  const backupPasswordAgain = prompt("Ulangi password backup:");
  if (backupPassword !== backupPasswordAgain) throw new Error("Password backup tidak sama.");

  const {key, saltB64} = await deriveBackupKey(backupPassword, state.username);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const header = {
    app: "ONE_MIND",
    type: "encrypted-private-key-backup",
    version: 1,
    username: state.username,
    created_at: new Date().toISOString(),
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: BACKUP_KEY_ITERATIONS,
      salt_b64: saltB64,
    },
    cipher: {
      name: "AES-256-GCM",
      iv_b64: bytesToB64(iv),
    },
  };
  const aad = enc.encode(JSON.stringify(header));
  const cipher = await crypto.subtle.encrypt(
    {name: "AES-GCM", iv, additionalData: aad},
    key,
    enc.encode(JSON.stringify(privateKey))
  );
  downloadJson(`one-mind-${state.username}-private-key.one-mind-key`, {
    ...header,
    cipher: {...header.cipher, ciphertext_b64: bytesToB64(new Uint8Array(cipher))},
  });
  showNotice("Encrypted private key berhasil diexport. Simpan file dan password backup secara terpisah.");
}

async function importPrivateKeyBackup(file) {
  if (!state.username) throw new Error("Login diperlukan sebelum import key.");
  if (!file) return;
  const backup = JSON.parse(await file.text());
  if (backup.app !== "ONE_MIND" || backup.type !== "encrypted-private-key-backup" || backup.version !== 1) {
    throw new Error("Format backup key tidak dikenali.");
  }
  if (backup.username !== state.username) {
    throw new Error(`Backup ini milik akun ${backup.username}, bukan ${state.username}.`);
  }
  if (backup.kdf?.name !== "PBKDF2" || backup.kdf?.hash !== "SHA-256" || backup.cipher?.name !== "AES-256-GCM") {
    throw new Error("Parameter enkripsi backup tidak didukung.");
  }

  const backupPassword = prompt("Masukkan password backup untuk membuka file export:");
  if (!backupPassword) return;
  const accountPassword = prompt("Masukkan password akun untuk menyimpan private key di browser ini:");
  if (!accountPassword) return;
  const loginCheck = await api("/api/login", {
    method: "POST",
    body: JSON.stringify({username: state.username, password: accountPassword}),
  });
  state.token = loginCheck.token;
  localStorage.setItem("om_token", state.token);

  const {key} = await deriveBackupKey(backupPassword, backup.username, backup.kdf.salt_b64, backup.kdf.iterations);
  const aadHeader = {
    app: backup.app,
    type: backup.type,
    version: backup.version,
    username: backup.username,
    created_at: backup.created_at,
    kdf: backup.kdf,
    cipher: {
      name: backup.cipher.name,
      iv_b64: backup.cipher.iv_b64,
    },
  };
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: b64ToBytes(backup.cipher.iv_b64), additionalData: enc.encode(JSON.stringify(aadHeader))},
    key,
    b64ToBytes(backup.cipher.ciphertext_b64)
  );
  const privateKey = JSON.parse(dec.decode(plain));
  await savePrivateKey(state.username, accountPassword, privateKey);
  state.unlockedPrivateKey = privateKey;
  state.keyUnlockedUntil = Date.now() + SESSION_UNLOCK_MS;
  armKeyLockTimer();
  updateLocalKeyStatus();
  showNotice("Private key berhasil diimport ke browser ini.");
}

async function wrapFileKey(fileKey, recipientPublicKey) {
  const rawFileKey = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
  return dippWrapBytes(recipientPublicKey, rawFileKey);
}

async function unwrapFileKey(wrapped, privateKey) {
  const raw = dippUnwrapBytes(privateKey, wrapped);
  return crypto.subtle.importKey("raw", raw, {name: "AES-GCM"}, true, ["encrypt", "decrypt"]);
}

async function encryptFile(file) {
  const key = await crypto.subtle.generateKey({name: "AES-GCM", length: 256}, true, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await file.arrayBuffer());
  const aad = enc.encode(JSON.stringify({filename: file.name, type: file.type || "application/octet-stream"}));
  const cipher = await crypto.subtle.encrypt({name: "AES-GCM", iv, additionalData: aad}, key, data);
  return {
    key,
    envelope: {
      version: 2,
      algorithm: "AES-256-GCM",
      filename: file.name,
      mime: file.type || "application/octet-stream",
      aad_b64: bytesToB64(aad),
      iv_b64: bytesToB64(iv),
      ciphertext_b64: bytesToB64(new Uint8Array(cipher)),
    },
  };
}

async function decryptEnvelope(envelope, key) {
  const plain = await crypto.subtle.decrypt(
    {name: "AES-GCM", iv: b64ToBytes(envelope.iv_b64), additionalData: b64ToBytes(envelope.aad_b64)},
    key,
    b64ToBytes(envelope.ciphertext_b64)
  );
  return new Blob([plain], {type: envelope.mime || "application/octet-stream"});
}

async function getFileKey(fileId, password) {
  const file = await api(`/api/files/${fileId}`);
  const privateKey = password ? await unlockPrivateKeySession(password) : await ensureUnlockedPrivateKey();
  const fileKey = await unwrapFileKey(file.wrapped_key, privateKey);
  return {file, fileKey};
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
  if (!replacementFile || !replacementFile.size) return;
  const current = await getFileKey(fileId);
  await decryptEnvelope(current.file.envelope, current.fileKey);
  const encrypted = await encryptFile(replacementFile);
  const wrapped_keys = await wrapKeyForAccess(encrypted.key, fileId);
  await api(`/api/files/${fileId}`, {
    method: "PUT",
    body: JSON.stringify({
      filename: replacementFile.name,
      envelope: encrypted.envelope,
      wrapped_keys,
    }),
  });
  await refreshAll();
  showNotice("File berhasil diupdate. AES key baru sudah dibungkus ulang untuk semua user yang punya akses.");
}

async function rotateCurrentFileKey(fileId) {
  const current = await getFileKey(fileId);
  const blob = await decryptEnvelope(current.file.envelope, current.fileKey);
  const sameFile = new File([blob], current.file.filename, {type: current.file.envelope.mime || "application/octet-stream"});
  const encrypted = await encryptFile(sameFile);
  const wrapped_keys = await wrapKeyForAccess(encrypted.key, fileId);
  await api(`/api/files/${fileId}`, {
    method: "PUT",
    body: JSON.stringify({
      filename: current.file.filename,
      envelope: encrypted.envelope,
      wrapped_keys,
    }),
  });
  await refreshAll();
  await renderAccess(fileId);
  showNotice("AES key file berhasil dirotasi dan dibungkus ulang untuk akses aktif.");
}

function renderAuth() {
  const loggedIn = Boolean(state.token);
  $("authView")?.classList.toggle("hidden", loggedIn);
  $("appView")?.classList.toggle("hidden", !loggedIn);
  $("logoutBtn")?.classList.toggle("hidden", !loggedIn);
  if ($("sessionText")) $("sessionText").textContent = loggedIn ? `Login sebagai ${state.username}` : "Belum login";
  updateLocalKeyStatus();
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
  if ($("totalFiles")) $("totalFiles").textContent = String(state.files.length);
  if ($("ownedFiles")) $("ownedFiles").textContent = String(state.files.filter(f => f.owner === state.username).length);
  if ($("sharedFiles")) $("sharedFiles").textContent = String(state.files.filter(f => f.owner !== state.username).length);
  if ($("userCount")) $("userCount").textContent = String(state.users.length);

  const query = normalized(state.fileQuery);
  const filtered = state.files.filter(file => {
    const role = file.permission || (file.owner === state.username ? "owner" : "viewer");
    const haystack = normalized(`${file.filename} ${file.owner} ${role} ${file.created_at}`);
    const matchesQuery = !query || haystack.includes(query);
    const matchesScope =
      state.fileScope === "all" ||
      (state.fileScope === "owned" && file.owner === state.username) ||
      (state.fileScope === "shared" && file.owner !== state.username) ||
      (state.fileScope === "editor" && role === "editor") ||
      (state.fileScope === "viewer" && role === "viewer");
    return matchesQuery && matchesScope;
  });

  if (!state.files.length) {
    list.innerHTML = `<div class="emptyState"><strong>Belum ada file</strong><p>Upload file pertama dari tab Upload Terenkripsi.</p></div>`;
    return;
  }
  if (!filtered.length) {
    list.innerHTML = `<div class="emptyState"><strong>Tidak ada hasil</strong><p>Ubah kata kunci search atau filter file.</p></div>`;
    return;
  }
  for (const file of filtered) {
    const row = document.createElement("div");
    row.className = "item";
    const role = file.permission || (file.owner === state.username ? "owner" : "viewer");
    const actions = [
      `<button data-download="${file.id}">Unduh</button>`,
      canEdit(file) ? `<button class="ghost" data-update="${file.id}">Update & rotate key</button>` : "",
      canEdit(file) ? `<button class="ghost" data-rename="${file.id}">Rename</button>` : "",
      canManage(file) ? `<button class="ghost" data-access="${file.id}">Akses</button>` : "",
      canManage(file) ? `<button class="danger" data-delete="${file.id}">Delete</button>` : "",
    ].join("");
    row.innerHTML = `
      <div>
        <strong>${escapeHtml(file.filename)}</strong>
        <span class="meta">Pemilik: ${escapeHtml(file.owner)} | Role: ${escapeHtml(role)} | ${file.encrypted_size} byte | ${escapeHtml(file.created_at)}</span>
      </div>
      <div class="itemActions">${actions}</div>
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

on("registerForm", "submit", async (evt) => {
  evt.preventDefault();
  const form = new FormData(evt.currentTarget);
  const username = form.get("username").trim();
  const password = form.get("password");
  const publicKey = await createKeyBundle(username, password);
  const result = await api("/api/register", {
    method: "POST",
    body: JSON.stringify({
      username,
      display_name: form.get("display_name").trim(),
      password,
      public_key: publicKey,
    }),
  });
  state.token = result.token;
  state.username = result.username;
  localStorage.setItem("om_token", state.token);
  localStorage.setItem("om_username", state.username);
  renderAuth();
  await refreshAll();
  await unlockPrivateKeySession(password);
  showNotice("Akun dibuat. Keypair lokal sudah diamankan di browser ini.");
});

on("loginForm", "submit", async (evt) => {
  evt.preventDefault();
  const form = new FormData(evt.currentTarget);
  const username = form.get("username").trim();
  const password = form.get("password");
  const result = await api("/api/login", {method: "POST", body: JSON.stringify({username, password})});
  state.token = result.token;
  state.username = result.username;
  localStorage.setItem("om_token", state.token);
  localStorage.setItem("om_username", state.username);
  localStorage.removeItem("om_last_password_hint");
  renderAuth();
  await refreshAll();
  try {
    await unlockPrivateKeySession(password);
    showNotice("Login berhasil. Private key unlocked sementara di memory tab ini.");
  } catch {
    updateLocalKeyStatus();
    showNotice("Login berhasil, tetapi kunci lokal belum tersedia. Import encrypted private key sebelum membuka file lama.");
  }
});

on("uploadForm", "submit", async (evt) => {
  evt.preventDefault();
  const file = new FormData(evt.currentTarget).get("file");
  if (!file || !file.size) return;
  const me = await api("/api/me");
  const encrypted = await encryptFile(file);
  const wrapped = await wrapFileKey(encrypted.key, me.public_key);
  await api("/api/files", {
    method: "POST",
    body: JSON.stringify({filename: file.name, envelope: encrypted.envelope, wrapped_key_for_owner: wrapped}),
  });
  evt.currentTarget.reset();
  await refreshAll();
  showNotice("File dienkripsi di browser dan berhasil diupload.");
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
  const file = evt.currentTarget.files[0];
  const fileId = state.pendingUpdateFileId;
  try {
    if (fileId) await updateFileWithRotation(fileId, file);
  } finally {
    state.pendingUpdateFileId = null;
    evt.currentTarget.value = "";
  }
});
on("exportKeyBtn", "click", exportPrivateKeyBackup);
on("unlockKeyBtn", "click", async () => {
  const password = prompt("Masukkan password akun untuk unlock private key session:");
  if (!password) return;
  await unlockPrivateKeySession(password);
  showNotice("Private key unlocked di memory tab ini. Tidak disimpan sebagai plaintext.");
});
on("lockKeyBtn", "click", () => lockPrivateKeySession("Private key session dikunci."));
on("importKeyInput", "change", async (evt) => {
  const file = evt.currentTarget.files[0];
  try {
    await importPrivateKeyBackup(file);
  } finally {
    evt.currentTarget.value = "";
  }
});
on("logoutBtn", "click", () => {
  lockPrivateKeySession("");
  localStorage.removeItem("om_token");
  localStorage.removeItem("om_username");
  localStorage.removeItem("om_last_password_hint");
  state.token = null;
  state.username = null;
  renderAuth();
});
on("forgetLocalBtn", "click", () => {
  lockPrivateKeySession("");
  if (state.username) localStorage.removeItem(`om_private_${state.username}`);
  updateLocalKeyStatus();
  showNotice("Kunci lokal akun ini dihapus dari browser.");
});

window.addEventListener("unhandledrejection", evt => showNotice(evt.reason?.message || "Terjadi kesalahan."));
renderAuth();
refreshAll();
