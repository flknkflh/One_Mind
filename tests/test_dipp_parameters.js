const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const {randomBytes, webcrypto} = require("crypto");

const appSource = fs.readFileSync(
  path.join(__dirname, "..", "static", "app.js"),
  "utf8"
);
const coreStart = appSource.indexOf("const DIPP_ALGORITHM_NAME");
const coreEnd = appSource.indexOf("async function generatePKIKeypair");
const wrapStart = appSource.indexOf("function dippWrapBytes");
const wrapEnd = appSource.indexOf("async function exportPKIPublicKey", wrapStart);

assert(coreStart >= 0, "DIPP constants tidak ditemukan.");
assert(coreEnd > coreStart, "Batas DIPP core tidak ditemukan.");
assert(wrapStart >= 0, "DIPP wrap tidak ditemukan.");
assert(wrapEnd > wrapStart, "Batas DIPP wrap tidak ditemukan.");

const context = {console, crypto: webcrypto};
vm.createContext(context);
vm.runInContext(
  appSource.slice(coreStart, coreEnd)
    + appSource.slice(wrapStart, wrapEnd)
    + ";globalThis.dipp={DIPP_PARAMS,generateDippKeypair,dippWrapBytes,dippUnwrapBytes};",
  context
);

const {
  DIPP_PARAMS,
  generateDippKeypair,
  dippWrapBytes,
  dippUnwrapBytes,
} = context.dipp;

assert.deepStrictEqual(JSON.parse(JSON.stringify(DIPP_PARAMS)), {
  dim: 3,
  n_pub: 20,
  coord_max: 1000,
  w_range: [0.01, 0.15],
  delta_range: [-0.1, 0.1],
  q: 4096,
  scale: 100,
  error_bound: 8,
  error_geser: 0,
  dither_bound: 0,
  v_shift_bound: 8,
  repeat: 5,
});

let trials = 0;
for (let keypairIndex = 0; keypairIndex < 25; keypairIndex++) {
  const pair = generateDippKeypair();
  assert.strictEqual(pair.public.version, 2);
  assert.strictEqual(pair.public.n_pub, 20);
  assert.strictEqual(pair.public.q, 4096);
  assert.strictEqual(pair.public.dither_bound, 0);
  assert.strictEqual(pair.public.v_shift_bound, 8);

  for (let wrapIndex = 0; wrapIndex < 20; wrapIndex++) {
    const rawKey = new Uint8Array(randomBytes(32));
    const wrapped = dippWrapBytes(pair.public, rawKey);
    assert.strictEqual(wrapped.version, 2);
    assert.strictEqual(wrapped.dither_bound, 0);
    assert.strictEqual(wrapped.v_shift_bound, 8);
    const opened = dippUnwrapBytes(pair, wrapped);
    assert.deepStrictEqual(Array.from(opened), Array.from(rawKey));
    trials++;
  }
}

// Public key format v1 tetap dapat dipakai agar identitas lama tidak langsung rusak.
const legacyParams = {
  ...DIPP_PARAMS,
  n_pub: 40,
  q: 65536,
  error_bound: 50,
  error_geser: 10,
  dither_bound: 0,
  v_shift_bound: 0,
};
const legacyPair = generateDippKeypair(legacyParams);
legacyPair.public.version = 1;
legacyPair.public.algorithm = "DIPP-KEM-v1 (Weiszfeld, mirip FrodoKEM)";
delete legacyPair.public.dither_bound;
delete legacyPair.public.v_shift_bound;
const legacyRawKey = new Uint8Array(randomBytes(32));
const legacyWrapped = dippWrapBytes(legacyPair.public, legacyRawKey);
delete legacyWrapped.dither_bound;
delete legacyWrapped.v_shift_bound;
assert.deepStrictEqual(
  Array.from(dippUnwrapBytes(legacyPair, legacyWrapped)),
  Array.from(legacyRawKey)
);

console.log(
  `DIPP v2: ${trials}/${trials} wrap-unwrap berhasil; kompatibilitas key v1 berhasil.`
);
