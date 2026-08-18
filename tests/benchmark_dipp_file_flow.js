"use strict";

const assert = require("assert");
const fs = require("fs/promises");
const os = require("os");
const path = require("path");
const {createHash, webcrypto} = require("crypto");
const {performance} = require("perf_hooks");

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {value: webcrypto});
}
require("../static/dipp_ephemeral_r.js");

const D = globalThis.OneMindDippEphemeralR;

function elapsed(start) {
  return performance.now() - start;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function average(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function round(value) {
  return Math.round(value * 100) / 100;
}

async function measureFlow(sizeBytes, iteration, recipient, signingPair, storageDir) {
  const plaintext = new Uint8Array(sizeBytes);
  for (let offset = 0; offset < plaintext.length; offset += 4096) {
    plaintext[offset] = (offset / 4096 + iteration) & 0xff;
  }
  const expectedDigest = digest(plaintext);
  const fileContextId = D.b64url(crypto.getRandomValues(new Uint8Array(24)));
  const fileAad = D.encodeCanonical({
    filename: `benchmark-${sizeBytes}-${iteration}.bin`,
    type: "application/octet-stream",
  });

  let start = performance.now();
  const fileKey = await crypto.subtle.generateKey(
    {name: "AES-GCM", length: 256},
    true,
    ["encrypt", "decrypt"]
  );
  const fileIv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {name: "AES-GCM", iv: fileIv, additionalData: fileAad},
    fileKey,
    plaintext
  ));
  const encryptMs = elapsed(start);

  const rawFileKey = new Uint8Array(await crypto.subtle.exportKey("raw", fileKey));
  start = performance.now();
  const wrapped = await D.wrapFileKey(
    recipient.public,
    rawFileKey,
    {
      sender_id: "alice",
      recipient_id: "bob",
      file_context_id: fileContextId,
    },
    async hash => new Uint8Array(await crypto.subtle.sign(
      {name: "RSASSA-PKCS1-v1_5"},
      signingPair.privateKey,
      hash
    ))
  );
  const dippWrapMs = elapsed(start);
  rawFileKey.fill(0);

  // Persist ciphertext and its envelope separately, matching the application's
  // storage model closely enough to include local disk I/O in the benchmark.
  const itemName = `dipp-${sizeBytes}-${iteration}-${Date.now()}`;
  const ciphertextPath = path.join(storageDir, `${itemName}.bin`);
  const envelopePath = path.join(storageDir, `${itemName}.json`);
  start = performance.now();
  await Promise.all([
    fs.writeFile(ciphertextPath, ciphertext),
    fs.writeFile(envelopePath, JSON.stringify({
      fileIv: D.b64url(fileIv),
      fileAad: D.b64url(fileAad),
      wrapped,
    })),
  ]);
  const saveDiskMs = elapsed(start);

  start = performance.now();
  const [storedCiphertext, storedEnvelopeText] = await Promise.all([
    fs.readFile(ciphertextPath),
    fs.readFile(envelopePath, "utf8"),
  ]);
  const storedEnvelope = JSON.parse(storedEnvelopeText);
  const loadDiskMs = elapsed(start);

  start = performance.now();
  const recoveredRaw = await D.unwrapFileKey(
    recipient,
    storedEnvelope.wrapped,
    (hash, signature) => crypto.subtle.verify(
      {name: "RSASSA-PKCS1-v1_5"},
      signingPair.publicKey,
      signature,
      hash
    )
  );
  const dippUnwrapMs = elapsed(start);

  const recoveredFileKey = await crypto.subtle.importKey(
    "raw",
    recoveredRaw,
    {name: "AES-GCM"},
    false,
    ["decrypt"]
  );
  recoveredRaw.fill(0);

  start = performance.now();
  const recoveredPlaintext = new Uint8Array(await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: D.fromB64url(storedEnvelope.fileIv),
      additionalData: D.fromB64url(storedEnvelope.fileAad),
    },
    recoveredFileKey,
    storedCiphertext
  ));
  const decryptMs = elapsed(start);

  assert.strictEqual(recoveredPlaintext.length, plaintext.length);
  assert.strictEqual(digest(recoveredPlaintext), expectedDigest);
  assert.strictEqual(storedCiphertext.length, plaintext.length + 16);

  plaintext.fill(0);
  recoveredPlaintext.fill(0);
  storedCiphertext.fill(0);
  await Promise.all([fs.unlink(ciphertextPath), fs.unlink(envelopePath)]);

  return {
    encryptMs,
    dippWrapMs,
    saveDiskMs,
    loadDiskMs,
    dippUnwrapMs,
    decryptMs,
    totalMs: encryptMs + dippWrapMs + saveDiskMs + loadDiskMs + dippUnwrapMs + decryptMs,
  };
}

(async () => {
  const identityStart = performance.now();
  const recipient = await D.generateIdentity("bob", "benchmark-password-kuat");
  const identityMs = elapsed(identityStart);

  const signingStart = performance.now();
  const signingPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-512",
    },
    false,
    ["sign", "verify"]
  );
  const signingKeygenMs = elapsed(signingStart);
  const storageDir = await fs.mkdtemp(path.join(os.tmpdir(), "one-mind-dipp-benchmark-"));

  // Warm up the fixed-point/BigInt geometry and Web Crypto paths. This result
  // is intentionally excluded so file-size ordering does not bias DIPP timing.
  await measureFlow(64 * 1024, -1, recipient, signingPair, storageDir);

  const sizesMiB = (process.env.DIPP_BENCH_SIZES_MIB || "1,10,50")
    .split(",")
    .map(value => Number.parseInt(value.trim(), 10))
    .filter(value => Number.isSafeInteger(value) && value > 0);
  const repetitions = Number.parseInt(process.env.DIPP_BENCH_REPETITIONS || "3", 10);
  const results = [];

  for (const sizeMiB of sizesMiB) {
    const samples = [];
    for (let iteration = 0; iteration < repetitions; iteration += 1) {
      samples.push(await measureFlow(
        sizeMiB * 1024 * 1024,
        iteration,
        recipient,
        signingPair,
        storageDir
      ));
    }
    results.push({
      sizeMiB,
      repetitions,
      averageMs: Object.fromEntries(
        Object.keys(samples[0]).map(key => [key, round(average(samples.map(sample => sample[key])))])
      ),
      runsMs: samples.map(sample => Object.fromEntries(
        Object.entries(sample).map(([key, value]) => [key, round(value)])
      )),
    });
  }

  await fs.rmdir(storageDir);

  process.stdout.write(JSON.stringify({
    profile: D.PARAMS.id,
    identityGenerationMs: round(identityMs),
    rsa4096GenerationMs: round(signingKeygenMs),
    results,
  }, null, 2) + "\n");
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
