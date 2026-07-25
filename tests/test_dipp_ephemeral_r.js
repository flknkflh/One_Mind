const assert = require("assert");
globalThis.crypto = require("crypto").webcrypto;
require("../static/dipp_ephemeral_r.js");

const D = globalThis.OneMindDippEphemeralR;

function hex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function bitsFromBytes(bytes) {
  const bits = [];
  for (const byte of bytes) {
    for (let shift = 7; shift >= 0; shift -= 1) bits.push((byte >>> shift) & 1);
  }
  return bits;
}

(async () => {
  assert.strictEqual(D.PROTOCOL, "ONE_MIND_DIPP_EPHEMERAL_R_STANDALONE");
  assert.strictEqual(D.PARAMS.dimension, 64);
  assert.strictEqual(D.PARAMS.publicPointCount, 16);
  assert.strictEqual(D.PARAMS.modulus, 65536);
  assert.strictEqual(D.PARAMS.preKeyBits, 256);
  assert.strictEqual(D.PARAMS.secretPointWeight, 8);
  assert.strictEqual(D.PARAMS.secretRadiusMinPermille, 2000);
  assert.strictEqual(D.PARAMS.secretRadiusMaxPermille, 4000);

  assert.strictEqual(
    hex(D.shake256(new Uint8Array(), 64)),
    "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
    "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
  );

  const deterministicSeed = new Uint8Array(32).map((_, index) => index);
  assert.deepStrictEqual(
    D.derivePublicPoints(deterministicSeed),
    D.derivePublicPoints(deterministicSeed)
  );

  const alice = await D.generateIdentity("alice", "alice-password-kuat");
  const bob = await D.generateIdentity("bob", "bob-password-kuat");
  D.validatePublicKey(alice.public, "alice");
  D.validatePublicKey(bob.public, "bob");
  assert.strictEqual("bob_private_point" in bob.public, false);
  assert.strictEqual("public_jwk" in bob.public, false);
  assert.strictEqual("pairing_curve" in bob.public, false);
  assert.strictEqual(D.VAULT_VERSION, 8);

  const opened = await D.openIdentity(bob.sealed, "bob", "bob-password-kuat");
  assert.strictEqual(opened.public.key_id, bob.public.key_id);
  await assert.rejects(
    D.openIdentity(bob.sealed, "bob", "password-salah"),
    /Password salah/
  );

  const rsa = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-512",
    },
    false,
    ["sign", "verify"]
  );
  const fileKey = crypto.getRandomValues(new Uint8Array(32));
  const metadata = {
    sender_id: "alice",
    recipient_id: "bob",
    file_context_id: D.b64url(crypto.getRandomValues(new Uint8Array(24))),
  };
  const signer = async hash => new Uint8Array(await crypto.subtle.sign(
    {name: "RSASSA-PKCS1-v1_5"}, rsa.privateKey, hash
  ));
  const verifier = (hash, signature) => crypto.subtle.verify(
    {name: "RSASSA-PKCS1-v1_5"}, rsa.publicKey, signature, hash
  );

  const first = await D.wrapFileKey(bob.public, fileKey, metadata, signer);
  D.validateEnvelope(first);
  assert.strictEqual(first.dipp_components.length, 256);
  assert.strictEqual(first.recipient_key_id, bob.public.key_id);
  assert.strictEqual(first.public_seed, bob.public.public_seed);
  assert.strictEqual(first.B_b, bob.public.B_b);
  assert.strictEqual(first.key_establishment_algorithm, "DIPP-ER-WEIGHTED-v2");
  assert.strictEqual(first.algorithms.geometry, "FIXED-WEISZFELD-24-WEIGHTED-8");
  assert.strictEqual(first.wrap_algorithm, "AES-256-GCM");
  assert.strictEqual(D.fromB64url(first.wrap_nonce).length, 12);
  assert.strictEqual(D.fromB64url(first.wrapped_file_key).length, 48);
  assert.strictEqual(first.algorithms.extractor, "HKDF-SHA-256");

  const recovered = await D.unwrapFileKey(bob, first, verifier);
  assert.strictEqual(D.equalBytes(recovered, fileKey), true);

  const second = await D.wrapFileKey(bob.public, fileKey, metadata, signer);
  assert.notStrictEqual(second.session_id, first.session_id);
  assert.notStrictEqual(second.dipp_components[0].U, first.dipp_components[0].U);
  assert.strictEqual(
    D.equalBytes(await D.unwrapFileKey(bob, second, verifier), fileKey),
    true
  );

  for (let attempt = 0; attempt < 3; attempt += 1) {
    const repeated = await D.wrapFileKey(bob.public, fileKey, metadata, signer);
    const repeatedRecovered = await D.unwrapFileKey(bob, repeated, verifier);
    assert.strictEqual(D.equalBytes(repeatedRecovered, fileKey), true);
  }

  const originalGetRandomValues = crypto.getRandomValues.bind(crypto);
  let capturePreKey = false;
  let capturedPreKey = null;
  crypto.getRandomValues = array => {
    const result = originalGetRandomValues(array);
    if (
      capturePreKey
      && capturedPreKey === null
      && array instanceof Uint8Array
      && array.length === 32
    ) {
      capturedPreKey = new Uint8Array(array);
    }
    return result;
  };
  let thresholdCorrect = 0;
  let thresholdBits = 0;
  try {
    for (let sample = 0; sample < 4; sample += 1) {
      capturedPreKey = null;
      capturePreKey = true;
      const audit = await D.encapsulate(bob.public, {
        sender_id: "alice",
        recipient_id: "bob",
        session_id: D.b64url(originalGetRandomValues(new Uint8Array(24))),
        file_context_id: D.b64url(originalGetRandomValues(new Uint8Array(24))),
      });
      capturePreKey = false;
      assert.ok(capturedPreKey);
      const auditBits = bitsFromBytes(capturedPreKey);
      audit.components.forEach((component, index) => {
        thresholdCorrect += Number(
          (component.V >= D.PARAMS.modulus / 2 ? 1 : 0) === auditBits[index]
        );
        thresholdBits += 1;
      });
      audit.dippKey.fill(0);
      capturedPreKey.fill(0);
    }
  } finally {
    capturePreKey = false;
    crypto.getRandomValues = originalGetRandomValues;
  }
  const rawThresholdAccuracy = Math.max(
    thresholdCorrect,
    thresholdBits - thresholdCorrect
  ) / thresholdBits;
  assert.ok(
    rawThresholdAccuracy < 0.8,
    `Distribusi V_i kembali terpisah: accuracy=${rawThresholdAccuracy}`
  );

  const changed = structuredClone(first);
  changed.dipp_components[0].V = (changed.dipp_components[0].V + 1) % D.PARAMS.modulus;
  await assert.rejects(
    D.unwrapFileKey(bob, changed, verifier),
    /Decapsulation Ephemeral-R gagal/
  );

  const badSignature = structuredClone(first);
  badSignature.sender_signature = D.b64url(new Uint8Array(512));
  await assert.rejects(
    D.unwrapFileKey(bob, badSignature, verifier),
    /Decapsulation Ephemeral-R gagal/
  );

  console.log(
    `DIPP Ephemeral-R weighted v2 lulus; raw V threshold accuracy=${rawThresholdAccuracy.toFixed(4)}.`
  );
})().catch(error => {
  console.error(error);
  process.exit(1);
});
