"use strict";

const {webcrypto} = require("crypto");
if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {value: webcrypto});
}
require("../static/dipp_ephemeral_r.js");

const D = globalThis.OneMindDippEphemeralR;

function bitsFromBytes(bytes) {
  const bits = [];
  for (const byte of bytes) {
    for (let shift = 7; shift >= 0; shift -= 1) {
      bits.push((byte >>> shift) & 1);
    }
  }
  return bits;
}

function hex(value) {
  return `0x${value.toString(16).toUpperCase().padStart(4, "0")}`;
}

(async () => {
  const bob = await D.generateIdentity("bob", "sample-password-kuat");
  const originalGetRandomValues = crypto.getRandomValues.bind(crypto);
  let capturedPreKey = null;
  let capture = true;

  crypto.getRandomValues = array => {
    const result = originalGetRandomValues(array);
    if (capture && capturedPreKey === null && array instanceof Uint8Array && array.length === 32) {
      capturedPreKey = new Uint8Array(array);
    }
    return result;
  };

  let encapsulation;
  try {
    encapsulation = await D.encapsulate(bob.public, {
      sender_id: "alice",
      recipient_id: "bob",
      session_id: D.b64url(originalGetRandomValues(new Uint8Array(24))),
      file_context_id: D.b64url(originalGetRandomValues(new Uint8Array(24))),
    });
  } finally {
    capture = false;
    crypto.getRandomValues = originalGetRandomValues;
  }

  if (!capturedPreKey) throw new Error("Pre-key audit tidak tertangkap.");
  const bits = bitsFromBytes(capturedPreKey);
  const values = encapsulation.components.map(component => component.V);
  let thresholdCorrect = 0;
  const rows = values.map((value, index) => {
    const prediction = value >= D.PARAMS.modulus / 2 ? 1 : 0;
    thresholdCorrect += Number(prediction === bits[index]);
    return {
      i: index + 1,
      bit: bits[index],
      V: value,
      V_hex: hex(value),
      half: prediction === 0 ? "LOW" : "HIGH",
    };
  });
  const directAccuracy = thresholdCorrect / rows.length;
  const fixedAccuracy = Math.max(directAccuracy, 1 - directAccuracy);

  process.stdout.write(JSON.stringify({
    profile: D.PARAMS.id,
    modulus: D.PARAMS.modulus,
    halfModulus: D.PARAMS.modulus / 2,
    sampleRows: rows.slice(0, 64),
    allValues: values,
    summary: {
      count: values.length,
      min: Math.min(...values),
      max: Math.max(...values),
      unique: new Set(values).size,
      fixedThresholdAccuracy: fixedAccuracy,
      bit0Low: rows.filter(row => row.bit === 0 && row.half === "LOW").length,
      bit0High: rows.filter(row => row.bit === 0 && row.half === "HIGH").length,
      bit1Low: rows.filter(row => row.bit === 1 && row.half === "LOW").length,
      bit1High: rows.filter(row => row.bit === 1 && row.half === "HIGH").length,
    },
  }, null, 2) + "\n");

  capturedPreKey.fill(0);
  encapsulation.dippKey.fill(0);
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
