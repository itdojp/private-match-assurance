#!/usr/bin/env node
/* Fixture-only Ed25519 and DSSE primitive for the public release profile. */

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const MAX_STDIN_BYTES = 4 * 1024 * 1024;
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE_KEYS = Object.freeze({
  "release-signing": path.join(
    ROOT,
    "tests/fixtures/public-release/keys/release-private.pem",
  ),
  "release-status-signing": path.join(
    ROOT,
    "tests/fixtures/public-release/keys/status-private.pem",
  ),
});

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

function strictBase64(value, label) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    fail(`${label} is not canonical base64`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) {
    fail(`${label} is not canonical base64`);
  }
  return decoded;
}

function pae(payloadType, payload) {
  const type = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "ascii"),
    type,
    Buffer.from(` ${payload.length} `, "ascii"),
    payload,
  ]);
}

function keyId(publicKey) {
  const der = publicKey.export({ format: "der", type: "spki" });
  return `sha256:${createHash("sha256").update(der).digest("hex")}`;
}

async function readInput() {
  const chunks = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > MAX_STDIN_BYTES) {
      fail("crypto input exceeds the configured bound");
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    fail("crypto input is not strict JSON");
  }
}

function assertPayload(input) {
  if (
    input === null ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    typeof input.payload_type !== "string" ||
    !input.payload_type ||
    typeof input.payload !== "string"
  ) {
    fail("crypto payload contract is invalid");
  }
  return strictBase64(input.payload, "payload");
}

function rfc8032Vector() {
  const vectors = [
    {
      id: "RFC8032-7.1-TEST-1",
      seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      message: "",
      signature:
        "e5564300c360ac729086e2cc806e828a" +
        "84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46b" +
        "d25bf5f0595bbe24655141438e7a100b",
    },
    {
      id: "RFC8032-7.1-TEST-2",
      seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      publicKey: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      message: "72",
      signature:
        "92a009a9f0d4cab8720e820b5f642540" +
        "a2b27b5416503f8fb3762223ebdb69da" +
        "085ac1e43e15996e458f3613d0f11d8c" +
        "387b2eaeb4302aeeb00d291612bb0c00",
    },
  ];
  for (const vector of vectors) {
    const privateDer = Buffer.from(
      "302e020100300506032b657004220420" + vector.seed,
      "hex",
    );
    const key = createPrivateKey({ key: privateDer, format: "der", type: "pkcs8" });
    const publicKey = createPublicKey(key);
    const message = Buffer.from(vector.message, "hex");
    const actual = sign(null, message, key);
    const publicRaw = publicKey
      .export({ format: "der", type: "spki" })
      .subarray(-32)
      .toString("hex");
    if (
      actual.toString("hex") !== vector.signature ||
      publicRaw !== vector.publicKey ||
      !verify(null, message, publicKey, actual)
    ) {
      fail("RFC 8032 Ed25519 test vector failed");
    }
  }
  return {
    algorithm: "ed25519-rfc8032",
    vectors: vectors.map((vector) => vector.id),
    verified: true,
  };
}

const [operation, usage] = process.argv.slice(2);
if (operation === "rfc8032-test") {
  process.stdout.write(`${JSON.stringify(rfc8032Vector())}\n`);
  process.exit(0);
}

const input = await readInput();
const payload = assertPayload(input);
const message = pae(input.payload_type, payload);

if (operation === "sign-fixture") {
  const keyPath = FIXTURE_KEYS[usage];
  const expectedPayloadType = {
    "release-signing":
      "application/vnd.itdo.private-match.assurance-release-manifest.v0.1+json",
    "release-status-signing":
      "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
  }[usage];
  if (
    !keyPath ||
    input.usage !== usage ||
    input.artifact_status !== "test-only" ||
    input.payload_type !== expectedPayloadType
  ) {
    fail("fixture signing authority is not permitted");
  }
  const privateKey = createPrivateKey(readFileSync(keyPath));
  const publicKey = createPublicKey(privateKey);
  const signature = sign(null, message, privateKey);
  process.stdout.write(
    `${JSON.stringify({
      algorithm: "ed25519-rfc8032",
      keyid: keyId(publicKey),
      sig: signature.toString("base64"),
    })}\n`,
  );
  process.exit(0);
}

if (operation === "verify") {
  if (
    input.algorithm !== "ed25519-rfc8032" ||
    typeof input.public_key_spki !== "string" ||
    typeof input.signature !== "string"
  ) {
    fail("verification authority is unsupported");
  }
  const publicDer = strictBase64(input.public_key_spki, "public key");
  const signature = strictBase64(input.signature, "signature");
  if (signature.length !== 64) {
    fail("signature length is invalid");
  }
  let publicKey;
  try {
    publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" });
  } catch {
    fail("public key is malformed");
  }
  process.stdout.write(
    `${JSON.stringify({ keyid: keyId(publicKey), verified: verify(null, message, publicKey, signature) })}\n`,
  );
  process.exit(0);
}

fail("crypto operation is unsupported");
