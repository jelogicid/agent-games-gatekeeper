import { createRequire } from "module";
import fs from "fs";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((BigInt(x) % P) + P) % P;

// distinct values to discover public signal order
const base = {
  registeredVkHash: mod("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
  proofVkHash:      mod("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
  minimum: 1000n,
  publicBalance: 1460n,
  expiryBlock: 8430000n,
  currentBlock: 8420000n,
  recipient: mod("0xDe42000000000000000000000000000000009f01"),
  conditionRecipient: mod("0xDe42000000000000000000000000000000009f01"),
  amount: 500n,
  maxTransfer: 1000n,
  taskId: 987654321n,
  decision: 1n,
  salt: 42n,
};

async function tryCase(label, input) {
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
    console.log(`[OK] ${label}`);
    console.log("  publicSignals:", JSON.stringify(publicSignals));
    const vk = JSON.parse((await import("fs")).readFileSync("gatekeeper_vk.json", "utf8"));
    const ok = await snarkjs.groth16.verify(vk, publicSignals, proof);
    console.log("  verify:", ok);
    return publicSignals;
  } catch (e) {
    console.log(`[FAIL] ${label}: ${String(e.message || e).slice(0, 200)}`);
    return null;
  }
}

const ps = await tryCase("valid task, decision=1 (APPROVE)", base);
await tryCase("valid task, decision=0 (REJECT)", { ...base, decision: 0n });
await tryCase("vk mismatch, decision=1", { ...base, proofVkHash: mod("0x13aa"), decision: 1n });
await tryCase("vk mismatch, decision=0", { ...base, proofVkHash: mod("0x13aa"), decision: 0n });
await tryCase("balance below minimum, decision=0", { ...base, publicBalance: 900n, decision: 0n });
await tryCase("expired, decision=0", { ...base, currentBlock: 8440000n, decision: 0n });
await tryCase("recipient mismatch, decision=0", { ...base, recipient: mod("0xBad"), decision: 0n });
await tryCase("amount overflow, decision=0", { ...base, amount: 1500n, decision: 0n });
