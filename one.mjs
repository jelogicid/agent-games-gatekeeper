import { createRequire } from "module";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((BigInt(x) % P) + P) % P;
const input = {
  registeredVkHash: mod("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
  proofVkHash: mod("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"),
  minimum: 1000n, publicBalance: 1460n, expiryBlock: 8430000n, currentBlock: 8420000n,
  recipient: mod("0xDe42000000000000000000000000000000009f01"),
  conditionRecipient: mod("0xDe42000000000000000000000000000000009f01"),
  amount: 500n, maxTransfer: 1000n, taskId: 987654321n, decision: 1n, salt: 42n,
};
const t0 = Date.now();
try {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
  console.log("PROVE OK in", Date.now()-t0, "ms");
  console.log("publicSignals:", JSON.stringify(publicSignals));
} catch(e) { console.log("PROVE FAIL after", Date.now()-t0, "ms:", String(e.message||e).slice(0,400)); }
process.exit(0);
