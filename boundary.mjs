import { createRequire } from "module";
const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (x) => ((BigInt(x) % P) + P) % P;
const VK = mod("0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0");
const R = mod("0xDe42000000000000000000000000000000009f01");
const base = { registeredVkHash: VK, proofVkHash: VK, minimum: 1000n, publicBalance: 1460n,
  expiryBlock: 8430000n, currentBlock: 8420000n, recipient: R, conditionRecipient: R,
  amount: 500n, maxTransfer: 1000n, taskId: 987654321n, decision: 1n, salt: 42n };
async function t(label, input) {
  try {
    await snarkjs.groth16.fullProve(input, "circuits/gatekeeper.wasm", "circuits/gatekeeper_final.zkey");
    console.log(`[PROVABLE] ${label}`);
  } catch(e) { console.log(`[BLOCKED]  ${label}`); }
}
await t("balance == minimum, approve", {...base, publicBalance: 1000n});
await t("balance == minimum-1, approve", {...base, publicBalance: 999n});
await t("currentBlock == expiryBlock, approve", {...base, currentBlock: 8430000n});
await t("currentBlock == expiryBlock-1, approve", {...base, currentBlock: 8429999n});
await t("amount == maxTransfer, approve", {...base, amount: 1000n});
await t("amount == maxTransfer+1, approve", {...base, amount: 1001n});
await t("amount == 0, approve", {...base, amount: 0n});
await t("amount > balance, approve", {...base, amount: 1461n, maxTransfer: 2000n});
process.exit(0);
