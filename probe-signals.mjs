import fs from "fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

function fnvHash(str) {
  const max = 2n ** 64n;
  let h = 0xCBF29CE484222325n;
  for (const c of str) { h ^= BigInt(c.charCodeAt(0)); h = (h * 0x100000001B3n) % max; }
  const s = h.toString(16).padStart(16, "0");
  return [parseInt(s.slice(0, 8), 16), parseInt(s.slice(8, 16), 16)];
}

const candidates = [
  // task fields snake_case
  "registered_vk","proof_vk","minimum","public_balance","expiry_block","current_block",
  "recipient","condition_recipient","amount","max_transfer","proof_tx","task_id",
  "decision","reason_code","reason","vk_hash","proof_vk_hash","registered_vk_hash",
  "balance","threshold","expiry","block","cap","transfer_cap","nonce","issued_at","deadline_at",
  // camelCase
  "registeredVk","proofVk","publicBalance","expiryBlock","currentBlock","conditionRecipient",
  "maxTransfer","proofTx","taskId","reasonCode","vkHash","minimumThreshold",
  // decision-related
  "approve","reject","valid","is_valid","isValid","vk_match","vkMatch","recipient_match",
  "recipientMatch","threshold_ok","thresholdOk","amount_ok","amountOk","not_expired","notExpired",
  "not_reused","notReused","decision_bit","decisionBit","out","result","verdict",
  // hashes / commitments
  "task_hash","taskHash","input_hash","inputHash","statement","statement_hash","statementHash",
  "public_inputs_hash","publicInputsHash","commitment","salt","params",
  // steal-the-vfy fields
  "selfBalance","opponentBalance","self_balance","opponent_balance","turn","matchId","match_id",
  "action","actionType","action_type","fortified","selfFortifiedUntilTurn","opponentFortifiedUntilTurn",
  "strategyCommitment","commitmentHash","circuitVersion","circuit_version","pot","balanceSelf","balanceOpponent",
];

for (const name of ["gatekeeper", "vfy-policy"]) {
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(`circuits/${name}.wasm`), { sanityCheck: true });
  const inst = wc.instance;
  console.log(`=== ${name} === total input scalars: ${inst.exports.getInputSize()}`);
  const found = [];
  for (const c of candidates) {
    const [msb, lsb] = fnvHash(c);
    try {
      const size = inst.exports.getInputSignalSize(msb, lsb);
      if (size >= 0) found.push([c, size]);
    } catch (e) {}
  }
  for (const [c, s] of found) console.log(`  INPUT ${c} size=${s}`);
  if (!found.length) console.log("  (no candidate matched)");
}
