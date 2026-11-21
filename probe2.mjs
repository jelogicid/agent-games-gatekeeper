import fs from "fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

function fnvHash(str) {
  const max = 2n ** 64n;
  let h = 0xCBF29CE484222325n;
  for (const c of str) { h ^= BigInt(c.charCodeAt(0)); h = (h * 0x100000001B3n) % max; }
  const s = h.toString(16).padStart(16, "0");
  return [parseInt(s.slice(0, 8), 16), parseInt(s.slice(8, 16), 16)];
}

const gk = ["registeredVk","proofVk","registeredVK","proofVK","vkRegistered","vkProof","conditionVk","expectedVk","actualVk",
"vk1","vk2","vkA","vkB","registered","proof","vk","registeredVkHash","proofVkHash","vkHashRegistered","vkHashProof",
"proofTxHash","txHash","proofRef","proofReference","reuseFlag","seen","used","reused","isReused","proofUsed",
"taskIdHash","taskHash","id","nonce","salt","decisionBit","approveBit","reasonCode","reason","code",
"minimumBalance","balanceMin","requiredMinimum","threshold","cap","expiry","current","blockHeight",
"recipientAddr","conditionRecipientAddr","addr","to","from","payer","payee"];

const vfy = ["turn","turnNumber","turnIndex","selfFortified","opponentFortified","selfFortifiedUntil","opponentFortifiedUntil",
"fortifiedSelf","fortifiedOpponent","selfFortify","opponentFortify","fortifySelf","fortifyOpponent",
"params","policyParams","p0","p1","p2","p3","p4","p5","p6","p7","p8","p9",
"strategy","strategyHash","commitmentHash","strategyCommitment","extractCap","maxExtract","fortifyCost","blockGain",
"selfFortifiedUntilTurn","opponentFortifiedUntilTurn","fortifiedUntilSelf","fortifiedUntilOpponent",
"nonce","salt","matchIdHash","turnHash","stateHash","publicInputsHash","actionAmount","amountExtract",
"selfBalanceStart","opponentBalanceStart","pot","round","swissRound"];

for (const [name, cands] of [["gatekeeper", gk], ["vfy-policy", vfy]]) {
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(`circuits/${name}.wasm`), { sanityCheck: true });
  const inst = wc.instance;
  console.log(`=== ${name} === total=${inst.exports.getInputSize()}`);
  for (const c of cands) {
    const [msb, lsb] = fnvHash(c);
    try {
      const size = inst.exports.getInputSignalSize(msb, lsb);
      if (size > 0) console.log(`  INPUT ${c} size=${size}`);
    } catch (e) {}
  }
}
