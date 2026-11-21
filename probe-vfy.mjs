import fs from "fs";
import { WitnessCalculatorBuilder } from "circom_runtime";
function fnvHash(str){const max=2n**64n;let h=0xCBF29CE484222325n;for(const c of str){h^=BigInt(c.charCodeAt(0));h=(h*0x100000001B3n)%max;}const s=h.toString(16).padStart(16,"0");return [parseInt(s.slice(0,8),16),parseInt(s.slice(8,16),16)];}
const base=["commitment","strategyCommitment","commitmentHash","strategyHash","policyHash","policyCommitment",
"matchId","match","matchHash","matchIdHash","turn","turnNumber","turnIndex","round","swissRound",
"selfBalance","ownBalance","myBalance","balanceSelf","balanceA","balance1","playerBalance",
"opponentBalance","opponentBal","balanceOpponent","balanceB","balance2","enemyBalance","rivalBalance",
"action","actionType","actionCode","move","moveType","decision","actionBit",
"amount","actionAmount","extractAmount","transferAmount","value",
"circuitVersion","version","policyVersion","resolverVersion","v",
"selfFortified","opponentFortified","selfFortifiedUntil","opponentFortifiedUntil","fortifiedSelf","fortifiedOpponent",
"selfFortifiedUntilTurn","opponentFortifiedUntilTurn","fortifyCost","extractCap","maxExtract","minBalance",
"nonce","salt","deadline","timestamp","issuedAt","ts",
"allowed","isAllowed","valid","ok","permitted","legalMove","agent","strategy","params","policy"];
const wc=await WitnessCalculatorBuilder(fs.readFileSync("circuits/vfy-policy.wasm"),{sanityCheck:true});
const inst=wc.instance;
console.log("inputSize total:",inst.exports.getInputSize());
for(const c of base){
  const [msb,lsb]=fnvHash(c);
  try{const size=inst.exports.getInputSignalSize(msb,lsb);if(size>0)console.log(`INPUT ${c} size=${size}`);}catch(e){}
}
console.log("--- nSignals:", inst.exports.getNSignals ? inst.exports.getNSignals() : "n/a");
