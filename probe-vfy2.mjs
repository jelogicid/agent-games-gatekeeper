import fs from "fs";
import { WitnessCalculatorBuilder } from "circom_runtime";
function fnvHash(str){const max=2n**64n;let h=0xCBF29CE484222325n;for(const c of str){h^=BigInt(c.charCodeAt(0));h=(h*0x100000001B3n)%max;}const s=h.toString(16).padStart(16,"0");return [parseInt(s.slice(0,8),16),parseInt(s.slice(8,16),16)];}
const wc=await WitnessCalculatorBuilder(fs.readFileSync("circuits/vfy-policy.wasm"),{sanityCheck:true});
const inst=wc.instance;
const known=new Map(); // name -> size
function tryName(n){ const [m,l]=fnvHash(n); try{const s=inst.exports.getInputSignalSize(m,l); if(s>0){ if(!known.has(n)){known.set(n,s); console.log("HIT",n,s);} return true;} }catch(e){} return false; }
const toks=["strategy","policy","param","params","salt","seed","turn","balance","self","opponent","min","max","cap","cost","gain","block","extract","fortify","hold","action","amount","commitment","version","hash","limit","floor","ceiling","threshold","reserve","delta","prev","next","start","end","until","fortified","spendable","exposed","protected","attack","defend","steal","take","give","pay","fee","price","rate","ratio","weight","score","round","match","game","state","total","sum","a","b","c","d","e","f","g","h","i","j","k","x","y","z","v","p","s","m","n","t","w","pot","pool","bank","wallet","cash","fund"];
const singles=[...toks];
// combos of 2
const combos=[];
for(const a of toks) for(const b of toks){ if(a===b) continue; combos.push(a+b[0].toUpperCase()+b.slice(1)); }
const set=new Set([...singles,...combos]);
// numeric suffixes
for(const p of ["p","k","s","v","x","y","a","b","c","d","m","n","q","r"]) for(let i=0;i<20;i++) set.add(p+i);
let count=0;
for(const n of set){ count++; tryName(n); }
console.log("tested",count,"found",known.size);
