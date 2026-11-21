import crypto from 'crypto';
import fs from 'fs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');
const { buildPoseidon } = require('circomlibjs');

const BASE = process.argv[2] || 'http://127.0.0.1:3100';
const SECRET = process.argv[3] || 'test-secret';
const policy = JSON.parse(fs.readFileSync('vfy-policy.json', 'utf8'));
const vk = JSON.parse(fs.readFileSync('circuits/vfy_vk.json', 'utf8'));

function sign(b){ return crypto.createHmac('sha256', SECRET).update(b).digest('hex'); }
async function post(obj){
  const body = Buffer.from(JSON.stringify(obj));
  const r = await fetch(BASE + '/agent', { method:'POST', headers:{ 'content-type':'application/json','x-agent-games-signature':sign(body) }, body });
  return { status: r.status, json: JSON.parse(await r.text()), sig: r.headers.get('x-agent-games-signature') };
}
const poseidon = await buildPoseidon();
const F = poseidon.F;
const matchId = crypto.randomUUID();
let pass=0, fail=0;
const ck=(n,c,x='')=>{ if(c){pass++;console.log('  PASS',n);} else {fail++;console.log('  FAIL',n,x);} };

for (const [turn, selfB, oppB] of [[1,100,100],[2,110,90],[3,110,80],[4,0,80]]) {
  const env = { protocolVersion:'v1', eventId:'steal-the-vfy', mode:'practice', matchId, turn,
    issuedAt:new Date().toISOString(), deadlineAt:new Date(Date.now()+300000).toISOString(),
    state:{ selfBalance:String(selfB), opponentBalance:String(oppB),
            selfFortifiedUntilTurn:null, opponentFortifiedUntilTurn:null },
    strategyCommitment:{ hash: policy.commitment }, resolverVersion:'v1', nonce:crypto.randomUUID() };
  const res = await post(env);
  ck(`turn ${turn} HTTP 200`, res.status===200, res.status);
  ck(`turn ${turn} echoes matchId/turn`, res.json.matchId===matchId && res.json.turn===turn);
  const pp = res.json.policyProof||{};
  ck(`turn ${turn} has proof+signals`, !!pp.proof && Array.isArray(pp.public_signals) && pp.public_signals.length===9);
  ck(`turn ${turn} circuitVersion v1`, pp.circuitVersion==='v1');
  const ok = await snarkjs.groth16.verify(vk, pp.public_signals, pp.proof);
  ck(`turn ${turn} proof verifies vs official VK`, ok);
  const matchIdField = BigInt('0x'+matchId.replace(/-/g,''));
  const tag = F.toObject(poseidon([matchIdField, BigInt(turn), 1n]));
  ck(`turn ${turn} proofTag binds match/turn/version`, pp.public_signals[0]===tag.toString());
  ck(`turn ${turn} commitment echoed`, BigInt(pp.public_signals[1])===BigInt(policy.commitment));
  const expected = selfB < policy.params[1] ? 1 : (oppB > policy.params[2] && policy.params[3]===0 ? 2 : 0);
  ck(`turn ${turn} action matches policy (${expected})`, pp.public_signals[6]===String(expected), pp.public_signals[6]);
  ck(`turn ${turn} amount consistent`, pp.public_signals[7]===(expected===2?String(policy.params[0]):'0'));
  ck(`turn ${turn} response signed`, !!res.sig);
}
const env2 = { protocolVersion:'v1', eventId:'steal-the-vfy', matchId, turn:1, mode:'practice',
  issuedAt:new Date().toISOString(), deadlineAt:new Date(Date.now()+300000).toISOString(),
  state:{selfBalance:'100',opponentBalance:'100'}, strategyCommitment:{hash:policy.commitment}, resolverVersion:'v1', nonce:'x' };
const a = await post(env2), b = await post(env2);
ck('idempotent replay identical', JSON.stringify(a.json)===JSON.stringify(b.json));

const pre = await post({ type:'agent-games.preflight.v1', nonce:'p1' });
ck('preflight ok', pre.json.ok===true && pre.json.protocolVersion==='v1');

console.log(`RESULT: ${pass} pass, ${fail} fail`);
process.exit(fail?1:0);
