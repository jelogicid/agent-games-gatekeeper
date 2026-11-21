// Local test harness — replays signed envelopes for all 7 trap varieties +
// boundary cases against the running agent. Verifies HMAC both ways, proof
// validity against the official VK, and public-signal/task binding.
// Usage: node test.mjs [base_url] [hmac_secret]
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const snarkjs = require('snarkjs');

const BASE = process.argv[2] || 'http://127.0.0.1:3000';
const SECRET = process.argv[3] || process.env.AGENT_GAMES_HMAC_SECRET || 'test-secret-local-only';
const vk = JSON.parse(fs.readFileSync(__dirname + '/circuits/vk.json', 'utf8'));
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const VKH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const R = '0xDe42000000000000000000000000000000009f01';
const uuid = () => crypto.randomUUID();
const tid = () => 'task_T01_' + uuid();

function envelope(input, taskId) {
  const now = Date.now();
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: taskId || tid(),
    mode: 'practice',
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 60000).toISOString(),
    input,
  };
}
const validInput = (over = {}) => ({
  registered_vk: VKH, proof_vk: VKH,
  minimum: '1000', public_balance: '1460',
  expiry_block: 8430000, current_block: 8420000,
  recipient: R, condition_recipient: R,
  amount: '500', max_transfer: '1000',
  proof_tx: '0x' + crypto.randomBytes(32).toString('hex'),
  ...over,
});

function sign(body) { return crypto.createHmac('sha256', SECRET).update(body).digest('hex'); }

async function post(path, obj, secret = SECRET) {
  const body = Buffer.from(JSON.stringify(obj));
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': crypto.createHmac('sha256', secret).update(body).digest('hex') },
    body,
  });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, sig: res.headers.get('x-agent-games-signature'), raw: text };
}

let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
}

async function expectTask(name, input, wantDecision, wantReason, { noProof = false, taskId } = {}) {
  const env = envelope(input, taskId);
  const r = await post('/agent', env);
  check(name + ' [200]', r.status === 200, `got ${r.status} ${r.raw.slice(0, 120)}`);
  if (!r.json) return;
  check(name + ' [decision]', r.json.decision === wantDecision, JSON.stringify(r.json).slice(0, 120));
  check(name + ' [reason]', r.json.reason_code === wantReason, r.json.reason_code);
  // response signature valid over raw body
  const expectSig = crypto.createHmac('sha256', SECRET).update(r.raw).digest('hex');
  check(name + ' [resp sig]', r.sig === expectSig);
  if (noProof) {
    check(name + ' [no proof]', !r.json.proof);
  } else if (r.json.proof) {
    const ok = await snarkjs.groth16.verify(vk, r.json.public_signals, r.json.proof);
    check(name + ' [proof verifies]', ok);
    // signal layout: [0]=commitment, [1..12] = registeredVkHash, proofVkHash,
    // minimum, publicBalance, expiryBlock, currentBlock, recipient,
    // conditionRecipient, amount, maxTransfer, decision, taskId
    const ps = r.json.public_signals.map(BigInt);
    const m = String(env.task_id).match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i);
    const wantTask = m ? BigInt('0x' + m[0].replace(/-/g, '')) : null;
    if (wantTask !== null) check(name + ' [taskId binding]', ps[12] === wantTask, `${ps[12]} != ${wantTask}`);
    check(name + ' [decision bit]', ps[11] === (wantDecision === 'APPROVE' ? 1n : 0n));
    check(name + ' [balance field]', ps[4] === BigInt(input.public_balance));
  } else {
    check(name + ' [proof present]', false, 'no proof in response');
  }
  return r;
}

(async () => {
  console.log('== health ==');
  const h = await fetch(BASE + '/health').then(r => r.json());
  check('health ok', h.ok === true);

  console.log('== auth ==');
  const bad = await post('/agent', envelope(validInput()), 'wrong-secret');
  check('bad HMAC rejected 401', bad.status === 401);

  console.log('== preflight ==');
  const pf = await post('/agent', { type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
  check('preflight ok', pf.status === 200 && pf.json.ok === true && pf.json.protocolVersion === 'v1');

  console.log('== 7 trap varieties ==');
  await expectTask('VALID_CONDITION', validInput(), 'APPROVE', 'VALID_CONDITION');
  await expectTask('VK_SUBSTITUTION', validInput({ proof_vk: '0x13' + 'aa'.repeat(31) }), 'REJECT', 'VK_SUBSTITUTION');
  await expectTask('THRESHOLD_MISMATCH', validInput({ public_balance: '999' }), 'REJECT', 'THRESHOLD_MISMATCH');
  const reusedRef = '0x' + crypto.randomBytes(32).toString('hex');
  await expectTask('PROOF_REUSED seed', validInput({ proof_tx: reusedRef }), 'APPROVE', 'VALID_CONDITION');
  await expectTask('PROOF_REUSED', validInput({ proof_tx: reusedRef }), 'REJECT', 'PROOF_REUSED', { noProof: true });
  await expectTask('EXPIRED_CONDITION', validInput({ current_block: 8430000 }), 'REJECT', 'EXPIRED_CONDITION');
  await expectTask('RECIPIENT_MISMATCH', validInput({ recipient: '0xBad0000000000000000000000000000000000001' }), 'REJECT', 'RECIPIENT_MISMATCH');
  await expectTask('AMOUNT_OVERFLOW', validInput({ amount: '1001' }), 'REJECT', 'AMOUNT_OVERFLOW');

  console.log('== boundaries (circuit-verified semantics) ==');
  await expectTask('balance == minimum', validInput({ public_balance: '1000' }), 'APPROVE', 'VALID_CONDITION');
  await expectTask('current == expiry-1', validInput({ current_block: 8429999 }), 'APPROVE', 'VALID_CONDITION');
  await expectTask('amount == cap', validInput({ amount: '1000' }), 'APPROVE', 'VALID_CONDITION');
  await expectTask('padded vk spelling', validInput({ proof_vk: '0x00' + VKH.slice(2) }), 'APPROVE', 'VALID_CONDITION');

  console.log('== idempotency ==');
  const fixedId = tid();
  const r1 = await expectTask('first send', validInput(), 'APPROVE', 'VALID_CONDITION', { taskId: fixedId });
  const r2 = await post('/agent', envelope(validInput(), fixedId));
  check('retry same body', r1 && r2.raw === r1.raw);

  console.log(`\nRESULT: ${pass} pass, ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
