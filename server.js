// ratman4080 — Proof Gatekeeper agent for zkVerify Agent Games (Season 01)
// Node stdlib + snarkjs. Secrets from env only. Fail closed everywhere.
//
// Protocol facts verified against:
//   - agentgames.zkverify.io/build + /events/proof-gatekeeper + /api/circuit-info
//   - local witness probing of the official gatekeeper.wasm (FNV signal-name
//     recovery + boundary tests: balance>=minimum, currentBlock<expiryBlock
//     strict, amount<=maxTransfer, circuit forces decision correctness)
//   - community live-verified taskId encoding (UUID embedded in task_id ->
//     BigInt of dash-stripped hex; non-UUID -> sha256 mod p)
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const snarkjs = require('snarkjs');

// ---------------------------------------------------------------- config
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const KURIER_URL = process.env.KURIER_URL || 'https://api.kurier.xyz/api/v1';
const VK_HASH = process.env.GATEKEEPER_VK_HASH ||
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const WASM_PATH = process.env.GATEKEEPER_WASM || path.join(__dirname, 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = process.env.GATEKEEPER_ZKEY || path.join(__dirname, 'circuits', 'gatekeeper_final.zkey');
const VK_PATH = process.env.GATEKEEPER_VK || path.join(__dirname, 'circuits', 'vk.json');
const STATE_DIR = process.env.GATEKEEPER_STATE_DIR || __dirname;
const SEEN_PATH = path.join(STATE_DIR, 'seen.json');
const DECISIONS_PATH = path.join(STATE_DIR, 'decisions.json');
const PROOF_TIMEOUT_MS = parseInt(process.env.GATEKEEPER_PROOF_TIMEOUT_MS || '45000', 10);
const KURIER_TIMEOUT_MS = parseInt(process.env.KURIER_TIMEOUT_MS || '40000', 10);
const KURIER_POLL_MS = 2500;
const FIELD_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

if (!HMAC_SECRET) {
  console.warn('[gk] WARNING: AGENT_GAMES_HMAC_SECRET unset — inbound auth + response signing DISABLED. Set it from dashboard Rotate Secret.');
}

// ---------------------------------------------------------------- state
function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return fallback; }
}
function saveJson(file, obj) {
  try {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(obj));
    fs.renameSync(tmp, file);
  } catch (e) { console.error('[gk] save failed', path.basename(file), e.message); }
}
const seenProofTx = new Set(loadJson(SEEN_PATH, []));
const decisionsByTask = loadJson(DECISIONS_PATH, {});
let vk = null;
try { vk = JSON.parse(fs.readFileSync(VK_PATH, 'utf8')); }
catch (e) { console.warn('[gk] vk.json missing — local proof self-check disabled:', e.message); }

// ---------------------------------------------------------------- field parsing
// Hex fields (vk hashes, addresses) compare as BN128 field elements mod p —
// that is exactly what the circuit does; string comparison would wrongly
// reject padded / prefix-less spellings the circuit accepts.
function parseHexField(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  const hex = s.startsWith('0x') ? s.slice(2) : s;
  if (!hex.length || !/^[0-9a-f]+$/.test(hex)) return null;
  return BigInt('0x' + hex) % FIELD_P;
}
function parseDecimalField(v) {
  if (typeof v === 'number') return Number.isInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s) return null;
  try { const b = BigInt(s); return b < 0n ? null : b; } catch { return null; }
}
// proof_tx refs are opaque identifiers: string compare, case-folded, NO
// leading-zero collapse (0x00ab and 0xab are distinct refs).
function normProofRef(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  if (!s || /[\s\x00-\x1f\x7f]/.test(s)) return null;
  return s;
}
function taskIdField(taskId) {
  const s = String(taskId || '');
  const m = s.match(UUID_RE);
  if (m) return BigInt('0x' + m[0].replace(/-/g, ''));
  const h = crypto.createHash('sha256').update(s, 'utf8').digest('hex');
  return BigInt('0x' + h) % FIELD_P;
}

// ---------------------------------------------------------------- decision
// Trap order per /events/proof-gatekeeper: VK, THRESHOLD, REUSED, EXPIRED,
// RECIPIENT, AMOUNT. Expiry is STRICT (currentBlock >= expiryBlock = expired)
// — verified against the official circuit by witness probing.
function decide(input) {
  const registeredVk = parseHexField(input.registered_vk);
  const proofVk = parseHexField(input.proof_vk);
  const minimum = parseDecimalField(input.minimum);
  const balance = parseDecimalField(input.public_balance);
  const amount = parseDecimalField(input.amount);
  const maxTransfer = parseDecimalField(input.max_transfer);
  const recipient = parseHexField(input.recipient);
  const conditionRecipient = parseHexField(input.condition_recipient);
  const expiry = typeof input.expiry_block === 'number' ? input.expiry_block : NaN;
  const current = typeof input.current_block === 'number' ? input.current_block : NaN;
  const proofRef = normProofRef(input.proof_tx);

  const fail = (reason_code) => ({ decision: 'REJECT', reason_code, proofRef });

  if (registeredVk === null || proofVk === null || registeredVk !== proofVk) return fail('VK_SUBSTITUTION');
  if (minimum === null || balance === null || balance < minimum) return fail('THRESHOLD_MISMATCH');
  if (proofRef === null || seenProofTx.has(proofRef)) return fail('PROOF_REUSED');
  if (!Number.isInteger(expiry) || !Number.isInteger(current) || current >= expiry) return fail('EXPIRED_CONDITION');
  if (recipient === null || conditionRecipient === null || recipient !== conditionRecipient) return fail('RECIPIENT_MISMATCH');
  if (amount === null || maxTransfer === null || amount > maxTransfer) return fail('AMOUNT_OVERFLOW');
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proofRef };
}

// ---------------------------------------------------------------- proof
function buildCircuitInput(task, result) {
  const i = task.input;
  return {
    registeredVkHash: parseHexField(i.registered_vk).toString(),
    proofVkHash: parseHexField(i.proof_vk).toString(),
    minimum: parseDecimalField(i.minimum).toString(),
    publicBalance: parseDecimalField(i.public_balance).toString(),
    expiryBlock: String(i.expiry_block),
    currentBlock: String(i.current_block),
    recipient: parseHexField(i.recipient).toString(),
    conditionRecipient: parseHexField(i.condition_recipient).toString(),
    amount: parseDecimalField(i.amount).toString(),
    maxTransfer: parseDecimalField(i.max_transfer).toString(),
    decision: result.decision === 'APPROVE' ? '1' : '0',
    taskId: taskIdField(task.task_id).toString(),
    salt: BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString(),
  };
}
async function generateProof(task, result) {
  const ci = buildCircuitInput(task, result);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(ci, WASM_PATH, ZKEY_PATH);
  if (vk && !(await snarkjs.groth16.verify(vk, publicSignals, proof))) {
    throw new Error('local proof self-verify failed');
  }
  return { proof, public_signals: publicSignals };
}
function withTimeout(promise, ms, label) {
  let t;
  const to = new Promise((_, rej) => { t = setTimeout(() => rej(new Error(label + ' timeout ' + ms + 'ms')), ms); });
  return Promise.race([promise.finally(() => clearTimeout(t)), to]);
}

// ---------------------------------------------------------------- Kurier
// On-chain confirmation is what makes the platform count a proof as verified.
// Bounded budget inside the 60s task window; any failure is non-fatal.
async function kurierSubmitOnce(proof, publicSignals, vkRegistered) {
  const body = {
    proofType: 'groth16',
    vkRegistered,
    proofOptions: { library: 'snarkjs', curve: 'bn128' },
    proofData: { proof, publicSignals, vk: vkRegistered ? VK_HASH : vk },
  };
  const res = await fetch(`${KURIER_URL}/submit-proof/${KURIER_API_KEY}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error('kurier submit HTTP ' + res.status);
  const job = await res.json();
  return job.jobId || job.job_id || job.id || null;
}
async function kurierPoll(jobId, deadlineMs) {
  while (Date.now() < deadlineMs) {
    try {
      const res = await fetch(`${KURIER_URL}/job-status/${KURIER_API_KEY}/${jobId}`,
        { signal: AbortSignal.timeout(8000) });
      if (res.ok) {
        const st = await res.json();
        const status = String(st.status || st.state || '').toLowerCase();
        if (['finalized', 'success', 'verified'].includes(status)) {
          return st.txHash || st.tx_hash || st.transactionHash || st.proofTx || null;
        }
        if (['failed', 'error', 'rejected'].includes(status)) throw new Error('kurier job ' + status);
      }
    } catch (e) {
      if (/kurier job/.test(e.message)) throw e;
    }
    await new Promise((r) => setTimeout(r, KURIER_POLL_MS));
  }
  throw new Error('kurier poll timeout');
}
async function submitToKurier(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const deadlineMs = Date.now() + Math.max(0, budgetMs);
  try {
    let jobId;
    try { jobId = await kurierSubmitOnce(proof, publicSignals, true); }
    catch (e) {
      if (!vk) throw e;
      console.warn('[gk] kurier vkRegistered:true failed, retry full vk:', e.message);
      jobId = await kurierSubmitOnce(proof, publicSignals, false);
    }
    if (!jobId) throw new Error('no jobId');
    const txHash = await kurierPoll(jobId, deadlineMs);
    if (txHash) console.log('[gk] kurier Finalized tx:', txHash);
    return txHash || null;
  } catch (e) {
    console.error('[gk] kurier non-fatal failure:', e.message);
    return null;
  }
}

// ---------------------------------------------------------------- HMAC
function verifySignature(rawBody, header) {
  if (!HMAC_SECRET || !header) return false;
  let sig = String(header).trim();
  if (sig.toLowerCase().startsWith('sha256=')) sig = sig.slice(7);
  const digest = crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest();
  const a = Buffer.from(sig, 'utf8');
  for (const expected of [digest.toString('hex'), digest.toString('base64')]) {
    const b = Buffer.from(expected, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}
function sendJson(res, status, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (HMAC_SECRET) headers['x-agent-games-signature'] = crypto.createHmac('sha256', HMAC_SECRET).update(body).digest('hex');
  res.writeHead(status, headers);
  res.end(body);
}
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => {
      chunks.push(c);
      if (Buffer.concat(chunks).length > 1024 * 1024) { req.destroy(); reject(new Error('body too large')); }
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// ---------------------------------------------------------------- Steal the VFY
// Committed policy: commitment = Poseidon(strategyParams[8], salt) exactly as the
// official vfy-policy circuit checks it. Strategy is read from VFY_POLICY_FILE.
const VFY_POLICY_FILE = process.env.VFY_POLICY_FILE || path.join(STATE_DIR, 'vfy-policy.json');
const VFY_WASM = process.env.VFY_WASM || path.join(__dirname, 'circuits', 'vfy-policy.wasm');
const VFY_ZKEY = process.env.VFY_ZKEY || path.join(__dirname, 'circuits', 'vfy-policy_final.zkey');
const VFY_PROOF_TIMEOUT_MS = parseInt(process.env.VFY_PROOF_TIMEOUT_MS || '45000', 10);

let vfyPolicy = null;
try { vfyPolicy = JSON.parse(fs.readFileSync(VFY_POLICY_FILE, 'utf8')); }
catch { vfyPolicy = null; }

const ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };

// Mirrors the circuit's policy branch order exactly.
function policyAction(selfBalance, opponentBalance, params) {
  const [extractAmount, fortifyThreshold, extractThreshold, holdPriority] = params;
  if (selfBalance < fortifyThreshold) return { type: 'FORTIFY', amount: 0 };
  if (opponentBalance > extractThreshold && holdPriority === 0) return { type: 'EXTRACT', amount: extractAmount };
  return { type: 'HOLD', amount: 0 };
}

async function vfyProof(commitment, matchIdField, turnNumber, selfBalance, opponentBalance, action) {
  const input = {
    commitment: commitment.toString(),
    matchId: matchIdField.toString(),
    turnNumber: String(turnNumber),
    selfBalance: String(selfBalance),
    opponentBalance: String(opponentBalance),
    action: String(ACTION_CODE[action.type]),
    amount: String(action.amount || 0),
    circuitVersion: '1',
    salt: BigInt(vfyPolicy.salt).toString(),
    strategyParams: vfyPolicy.params.map(String),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, VFY_WASM, VFY_ZKEY);
  return { proof, publicSignals };
}

const vfyByTurn = {}; // `${matchId}:${turn}` -> signed response body

async function handleVfyTurn(res, turn) {
  const key = `${turn.matchId}:${turn.turn}`;
  if (vfyByTurn[key]) {
    const body = Buffer.from(JSON.stringify(vfyByTurn[key]));
    const headers = { 'content-type': 'application/json', 'content-length': body.length };
    if (HMAC_SECRET) headers['x-agent-games-signature'] = crypto.createHmac('sha256', HMAC_SECRET).update(body).digest('hex');
    res.writeHead(200, headers);
    return res.end(body);
  }
  if (!vfyPolicy) {
    // Without the opening (params+salt) no valid proof exists; answer HOLD, signed.
    return sendJson(res, 200, {
      matchId: turn.matchId, turn: turn.turn, action: { type: 'HOLD' },
      agentTimestamp: new Date().toISOString(), idempotencyKey: key,
    });
  }
  const selfBalance = Number(turn.state?.selfBalance ?? 0);
  const opponentBalance = Number(turn.state?.opponentBalance ?? 0);
  const action = policyAction(selfBalance, opponentBalance, vfyPolicy.params);

  const commitment = BigInt(vfyPolicy.commitment);
  const matchIdHex = String(turn.matchId).replace(/-/g, '');
  const matchIdField = BigInt('0x' + matchIdHex);

  const t0 = Date.now();
  let policyProof = { circuitVersion: vfyPolicy.circuitVersion || 'v1' };
  try {
    const { proof, publicSignals } = await withTimeout(
      vfyProof(commitment, matchIdField, turn.turn, selfBalance, opponentBalance, action),
      VFY_PROOF_TIMEOUT_MS, 'vfy-prove');
    policyProof.proof = proof;
    policyProof.public_signals = publicSignals;
    console.log(`[vfy] ${key} ${action.type}${action.amount ? '/' + action.amount : ''} proof ${Date.now() - t0}ms`);
  } catch (e) {
    console.error(`[vfy] ${key} proof FAILED:`, e.message);
  }

  const response = {
    matchId: turn.matchId,
    turn: turn.turn,
    action: action.type === 'EXTRACT' ? { type: 'EXTRACT', amount: action.amount } : { type: action.type },
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey: crypto.randomUUID(),
  };
  vfyByTurn[key] = response;
  return sendJson(res, 200, response);
}

// ---------------------------------------------------------------- handler
async function handleTask(req, res, rawBody) {
  if (!verifySignature(rawBody, req.headers['x-agent-games-signature'])) {
    console.warn('[gk] bad/missing HMAC');
    return sendJson(res, 401, { error: 'invalid signature' });
  }
  let task;
  try { task = JSON.parse(rawBody.toString('utf8')); }
  catch { return sendJson(res, 400, { error: 'invalid json' }); }

  if (task.type === 'agent-games.preflight.v1') {
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }
  // Steal the VFY turn envelope carries no `type` — it is identified by the
  // match/turn fields documented in the build guide.
  if (task.eventId === 'steal-the-vfy' || (task.matchId && task.turn !== undefined && task.state)) {
    return await handleVfyTurn(res, task);
  }
  if (task.type && task.type !== 'agent-games.proof-gatekeeper.v1') {
    return sendJson(res, 400, { error: 'unknown task type' });
  }
  if (!task.input || !task.task_id) return sendJson(res, 400, { error: 'missing task_id/input' });

  // idempotency: platform may retry the same task_id — same signed answer
  if (decisionsByTask[task.task_id]) {
    const body = Buffer.from(JSON.stringify(decisionsByTask[task.task_id]));
    const headers = { 'content-type': 'application/json', 'content-length': body.length };
    if (HMAC_SECRET) headers['x-agent-games-signature'] = crypto.createHmac('sha256', HMAC_SECRET).update(body).digest('hex');
    res.writeHead(200, headers);
    return res.end(body);
  }

  const t0 = Date.now();
  let result;
  const deadlineMs = task.deadline_at ? Date.parse(task.deadline_at) : NaN;
  if (!Number.isNaN(deadlineMs) && Date.now() > deadlineMs) {
    console.warn(`[gk] ${task.task_id}: past deadline, fail closed`);
    result = { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', proofRef: normProofRef(task.input.proof_tx) };
  } else {
    try { result = decide(task.input); }
    catch (e) {
      console.error('[gk] decide error, fail closed:', e.message);
      result = { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', proofRef: normProofRef(task.input.proof_tx) };
    }
  }

  const response = { decision: result.decision, reason_code: result.reason_code };
  if (task.input.proof_tx) response.proof_tx = task.input.proof_tx;

  // PROOF_REUSED tasks carry no proof (platform excludes them from bonus).
  if (result.reason_code !== 'PROOF_REUSED') {
    try {
      const { proof, public_signals } = await withTimeout(generateProof(task, result), PROOF_TIMEOUT_MS, 'prove');
      response.proof = proof;
      response.public_signals = public_signals;
      console.log(`[gk] ${task.task_id} ${result.decision}/${result.reason_code} proof ${Date.now() - t0}ms`);
      let budget = KURIER_TIMEOUT_MS;
      if (!Number.isNaN(deadlineMs)) budget = Math.min(budget, deadlineMs - Date.now() - 5000);
      if (budget > 3000) {
        const txHash = await submitToKurier(proof, public_signals, budget);
        if (txHash) response.proof_tx = txHash;
      }
    } catch (e) {
      console.error(`[gk] ${task.task_id} proof FAILED (decision still returned):`, e.message);
    }
  } else {
    console.log(`[gk] ${task.task_id} REJECT/PROOF_REUSED (no proof)`);
  }

  if (result.proofRef) {
    seenProofTx.add(result.proofRef);
    saveJson(SEEN_PATH, [...seenProofTx]);
  }
  decisionsByTask[task.task_id] = response;
  saveJson(DECISIONS_PATH, decisionsByTask);
  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && ['/', '/health', '/agent'].includes(url.pathname)) {
      return sendJson(res, 200, {
        ok: true, service: 'proof-gatekeeper', protocolVersion: 'v1',
        uptime_s: Math.floor(process.uptime()),
        hmac_configured: Boolean(HMAC_SECRET),
        kurier_configured: Boolean(KURIER_API_KEY),
        seen_proof_refs: seenProofTx.size,
        tasks_answered: Object.keys(decisionsByTask).length,
        vfy_policy: vfyPolicy ? vfyPolicy.commitment.slice(0, 12) + '…' : null,
        vfy_turns: Object.keys(vfyByTurn).length,
      });
    }
    if (req.method === 'POST' && ['/agent', '/'].includes(url.pathname)) {
      const rawBody = await readRawBody(req);
      return await handleTask(req, res, rawBody);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[gk] handler error:', e.message);
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal error' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`[gk] listening http://${HOST}:${PORT} — POST /agent, GET /health`);
    console.log(`[gk] hmac=${Boolean(HMAC_SECRET)} kurier=${Boolean(KURIER_API_KEY)} seen=${seenProofTx.size}`);
  });
}

module.exports = { server, decide, verifySignature, taskIdField, buildCircuitInput, generateProof, seenProofTx };
