# Proof Gatekeeper agent — zkVerify Agent Games Season 01

ratman4080 build. Deterministic decision engine + local Groth16 proving (snarkjs)
against the OFFICIAL platform circuit. The circuit is the referee: it refuses to
prove a wrong decision, so decision logic and circuit semantics must match exactly.

## Verified protocol facts (evidence, not guesses)

- Circuit inputs recovered by FNV-hash probing of gatekeeper.wasm (13 scalars):
  registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  recipient, conditionRecipient, amount, maxTransfer, decision, taskId, salt.
- Public signals order: [0]=commitment(taskId,salt), [1..12] = the 12 inputs above
  minus salt, in that order (decision at [11], taskId at [12]).
- Circuit semantics (witness-probed): balance >= minimum; currentBlock < expiryBlock
  STRICT (equality = expired); amount <= maxTransfer; vk/recipient equality as field
  elements mod p; decision forced to the correct evaluation (1=APPROVE, 0=REJECT).
- taskId encoding (community live-verified 19 Nov): UUID embedded anywhere in
  task_id -> BigInt of dash-stripped hex; non-UUID -> sha256(task_id) mod p.
  UTF-8-bytes encoding is WRONG (scores proof_failure live).
- HMAC-SHA256 over RAW body, header x-agent-games-signature, hex (accept sha256=
  prefix / base64 inbound). Sign every response. Preflight: {ok:true,protocolVersion:"v1"}.
- Response: {decision, reason_code, proof_tx, proof, public_signals}.
  PROOF_REUSED tasks: NO proof (platform excludes them).
- Kurier on-chain Finalized confirmation is what makes proofs count as verified
  (without it: -2/task, no reliability bonus). Submit vkRegistered:true with
  vk=0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0,
  poll job-status, use returned txHash as response.proof_tx.
- Trap order: VK, THRESHOLD, REUSED, EXPIRED, RECIPIENT, AMOUNT.

## Files

- server.js — the agent (Node stdlib + snarkjs). POST /agent, GET /health.
- test.js — harness: 105 checks (7 traps, boundaries, HMAC both ways, preflight,
  proof verify vs official VK, taskId binding, idempotency).
  `node test.js [base_url] [secret]`
- circuits/ — official gatekeeper.wasm + gatekeeper_final.zkey + vk.json
  (exported via `snarkjs zkey export verificationkey`).
- run.sh — supervisor loop (re-sources .env every restart).
- gk-nginx.conf / nginx-default — reverse proxy snippet used on the VPS.
- probe-signals.mjs / probe2.mjs / boundary.mjs / test-circuit.mjs — the RE tools
  that recovered the circuit schema (kept as evidence).

## Live deployment (2026-11-21)

- Host: Host4.ai container, SSH clientuser@135.181.75.25 -p 3005
- Path: ~/agent-games, supervisor `bash run.sh` (nohup setsid), node 127.0.0.1:3000
- Public endpoint: **https://ffasf.srv2.host4.ai/agent** (Caddy TLS -> nginx -> node)
- State: seen.json (proof_tx reuse set) + decisions.json (idempotency) — persistent disk.
- .env (chmod 600): AGENT_GAMES_HMAC_SECRET, KURIER_API_KEY. Currently EMPTY =
  fail-closed (401 to everything) until the real dashboard secret is set.
- Keepalive: external curl of /health every 3 min (host4 free tier stops idle boxes).
- No cron daemon in container; after a panel Restart, re-run:
  `cd ~/agent-games && nohup setsid bash run.sh >/dev/null 2>&1 < /dev/null &`

## Go-live checklist (user actions)

1. https://agentgames.zkverify.io/register — sign in with X or wallet; connect
   GitHub + wallet (prize eligibility).
2. Dashboard -> register agent endpoint `https://ffasf.srv2.host4.ai/agent`.
3. Rotate Secret -> copy the one-time plaintext into ~/agent-games/.env on the VPS
   (AGENT_GAMES_HMAC_SECRET=...). Never paste it into chat. Supervisor picks it up
   on next node restart (kill the node PID; run.sh respawns in 2s).
4. https://kurier.xyz -> mainnet signup (free) -> KURIER_API_KEY into same .env.
5. Dashboard: run preflight (must pass) + at least one practice task.
6. Enter Proof Gatekeeper. Deadline: 21 Nov 2026 22:00 UTC.

## Scoring

+12 correct (verified), -6 approve trap, -3 reject valid, -2 timeout, -2 missing/
invalid proof, reliability bonus +0..5 pro-rated on verified proofs. 8 tasks/round.
