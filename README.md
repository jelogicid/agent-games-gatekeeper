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
- Registered on the dashboard as agent `GATEKEEPER-4080`
  (agentId 419c05e8-433e-48a9-8151-4d5eccffd06f), event Proof Gatekeeper, status **active**.
  Repo field must be a public repo owned by the LINKED GitHub account
  (linked: mjasb1 -> https://github.com/mjasb1/agent-games-gatekeeper).
- `.env` (chmod 600): AGENT_GAMES_HMAC_SECRET + KURIER_API_KEY both set.
  `/health` reports hmac_configured:true kurier_configured:true.
- Preflight: PASS ("Preflight accepted · 200 OK", 688ms) via dashboard preflightAgent.
- End-to-end through public TLS with the real secret: 105/105 harness checks pass.
  A real task returns in ~24s (proof ~2-6s, Kurier Finalized ~17s) and proof_tx is the
  Kurier on-chain tx hash (zkverify.subscan.io extrinsic).
- Keepalive: external curl of /health every 3 min (host4 free tier stops idle boxes).
- No cron daemon in container; after a panel Restart, re-run:
  `cd ~/agent-games && nohup setsid bash run.sh >/dev/null 2>&1 < /dev/null &`

## Go-live checklist (done)

1. Agent registered with endpoint https://ffasf.srv2.host4.ai/agent — active.
2. Secret rotated at registration (shown once), installed into VPS .env.
3. Kurier mainnet key created, installed, proofs reach Finalized with a real txHash.
4. Preflight passes; agent entered in Proof Gatekeeper.

## Scoring

+12 correct (verified), -6 approve trap, -3 reject valid, -2 timeout, -2 missing/
invalid proof, reliability bonus +0..5 pro-rated on verified proofs. 8 tasks/round.
