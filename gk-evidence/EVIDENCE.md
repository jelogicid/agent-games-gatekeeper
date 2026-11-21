# GATEKEEPER-4080 — Season 01 evidence bundle

Competition closed 2026-11-21 22:00 UTC. Final board: rank 387 / 521, total 0.
Not a runtime failure — the agent was never paired into a scored round (see README,
"Season 01 final result").

## What this bundle proves

- 14 Gatekeeper tasks answered, all 7 trap varieties exercised, every answer carried a
  proof whose Kurier tx landed on zkVerify mainnet.
- 12 of those reached Kurier status `Finalized` with a real txHash; 13 refs in the
  reuse set.

## Files

| file | what it is |
|---|---|
| decisions.json | full response bodies (decision, reason_code, proof, public_signals, Kurier txHash) keyed by task_id — the idempotency store as it stood at close |
| seen.json | proof_tx reuse set (13 refs) |
| agent.log | server log tail: proof timings, Kurier Finalized lines, VFY turn timings |
| leaderboard-final.json | `/api/leaderboard` snapshot, 521 entries |
| README.md | protocol dossier + Season 01 result + next-season rules |

## Decision ledger as recorded

```
APPROVE VALID_CONDITION   0xaa5ca293087b0f7c
REJECT  VK_SUBSTITUTION   0x2fa08dcb6c474038
REJECT  THRESHOLD_MISMATCH 0x2e6bcbad860751aa
APPROVE VALID_CONDITION   0xe5e4997f755b1d8e
REJECT  PROOF_REUSED      0xf14a9e069be7f262
REJECT  EXPIRED_CONDITION 0x3eac7616fcfe6dd7
APPROVE VALID_CONDITION   0x7f840abb2b5c5a7a
REJECT  RECIPIENT_MISMATCH 0x4eef3dea1fb1a72a
REJECT  AMOUNT_OVERFLOW   0x3249da8510a993ea
APPROVE VALID_CONDITION   0xf523535a61adb630
APPROVE VALID_CONDITION   0xe574eaa569f8499d
APPROVE VALID_CONDITION   0xe54c74451c9c7f76
APPROVE VALID_CONDITION   0xaa66d2e513a7a9b4
APPROVE VALID_CONDITION   0xc420ae8fc72dbfd3
```

## Reproduce

```
cd /home/mjasb/agent-games-zkverify
node test.js http://127.0.0.1:3000 <hmac-secret>    # 105 checks (Gatekeeper)
node vfy-test.mjs http://127.0.0.1:3000 <hmac-secret>  # 42 checks (Steal the VFY)
```

Both harnesses verify proofs against the official VKs and check taskId/matchId binding.

## Server snapshot

`/home/clientuser/gk-snapshot-20261121T2204.tgz` (2.5 MB, no node_modules, no .env)
sha256 `e4bbd533c116e1d166cd3dbfe4a62d7c1d390ea59706f6df638795aca5b330f7`
