#!/usr/bin/env node
// Generate the committed Steal-the-VFY policy: params + salt -> Poseidon commitment.
// Mirrors circuits/vfy-policy.circom:
//   commitment = Poseidon([p0..p7, salt])
// policy: selfBalance < p1 -> FORTIFY
//         elif opponentBalance > p2 && p3 == 0 -> EXTRACT(p0)
//         else HOLD
// Usage: node make-policy.mjs [extractAmount] [fortifyThreshold] [extractThreshold] [holdPriority]
'use strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { buildPoseidon } = require('circomlibjs');
const crypto = require('crypto');

const argv = process.argv.slice(2).map(Number);
const params = [
  argv[0] || 10,   // extractAmount in [1,10]
  argv[1] || 0,    // fortifyThreshold (0 = never fortify)
  argv[2] || 0,    // extractThreshold (0 = extract whenever opponent has anything)
  argv[3] || 0,    // holdPriority
  0, 0, 0, 0,      // reserved, circuit forces zero
];

(async () => {
  const poseidon = await buildPoseidon();
  const F = poseidon.F;
  const salt = BigInt('0x' + crypto.randomBytes(16).toString('hex'));
  const commitment = F.toObject(poseidon(params.map(String).map(BigInt).concat([salt])));
  const commitmentHex = '0x' + BigInt(commitment).toString(16).padStart(64, '0');
  const out = {
    params,
    salt: salt.toString(),
    commitment: commitmentHex,
    circuitVersion: 'v1',
    policyVersion: 'v1',
    createdAt: new Date().toISOString(),
  };
  const file = path.join(__dirname, 'vfy-policy.json');
  fs.writeFileSync(file, JSON.stringify(out, null, 1));
  fs.chmodSync(file, 0o600);
  console.log(JSON.stringify(out, null, 1));
  console.log('written', file);
})();
