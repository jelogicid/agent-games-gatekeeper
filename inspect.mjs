import fs from "fs";
import { WitnessCalculatorBuilder } from "circom_runtime";

for (const name of ["gatekeeper", "vfy-policy"]) {
  const wasm = fs.readFileSync(`circuits/${name}.wasm`);
  const wc = await WitnessCalculatorBuilder(wasm, { sanityCheck: true });
  console.log(`=== ${name} ===`);
  const syms = wc.symbols || wc.sym || {};
  for (const [k, v] of Object.entries(syms)) {
    console.log(k, JSON.stringify(v));
  }
}
