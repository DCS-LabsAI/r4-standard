// ═══════════════════════════════════════════════════════════════════
// R4.3 smoke test — call verifyProof() on an already-deployed
// Groth16Verifier (Base Sepolia) with the real example proof.json.
//
// Use this when deploy-verifier.mjs deployed the contract but its
// inline smoke test raced the RPC. No redeploy — read-only call.
//
// Env:
//   R4_VERIFIER_ADDRESS   the deployed Groth16Verifier address
//   BASE_SEPOLIA_RPC      optional — defaults to https://sepolia.base.org
//
// Run:  node scripts/verify-onchain.mjs
// ═══════════════════════════════════════════════════════════════════
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { groth16 } from "snarkjs";
import { createPublicClient, http } from "viem";
import { baseSepolia } from "viem/chains";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const RPC = process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org";
const ADDR = process.env.R4_VERIFIER_ADDRESS;
if (!ADDR) {
  console.error("ERROR: set R4_VERIFIER_ADDRESS (the deployed Groth16Verifier address).");
  process.exit(1);
}

const abi = [
  {
    type: "function",
    name: "verifyProof",
    stateMutability: "view",
    inputs: [
      { name: "_pA", type: "uint256[2]" },
      { name: "_pB", type: "uint256[2][2]" },
      { name: "_pC", type: "uint256[2]" },
      { name: "_pubSignals", type: "uint256[8]" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
];

const pub = createPublicClient({ chain: baseSepolia, transport: http(RPC) });

const code = await pub.getCode({ address: ADDR });
const hasCode = !!code && code !== "0x";
console.log(`verifier ${ADDR}`);
console.log(`contract code present: ${hasCode}  (${code ? code.length - 2 : 0} hex chars)`);
if (!hasCode) {
  console.error("ERROR: no contract code at that address on this RPC — wrong address, or RPC still lagging. Retry in a minute.");
  process.exit(1);
}

const proofObj = JSON.parse(readFileSync(join(root, "proof.json"), "utf8"));
const rawProof = { ...proofObj.proof, protocol: "groth16", curve: "bn128" };
const calldata = await groth16.exportSolidityCallData(rawProof, proofObj.public_inputs);
const [pA, pB, pC, pubSignals] = JSON.parse("[" + calldata + "]");

const ok = await pub.readContract({
  address: ADDR,
  abi,
  functionName: "verifyProof",
  args: [pA, pB, pC, pubSignals],
});

console.log(`on-chain verifyProof : ${ok}`);
console.log(
  ok === true
    ? "PASS — R+4 Groth16 verifier is live on Base Sepolia and accepts the real proof."
    : "FAIL — verifyProof returned false (proof/public-input mismatch)."
);
process.exit(ok === true ? 0 : 2);
