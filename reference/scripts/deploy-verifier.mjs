// ═══════════════════════════════════════════════════════════════════
// R4.3 — compile + deploy the Groth16 verifier to Base Sepolia, then
// smoke-test verifyProof() on-chain with the real example proof.
//
// The verifier contract (solidity/Groth16Verifier.gen.sol) was emitted by
// build.sh step 5 from the dev proving key. Deploying it on Base Sepolia
// gives an on-chain endpoint that confirms an R+4 proof in a `view` call —
// the testnet half of R+4's on-chain verification path.
//
// Prereqs (run in r4-reference/):
//   npm install solc viem
//   ./build.sh dev            # produces solidity/Groth16Verifier.gen.sol
//   npm run prove ...         # produces proof.json (for the smoke test)
//
// Env:
//   R4_DEPLOY_PRIVATE_KEY   testnet deployer key (Base Sepolia ETH funded)
//   BASE_SEPOLIA_RPC        optional — defaults to https://sepolia.base.org
//
// Run:  node scripts/deploy-verifier.mjs
// ═══════════════════════════════════════════════════════════════════
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import solc from "solc";
import { groth16 } from "snarkjs";
import { createWalletClient, createPublicClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { baseSepolia } from "viem/chains";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const RPC = process.env.BASE_SEPOLIA_RPC || "https://sepolia.base.org";
let KEY = process.env.R4_DEPLOY_PRIVATE_KEY || "";
if (!KEY) {
  console.error("ERROR: set R4_DEPLOY_PRIVATE_KEY (Base Sepolia testnet deployer key).");
  process.exit(1);
}
if (!KEY.startsWith("0x")) KEY = "0x" + KEY;

// ── 1. compile Groth16Verifier.gen.sol ──────────────────────────────
const SOL = "Groth16Verifier.gen.sol";
const source = readFileSync(join(root, "solidity", SOL), "utf8");
console.log(`[1/4] compiling solidity/${SOL} …`);

const input = {
  language: "Solidity",
  sources: { [SOL]: { content: source } },
  settings: {
    optimizer: { enabled: true, runs: 200 },
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const fatal = (out.errors || []).filter((e) => e.severity === "error");
if (fatal.length) {
  console.error(fatal.map((e) => e.formattedMessage).join("\n"));
  process.exit(1);
}
const c = out.contracts[SOL]["Groth16Verifier"];
const abi = c.abi;
const bytecode = "0x" + c.evm.bytecode.object;
console.log(`      → compiled · bytecode ${bytecode.length / 2 - 1} bytes`);

// ── 2. connect to Base Sepolia ──────────────────────────────────────
const account = privateKeyToAccount(KEY);
const wallet = createWalletClient({ account, chain: baseSepolia, transport: http(RPC) });
const pub = createPublicClient({ chain: baseSepolia, transport: http(RPC) });

const bal = await pub.getBalance({ address: account.address });
console.log(`[2/4] deployer ${account.address} · balance ${(Number(bal) / 1e18).toFixed(6)} ETH`);
if (bal === 0n) {
  console.error("ERROR: deployer has 0 Base Sepolia ETH — fund it first.");
  process.exit(1);
}

// ── 3. deploy ───────────────────────────────────────────────────────
console.log("[3/4] deploying Groth16Verifier …");
const txHash = await wallet.deployContract({ abi, bytecode });
console.log(`      deploy tx: ${txHash}`);
const receipt = await pub.waitForTransactionReceipt({ hash: txHash });
if (receipt.status !== "success") {
  console.error("ERROR: deploy transaction reverted.");
  process.exit(1);
}
const verifierAddress = receipt.contractAddress;
console.log(`      → Groth16Verifier @ ${verifierAddress}  (block ${receipt.blockNumber})`);

// ── 4. on-chain smoke test: verifyProof(example proof) ─────────────
console.log("[4/4] on-chain smoke test — verifyProof(example proof.json) …");
let smoke = "skipped (no proof.json)";
try {
  const proofObj = JSON.parse(readFileSync(join(root, "proof.json"), "utf8"));
  const rawProof = { ...proofObj.proof, protocol: "groth16", curve: "bn128" };
  const calldata = await groth16.exportSolidityCallData(rawProof, proofObj.public_inputs);
  const [pA, pB, pC, pubSignals] = JSON.parse("[" + calldata + "]");
  const ok = await pub.readContract({
    address: verifierAddress,
    abi,
    functionName: "verifyProof",
    args: [pA, pB, pC, pubSignals],
  });
  smoke = ok === true ? "PASS — verifyProof returned true" : "FAIL — verifyProof returned false";
} catch (e) {
  smoke = "error: " + (e?.message || String(e));
}
console.log(`      → ${smoke}`);

console.log("\n── R4.3 deploy complete ────────────────────────────────────────");
console.log(`  network  : Base Sepolia (chainId 84532)`);
console.log(`  verifier : ${verifierAddress}`);
console.log(`  deploy tx: ${txHash}`);
console.log(`  block    : ${receipt.blockNumber}`);
console.log(`  basescan : https://sepolia.basescan.org/address/${verifierAddress}`);
console.log(`  smoke    : ${smoke}`);
