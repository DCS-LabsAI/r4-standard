// ═══════════════════════════════════════════════════════════════════
// R4.4 — deploy the PRODUCTION Groth16 verifier to BASE MAINNET.
//
// This deploys solidity/Groth16Verifier.prod.sol — the verifier emitted
// from the ceremony key phase2_final.zkey (production trusted setup),
// NOT the dev-key verifier. Run this only AFTER the R+4.5 ceremony has
// completed and `snarkjs zkey verify` printed `ZKey Ok!`.
//
// ⚠️  MAINNET — this spends REAL ETH on Base. Gas cost is small (a few
//     US cents to a couple of dollars) but the transaction is permanent.
//
// Prereqs (run in r4-reference/):
//   npm install            # ensures solc + viem + snarkjs are present
//   snarkjs zkey export solidityverifier ceremony/phase2_final.zkey \
//           solidity/Groth16Verifier.prod.sol
//
// Env:
//   R4_DEPLOY_PRIVATE_KEY   a FUNDED Base mainnet wallet key (0x-hex).
//                           Use a low-value deploy-only wallet.
//                           Set it in the terminal — never paste it
//                           anywhere else.
//   BASE_RPC                optional — defaults to https://mainnet.base.org
//
// Run:  node scripts/deploy-verifier-mainnet.mjs
// ═══════════════════════════════════════════════════════════════════
import { readFileSync, existsSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import solc from "solc";
import { groth16 } from "snarkjs";
import { createWalletClient, createPublicClient, http } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { base } from "viem/chains";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const RPC = process.env.BASE_RPC || "https://mainnet.base.org";
let KEY = process.env.R4_DEPLOY_PRIVATE_KEY || "";
if (!KEY) {
  console.error("ERROR: set R4_DEPLOY_PRIVATE_KEY (a funded Base MAINNET wallet key).");
  process.exit(1);
}
if (!KEY.startsWith("0x")) KEY = "0x" + KEY;

// ── 1. compile the production verifier ──────────────────────────────
const SOL = "Groth16Verifier.prod.sol";
const solPath = join(root, "solidity", SOL);
if (!existsSync(solPath)) {
  console.error(`ERROR: solidity/${SOL} not found.`);
  console.error("Generate it first:");
  console.error("  snarkjs zkey export solidityverifier ceremony/phase2_final.zkey \\");
  console.error("          solidity/Groth16Verifier.prod.sol");
  process.exit(1);
}
const source = readFileSync(solPath, "utf8");
console.log(`[1/4] compiling solidity/${SOL} (production / ceremony key) …`);

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

// ── 2. connect to Base mainnet ──────────────────────────────────────
const account = privateKeyToAccount(KEY);
const wallet = createWalletClient({ account, chain: base, transport: http(RPC) });
const pub = createPublicClient({ chain: base, transport: http(RPC) });

const bal = await pub.getBalance({ address: account.address });
console.log(`[2/4] deployer ${account.address}`);
console.log(`      network Base MAINNET (chainId 8453) · balance ${(Number(bal) / 1e18).toFixed(6)} ETH`);
if (bal === 0n) {
  console.error("ERROR: deployer has 0 Base mainnet ETH — fund it first (a few dollars is plenty).");
  process.exit(1);
}

// ── 3. deploy ───────────────────────────────────────────────────────
console.log("[3/4] deploying production Groth16Verifier to Base mainnet …");
const txHash = await wallet.deployContract({ abi, bytecode });
console.log(`      deploy tx: ${txHash}`);
const receipt = await pub.waitForTransactionReceipt({ hash: txHash });
if (receipt.status !== "success") {
  console.error("ERROR: deploy transaction reverted.");
  process.exit(1);
}
const verifierAddress = receipt.contractAddress;
console.log(`      → Groth16Verifier @ ${verifierAddress}  (block ${receipt.blockNumber})`);

// ── 4. optional on-chain smoke test (free — verifyProof is a view call)
// Needs a proof produced under the PRODUCTION key. If proof-prod.json is
// absent this step is skipped cleanly — the deploy itself is complete.
console.log("[4/4] on-chain smoke test — verifyProof(proof-prod.json) …");
let smoke = "skipped (no proof-prod.json — generate a production-key proof to confirm)";
try {
  const pf = join(root, "proof-prod.json");
  if (existsSync(pf)) {
    const proofObj = JSON.parse(readFileSync(pf, "utf8"));
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
  }
} catch (e) {
  smoke = "error: " + (e?.message || String(e));
}
console.log(`      → ${smoke}`);

console.log("\n── R+4 mainnet deploy complete ─────────────────────────────────");
console.log(`  network  : Base MAINNET (chainId 8453)`);
console.log(`  verifier : ${verifierAddress}`);
console.log(`  deploy tx: ${txHash}`);
console.log(`  block    : ${receipt.blockNumber}`);
console.log(`  basescan : https://basescan.org/address/${verifierAddress}`);
console.log(`  smoke    : ${smoke}`);
console.log("\n  Record the verifier address + deploy tx — that is the R+4");
console.log("  mainnet proof. Production keys, ceremony-backed.");
