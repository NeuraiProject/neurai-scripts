/**
 * PQ (post-quantum) variant of the Partial-Fill Sell Order covenant.
 *
 * Identical partial-fill branch to the legacy covenant, but the **cancel**
 * branch accepts an ML-DSA-44 signature instead of an ECDSA one. This
 * requires:
 *   - `SCRIPT_VERIFY_CHECKSIGFROMSTACK` (for OP_CSFS) active
 *   - `SCRIPT_VERIFY_TXHASH` (for OP_TXHASH) active
 *   - NIP-18 (`MAX_PQ_SCRIPT_ELEMENT_SIZE = 3072`) active, so the ~2.4 KB
 *     signature and ~1.3 KB pubkey can be pushed to the script stack
 *
 * All three are active on DePIN-Test testnet.
 *
 * Cancel-branch flow (scriptSig pushes `<sig> <pubkey> OP_1`):
 *
 *   1. OP_DUP OP_SHA256 <commitment> OP_EQUALVERIFY   → pubkey matches
 *   2. <selector> OP_TXHASH                           → message = H(tx)
 *   3. OP_SWAP OP_CHECKSIGFROMSTACK                   → CSFS verifies sig
 *
 * The message that gets signed is **SHA256(OP_TXHASH(selector))** — CSFS
 * single-SHA256s its message argument before verification, and OP_TXHASH
 * produces its own 32-byte hash, so the seller computes:
 *   `sign(pqSeckey, SHA256(doubleSHA256(selected_tx_fields)))`
 */
import type { PartialFillOrderPQParams } from '../../types.js';
export declare const DEFAULT_PQ_TXHASH_SELECTOR = 255;
/**
 * Build the scriptPubKey of a PQ Partial-Fill Sell Order covenant UTXO.
 */
export declare function buildPartialFillScriptPQ(params: PartialFillOrderPQParams): Uint8Array;
export declare function buildPartialFillScriptPQHex(params: PartialFillOrderPQParams): string;
