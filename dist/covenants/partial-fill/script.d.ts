/**
 * Partial-Fill Sell Order covenant script.
 *
 * The covenant has two branches selected by the top of the unlock stack:
 *
 *   OP_IF   (unlock pushed 1)  → Cancel: seller signs, recovers remainder.
 *   OP_ELSE (unlock pushed 0)  → Public partial fill: buyer provides the
 *                                 fill amount `N` and the tx layout is
 *                                 validated byte by byte.
 *
 * The partial-fill branch enforces a fixed output layout so that the script
 * stays compact and parseable:
 *
 *   output[0] = XNA payment to seller   (value >= N * unitPriceSats)
 *   output[1] = asset to buyer          (tokenId, amount == N)
 *   output[2] = covenant remainder      (same scriptPubKey, amount == in - N)
 *   output[3+] = optional buyer change  (not constrained by the covenant)
 *
 * The remainder UTXO reuses the spent scriptPubKey via
 * `OP_OUTPUTSCRIPT == OP_TXFIELD 0x03`, so the covenant is self-replicating
 * without hardcoding its own hash.
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`) and
 * commits to a 20-byte PKH. As a consequence this variant only accepts
 * legacy P2PKH addresses as the seller destination. For AuthScript bech32m
 * destinations and post-quantum signing, use `buildPartialFillScriptPQ`.
 */
import type { PartialFillOrderParams } from '../../types.js';
export { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';
/**
 * Build the `scriptPubKey` of a Partial-Fill Sell Order covenant UTXO.
 * Returns raw bytes; wrap with `bytesToHex` for wire format.
 */
export declare function buildPartialFillScript(params: PartialFillOrderParams): Uint8Array;
/** Hex convenience wrapper for `buildPartialFillScript`. */
export declare function buildPartialFillScriptHex(params: PartialFillOrderParams): string;
export { pushBytes, pushInt } from '../../core/script-builder.js';
