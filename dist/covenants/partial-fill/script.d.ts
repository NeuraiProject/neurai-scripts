/**
 * Partial-Fill Sell Order covenant script (three-branch), ECDSA cancel.
 *
 * The covenant has three branches selected by the top of the unlock stack:
 *
 *   OP_IF                  ← Cancel: seller signs, recovers remainder.
 *   OP_ELSE OP_IF          ← Full fill: buyer drains the covenant entirely.
 *                            No continuation output is required.
 *   OP_ELSE OP_ELSE        ← Partial fill: buyer takes N < total. A
 *                            continuation UTXO at vout[2] preserves the
 *                            covenant with amount = total - N.
 *
 * Output layout:
 *
 *   output[0] = XNA payment to seller   (value >= N * unitPriceSats)
 *   output[1] = asset to buyer          (tokenId, amount == N)
 *   output[2] = covenant continuation   (only for partial fill;
 *                                        same AuthScript commitment,
 *                                        amount == inputAmount - N)
 *   output[3+] = optional buyer change  (not constrained by the covenant)
 *
 * The order must be input 0 for either fill branch to succeed: see the
 * input-0 binding in `./fill-branches.ts`.
 *
 * Unlock stack shapes (scriptSig pushes, top → bottom):
 *
 *   Cancel:        <sig> <pubkey> <1>
 *   Full fill:            <1>       <0>       (full-flag=1, cancel-flag=0)
 *   Partial fill:  <N>    <0>       <0>       (N, full-flag=0, cancel-flag=0)
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`)
 * against a 20-byte key hash. The payment destination is independent of
 * that key: a legacy P2PKH seller passes `sellerAddress` (both at once),
 * any other seller with a secp256k1 key — typically a strict ECDSA v3
 * `nq1r…` wallet — passes `paymentAddress` and `sellerPubKeyHash`. For
 * post-quantum cancellation use `buildPartialFillScriptPQ`.
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
