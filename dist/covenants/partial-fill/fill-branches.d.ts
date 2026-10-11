/**
 * Buyer fill branches shared by both Partial-Fill Sell Order variants
 * (ECDSA cancel in `./script.ts`, ML-DSA-44 cancel in `./script-pq.ts`).
 * The variants only differ in their cancel branch; everything after the
 * outer `OP_ELSE` is emitted and parsed here.
 *
 * Input-0 binding. The fill branches read the order's asset amount with
 * `<0> OP_INPUTASSETFIELD` and constrain outputs 0..2 by fixed index. Input
 * indices are absolute and Script cannot ask for the index of the input
 * being evaluated, so without a binding a buyer could:
 *   - put a foreign asset UTXO at input 0 and the order at input 1: the
 *     order then prices the fill by the foreign amount and the rest of the
 *     order leaves through an unconstrained output;
 *   - spend several identical orders together, every one of them satisfied
 *     by the same payment output.
 * The fill block therefore opens with
 *
 *   <0x80 0x00> OP_TXHASH <INPUT_ZERO_TXHASH> OP_EQUALVERIFY
 *
 * NIP-042 mask 0x0080 commits only to the index of the input being
 * evaluated, so the digest equals the constant exactly when this covenant
 * is spent as input 0. At most one order per transaction can take a fill
 * branch; the seller's cancel branch is not bound.
 *
 * Layout (after the variant's `OP_IF <cancel> OP_ELSE`):
 *
 *   <0x80 0x00> OP_TXHASH <INPUT_ZERO_TXHASH> OP_EQUALVERIFY
 *   OP_IF                                                  ← full fill, unlock <1> <0>
 *     [expiration gate]
 *     <0> <2> OP_INPUTASSETFIELD                           (N = order amount)
 *     DUP <price> MUL <0> OUTPUTVALUE SWAP GE VERIFY       (payment value)
 *     <0> OUTPUTSCRIPT <paymentSpk> EQUALVERIFY            (payment destination)
 *     DUP <1> <2> OUTPUTASSETFIELD EQUALVERIFY             (buyer amount == N)
 *     <1> <1> OUTPUTASSETFIELD <tokenId> EQUALVERIFY       (buyer asset name)
 *     DROP <1>
 *   OP_ELSE                                                ← partial fill, unlock <N> <0> <0>
 *     [expiration gate]
 *     payment value, payment destination, buyer amount, buyer name (as above)
 *     <2> OUTPUTAUTHCOMMITMENT <2> TXFIELD EQUALVERIFY     (continuation, NIP-023)
 *     <2> <1> OUTPUTASSETFIELD <tokenId> EQUALVERIFY       (continuation name)
 *     <2> <2> OUTPUTASSETFIELD OVER <0> <2> INPUTASSETFIELD SWAP SUB EQUALVERIFY
 *     DROP <1>
 *   OP_ENDIF
 */
import type { ScriptBuilder } from '../../core/script-builder.js';
import type { Cursor } from '../../core/script-parser.js';
import type { PartialFillExpiration } from '../../types.js';
/** NIP-042 mask (two bytes, little-endian) selecting only the current input index. */
export declare const INPUT_INDEX_TXHASH_SELECTOR: Uint8Array<ArrayBuffer>;
/**
 * `OP_TXHASH(0x0080)` evaluated at input 0:
 * `SHA256(tag || tag || 80 00 || 00 00 00 00)` with `tag = SHA256("NeuraiTxHash")`.
 */
export declare const INPUT_ZERO_TXHASH: Uint8Array<ArrayBufferLike>;
export interface FillBranchParams {
    /** scriptPubKey output 0 must pay (any destination type, no asset suffix). */
    paymentScriptPubKey: Uint8Array;
    tokenIdBytes: Uint8Array;
    unitPriceSats: bigint;
    expiration?: PartialFillExpiration;
}
export interface ParsedFillBranches {
    paymentScriptPubKey: Uint8Array;
    tokenId: string;
    unitPriceSats: bigint;
    expiration?: PartialFillExpiration;
}
/** Emit the input-0 binding and both fill branches, ending with the inner `OP_ENDIF`. */
export declare function appendFillBranches(b: ScriptBuilder, p: FillBranchParams): void;
/**
 * Parse what `appendFillBranches` emits. Both branches must agree on price,
 * payment destination, tokenId and expiration; any deviation throws.
 */
export declare function readFillBranches(c: Cursor): ParsedFillBranches;
