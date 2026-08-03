/**
 * Witness-stack builders for the Partial-Fill Sell Order covenant.
 *
 * When the covenant lives behind an AuthScript commitment (the only
 * asset-compatible deployment since the node's OP_XNA_ASSET placement rules
 * — bare covenant outputs can no longer carry assets), the unlock data goes
 * in the witness, not the scriptSig. The scriptSig builders in `spend.ts`
 * return a serialized script that PUSHES the elements; a witness needs the
 * elements THEMSELVES, one per stack slot, so those blobs cannot be reused
 * as a single `args` entry.
 *
 * These builders return the raw `args` stack (bottom → top), mirroring the
 * shapes documented in `spend.ts`:
 *
 *   Full fill:     [ <1>, <0> ]
 *   Partial fill:  [ <N>, <0>, <0> ]
 *   Cancel:        [ <sig>, <pubkey>, <1> ]
 *
 * Numbers are minimal CScriptNum stack values (0 = empty element). Wrap the
 * result with `buildAuthScriptWitnessNoAuth({ args, witnessScript: covenant })`
 * (from `standard/authscript.ts`) to get the final `[0x00, ...args, covenant]`
 * witness.
 */
import { encodeScriptNum } from '../../core/script-builder.js';
const MAX_PQ_SCRIPT_ELEMENT_SIZE = 3072;
/**
 * Witness `args` for the public fill branches. Same semantics and
 * validations as `buildFillScriptSig`.
 */
export function buildFillWitnessStack(amount, total) {
    if (typeof amount !== 'bigint' || typeof total !== 'bigint') {
        throw new Error('amount and total must be bigint');
    }
    if (amount <= 0n) {
        throw new Error('fill amount must be > 0');
    }
    if (total <= 0n) {
        throw new Error('total must be > 0');
    }
    if (amount > total) {
        throw new Error('fill amount exceeds the covenant total');
    }
    if (amount === total) {
        // Full fill: covenant drains entirely; buyer does not push N.
        return [encodeScriptNum(1n), encodeScriptNum(0n)];
    }
    // Partial fill: N, then both flag values.
    return [encodeScriptNum(amount), encodeScriptNum(0n), encodeScriptNum(0n)];
}
/**
 * Witness `args` for the seller's ECDSA cancel branch. Same semantics and
 * validations as `buildCancelScriptSig`.
 */
export function buildCancelWitnessStack(signatureDer, pubKey) {
    if (!(signatureDer instanceof Uint8Array) || signatureDer.length === 0) {
        throw new Error('signatureDer must be a non-empty Uint8Array');
    }
    if (!(pubKey instanceof Uint8Array) || (pubKey.length !== 33 && pubKey.length !== 65)) {
        throw new Error('pubKey must be a compressed (33B) or uncompressed (65B) secp256k1 key');
    }
    return [signatureDer, pubKey, encodeScriptNum(1n)];
}
/**
 * Witness `args` for the seller's PQ (ML-DSA-44) cancel branch. Same
 * semantics and validations as `buildCancelScriptSigPQ`.
 */
export function buildCancelWitnessStackPQ(sigPQ, pubKey) {
    if (!(sigPQ instanceof Uint8Array) || sigPQ.length === 0) {
        throw new Error('sigPQ must be a non-empty Uint8Array');
    }
    if (sigPQ.length > MAX_PQ_SCRIPT_ELEMENT_SIZE) {
        throw new Error(`sigPQ of ${sigPQ.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (${MAX_PQ_SCRIPT_ELEMENT_SIZE})`);
    }
    if (!(pubKey instanceof Uint8Array) || pubKey.length === 0) {
        throw new Error('pubKey must be a non-empty Uint8Array');
    }
    if (pubKey.length > MAX_PQ_SCRIPT_ELEMENT_SIZE) {
        throw new Error(`pubKey of ${pubKey.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (${MAX_PQ_SCRIPT_ELEMENT_SIZE})`);
    }
    return [sigPQ, pubKey, encodeScriptNum(1n)];
}
