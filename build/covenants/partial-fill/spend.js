/**
 * scriptSig builders for the Partial-Fill Sell Order covenant.
 *
 * These return the raw scriptSig bytes that unlock the covenant UTXO. The
 * surrounding transaction (inputs, outputs, fees, signatures on the buyer's
 * own inputs, etc.) is the caller's responsibility — stitch them together
 * with `@neuraiproject/neurai-create-transaction`.
 */
import { bytesToHex } from '../../core/bytes.js';
import { ScriptBuilder } from '../../core/script-builder.js';
/**
 * Unlock the covenant via the public partial-fill branch.
 *
 * Layout on the stack before OP_IF executes (top → bottom):
 *   0   ← selects the OP_ELSE (fill) branch
 *   N   ← amount of asset the buyer is taking from this order
 *
 * so the scriptSig pushes `<N>` then `<0>`.
 *
 * @param amount  units of the asset the buyer is taking. Must be > 0 and
 *                strictly less than the amount locked in the order UTXO
 *                (equal would leave a zero-asset remainder, which isn't a
 *                valid Neurai transfer output).
 */
export function buildFillScriptSig(amount) {
    if (typeof amount !== 'bigint') {
        throw new Error('amount must be a bigint');
    }
    if (amount <= 0n) {
        throw new Error('fill amount must be > 0');
    }
    return new ScriptBuilder()
        .pushInt(amount)
        .pushInt(0)
        .build();
}
export function buildFillScriptSigHex(amount) {
    return bytesToHex(buildFillScriptSig(amount));
}
/**
 * Unlock the covenant via the seller's cancel branch.
 *
 * Stack before OP_IF (top → bottom):
 *   1       ← selects the OP_IF branch
 *   pubkey  ← consumed by OP_DUP OP_HASH160 … OP_EQUALVERIFY
 *   sig     ← consumed by OP_CHECKSIG
 *
 * so the scriptSig pushes `<sig> <pubkey> <1>`.
 *
 * The signature is on whatever sighash the caller picked; this builder does
 * not hash or sign, it only assembles the unlock script once a signature is
 * available.
 */
export function buildCancelScriptSig(signatureDer, pubKey) {
    if (!(signatureDer instanceof Uint8Array) || signatureDer.length === 0) {
        throw new Error('signatureDer must be a non-empty Uint8Array');
    }
    if (!(pubKey instanceof Uint8Array) || (pubKey.length !== 33 && pubKey.length !== 65)) {
        throw new Error('pubKey must be a compressed (33B) or uncompressed (65B) secp256k1 key');
    }
    return new ScriptBuilder()
        .pushBytes(signatureDer)
        .pushBytes(pubKey)
        .pushInt(1)
        .build();
}
export function buildCancelScriptSigHex(signatureDer, pubKey) {
    return bytesToHex(buildCancelScriptSig(signatureDer, pubKey));
}
