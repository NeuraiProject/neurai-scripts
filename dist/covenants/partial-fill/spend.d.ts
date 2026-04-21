/**
 * scriptSig builders for the Partial-Fill Sell Order covenant.
 *
 * These return the raw scriptSig bytes that unlock the covenant UTXO. The
 * surrounding transaction (inputs, outputs, fees, signatures on the buyer's
 * own inputs, etc.) is the caller's responsibility — stitch them together
 * with `@neuraiproject/neurai-create-transaction`.
 */
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
export declare function buildFillScriptSig(amount: bigint): Uint8Array;
export declare function buildFillScriptSigHex(amount: bigint): string;
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
export declare function buildCancelScriptSig(signatureDer: Uint8Array, pubKey: Uint8Array): Uint8Array;
export declare function buildCancelScriptSigHex(signatureDer: Uint8Array, pubKey: Uint8Array): string;
