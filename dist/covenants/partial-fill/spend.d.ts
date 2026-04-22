/**
 * scriptSig builders for the Partial-Fill Sell Order covenant.
 *
 * These return the raw scriptSig bytes that unlock the covenant UTXO. The
 * surrounding transaction (inputs, outputs, fees, signatures on the buyer's
 * own inputs, etc.) is the caller's responsibility — stitch them together
 * with `@neuraiproject/neurai-create-transaction`.
 */
/**
 * Unlock the covenant via the public fill branches.
 *
 *   amount === total  →  full-fill branch. The entire covenant drains to
 *                        vout[1]; no vout[2] continuation is emitted.
 *   amount <  total   →  partial-fill branch. vout[2] re-locks the
 *                        continuation (`total - amount` units).
 *
 * Unlock stack shapes (pushed bottom → top):
 *
 *   Full fill:     <1> <0>         ( full-flag=1, cancel-flag=0 )
 *   Partial fill:  <N> <0> <0>     ( N, full-flag=0, cancel-flag=0 )
 *
 * @param amount  units the buyer is taking. Must be > 0 and ≤ total.
 * @param total   current asset amount locked in the covenant UTXO. The
 *                builder reads this to decide whether to emit the full-fill
 *                or partial-fill witness — consensus uses `OP_INPUTASSETFIELD`
 *                inside the covenant to check it independently, so the value
 *                passed here must match on-chain reality or the script fails.
 */
export declare function buildFillScriptSig(amount: bigint, total: bigint): Uint8Array;
export declare function buildFillScriptSigHex(amount: bigint, total: bigint): string;
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
