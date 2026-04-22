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
export function buildFillScriptSig(amount: bigint, total: bigint): Uint8Array {
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

  const b = new ScriptBuilder();
  if (amount === total) {
    // Full fill: covenant drains entirely. Buyer does not push N — the
    // covenant reads it via OP_INPUTASSETFIELD.
    b.pushInt(1).pushInt(0);
  } else {
    // Partial fill: buyer pushes N, then both flag bytes.
    b.pushInt(amount).pushInt(0).pushInt(0);
  }
  return b.build();
}

export function buildFillScriptSigHex(amount: bigint, total: bigint): string {
  return bytesToHex(buildFillScriptSig(amount, total));
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
export function buildCancelScriptSig(
  signatureDer: Uint8Array,
  pubKey: Uint8Array
): Uint8Array {
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

export function buildCancelScriptSigHex(
  signatureDer: Uint8Array,
  pubKey: Uint8Array
): string {
  return bytesToHex(buildCancelScriptSig(signatureDer, pubKey));
}
