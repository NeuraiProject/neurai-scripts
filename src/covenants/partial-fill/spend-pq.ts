/**
 * scriptSig builders for the PQ Partial-Fill Sell Order covenant.
 *
 * The fill branch is identical to the legacy variant (just pushes `<N> <0>`),
 * so callers reuse `buildFillScriptSig` from `./spend.ts`. Only the cancel
 * branch is different: it carries a full PQ pubkey (~1313 B) and signature
 * (~2421 B), which requires NIP-18's expanded element-size cap.
 */

import { bytesToHex } from '../../core/bytes.js';
import { ScriptBuilder } from '../../core/script-builder.js';

/**
 * Build the scriptSig that unlocks the PQ cancel branch.
 *
 * Stack ordering pushed (bottom → top): `sig, pubkey, 1`.
 *
 * @param sigPQ   ML-DSA-44 signature over `SHA256(OP_TXHASH(selector))`,
 *                **with trailing sighash byte appended** (same convention as
 *                OP_CHECKSIG — CSFS strips it before verification). Expected
 *                length 2421 bytes for ML-DSA-44.
 * @param pubKey  Versioned PQ public key bytes, 1313 bytes (1-byte prefix
 *                + 1312-byte ML-DSA-44 key). Must hash (via SHA256) to the
 *                `pubKeyCommitment` embedded in the covenant scriptPubKey.
 */
export function buildCancelScriptSigPQ(
  sigPQ: Uint8Array,
  pubKey: Uint8Array
): Uint8Array {
  if (!(sigPQ instanceof Uint8Array) || sigPQ.length === 0) {
    throw new Error('sigPQ must be a non-empty Uint8Array');
  }
  if (sigPQ.length > 3072) {
    throw new Error(
      `sigPQ of ${sigPQ.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (3072)`
    );
  }
  if (!(pubKey instanceof Uint8Array) || pubKey.length === 0) {
    throw new Error('pubKey must be a non-empty Uint8Array');
  }
  if (pubKey.length > 3072) {
    throw new Error(
      `pubKey of ${pubKey.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (3072)`
    );
  }
  return new ScriptBuilder()
    .pushBytes(sigPQ)
    .pushBytes(pubKey)
    .pushInt(1)
    .build();
}

export function buildCancelScriptSigPQHex(
  sigPQ: Uint8Array,
  pubKey: Uint8Array
): string {
  return bytesToHex(buildCancelScriptSigPQ(sigPQ, pubKey));
}
