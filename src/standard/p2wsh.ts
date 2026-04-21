/**
 * Native segwit v0 Pay-to-Witness-Script-Hash (P2WSH) scriptPubKey.
 * Layout: OP_0 0x20 <32-byte SHA256(witnessScript)>
 *
 * This helper takes the SHA256 digest of the witness script directly. The
 * SHA256 is computed externally by the caller's crypto stack (kept out of
 * this library to avoid a hash dependency).
 */

import { concatBytes } from '../core/bytes.js';
import { OP_0 } from '../core/opcodes.js';

export function encodeP2WSHScriptPubKey(witnessScriptSha256: Uint8Array): Uint8Array {
  if (!(witnessScriptSha256 instanceof Uint8Array) || witnessScriptSha256.length !== 32) {
    throw new Error('P2WSH witnessScriptSha256 must be a 32-byte Uint8Array');
  }
  return concatBytes(Uint8Array.of(OP_0, 0x20), witnessScriptSha256);
}
