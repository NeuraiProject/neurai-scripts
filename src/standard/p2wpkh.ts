/**
 * Native segwit v0 Pay-to-Witness-Public-Key-Hash (P2WPKH) scriptPubKey.
 * Layout: OP_0 0x14 <20-byte HASH160(pubKey)>
 *
 * Callers compute HASH160 externally (e.g. via neurai-key / their crypto
 * stack). This helper only encodes the scriptPubKey once the hash is known.
 */

import { concatBytes } from '../core/bytes.js';
import { OP_0 } from '../core/opcodes.js';

export function encodeP2WPKHScriptPubKey(pubKeyHash: Uint8Array): Uint8Array {
  if (!(pubKeyHash instanceof Uint8Array) || pubKeyHash.length !== 20) {
    throw new Error('P2WPKH pubKeyHash must be a 20-byte Uint8Array');
  }
  return concatBytes(Uint8Array.of(OP_0, 0x14), pubKeyHash);
}
