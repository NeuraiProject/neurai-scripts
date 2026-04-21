/**
 * Pay-to-Public-Key-Hash (P2PKH) scriptPubKey.
 * Layout: OP_DUP OP_HASH160 0x14 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG
 */

import { concatBytes } from '../core/bytes.js';
import { OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160 } from '../core/opcodes.js';

export function encodeP2PKHScriptPubKey(pubKeyHash: Uint8Array): Uint8Array {
  if (!(pubKeyHash instanceof Uint8Array) || pubKeyHash.length !== 20) {
    throw new Error('P2PKH pubKeyHash must be a 20-byte Uint8Array');
  }
  return concatBytes(
    Uint8Array.of(OP_DUP, OP_HASH160, 0x14),
    pubKeyHash,
    Uint8Array.of(OP_EQUALVERIFY, OP_CHECKSIG)
  );
}
