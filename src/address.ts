/**
 * Address helpers. Wraps `decodeAddress` from
 * `@neuraiproject/neurai-create-transaction` to produce the exact
 * scriptPubKey bytes a covenant needs to hardcode. The actual
 * scriptPubKey encoders live in `./standard/*`; this module delegates.
 *
 * Two destination types are supported for the payment output (output[0]):
 *   - Legacy P2PKH (base58check)
 *   - AuthScript witness v1 (bech32m)
 */

import { decodeAddress } from '@neuraiproject/neurai-create-transaction';
import { encodeP2PKHScriptPubKey } from './standard/p2pkh.js';
import { encodeAuthScriptScriptPubKey } from './standard/authscript.js';

export type SellerAddressKind = 'p2pkh' | 'authscript';

export interface SellerScriptPubKey {
  kind: SellerAddressKind;
  /** Raw scriptPubKey bytes that output[0] of a fill tx must equal. */
  bytes: Uint8Array;
  /**
   * Address-specific hash: 20-byte PKH for P2PKH, 32-byte program for
   * AuthScript. Used by the cancel branch (either as the HASH160 target or
   * as the SHA256(pubKey) commitment).
   */
  hash: Uint8Array;
}

// Re-export for callers that imported these from `address` pre-refactor. The
// canonical path going forward is `./standard/p2pkh` / `./standard/authscript`.
export { encodeP2PKHScriptPubKey, encodeAuthScriptScriptPubKey };

/**
 * Resolve any accepted seller address string into its scriptPubKey.
 * The returned bytes are what the covenant will hardcode and later verify
 * via `OP_OUTPUTSCRIPT == <bytes>`.
 */
export function encodeSellerScriptPubKey(address: string): SellerScriptPubKey {
  const decoded = decodeAddress(address);
  if (decoded.type === 'p2pkh') {
    const hash = Uint8Array.from(decoded.hash);
    return {
      kind: 'p2pkh',
      bytes: encodeP2PKHScriptPubKey(hash),
      hash
    };
  }
  if (decoded.type === 'authscript') {
    const program = Uint8Array.from(decoded.program);
    return {
      kind: 'authscript',
      bytes: encodeAuthScriptScriptPubKey(program),
      hash: program
    };
  }
  throw new Error(`Unsupported seller address type for "${address}"`);
}
