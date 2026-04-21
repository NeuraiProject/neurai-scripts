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
export { encodeP2PKHScriptPubKey, encodeAuthScriptScriptPubKey };
/**
 * Resolve any accepted seller address string into its scriptPubKey.
 * The returned bytes are what the covenant will hardcode and later verify
 * via `OP_OUTPUTSCRIPT == <bytes>`.
 */
export declare function encodeSellerScriptPubKey(address: string): SellerScriptPubKey;
