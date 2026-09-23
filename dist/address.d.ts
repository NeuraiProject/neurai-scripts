/**
 * Address helpers. Wraps `decodeAddress` from
 * `@neuraiproject/neurai-create-transaction` to produce the exact
 * scriptPubKey bytes a covenant needs to hardcode. The actual
 * scriptPubKey encoders live in `./standard/*`; this module delegates.
 *
 * Every Neurai destination type is supported for the payment output
 * (output[0]):
 *   - Legacy P2PKH (base58check)                     → `76a914<20>88ac`
 *   - Generic AuthScript witness v1 (nc1p… / tnc1p…) → `5120<32>`
 *   - Strict PQ witness v2 (pq1z… / tpq1z…)          → `5220<32>`
 *   - Strict ECDSA witness v3 (nq1r… / tnq1r…)       → `5320<32>`
 */
import { encodeP2PKHScriptPubKey } from './standard/p2pkh.js';
import { encodeAuthScriptScriptPubKey } from './standard/authscript.js';
import type { AuthScriptWitnessVersion } from './standard/authscript.js';
/**
 * `authscript` is the generic witness v1; `pq` and `ecdsa` are the strict
 * witness v2 and v3 families.
 */
export type SellerAddressKind = 'p2pkh' | 'authscript' | 'pq' | 'ecdsa';
export interface SellerScriptPubKey {
    kind: SellerAddressKind;
    /** Witness version of an AuthScript destination (1, 2 or 3). */
    witnessVersion?: AuthScriptWitnessVersion;
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
