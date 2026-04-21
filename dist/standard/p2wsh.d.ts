/**
 * Native segwit v0 Pay-to-Witness-Script-Hash (P2WSH) scriptPubKey.
 * Layout: OP_0 0x20 <32-byte SHA256(witnessScript)>
 *
 * This helper takes the SHA256 digest of the witness script directly. The
 * SHA256 is computed externally by the caller's crypto stack (kept out of
 * this library to avoid a hash dependency).
 */
export declare function encodeP2WSHScriptPubKey(witnessScriptSha256: Uint8Array): Uint8Array;
