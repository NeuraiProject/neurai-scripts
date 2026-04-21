/**
 * Native segwit v0 Pay-to-Witness-Public-Key-Hash (P2WPKH) scriptPubKey.
 * Layout: OP_0 0x14 <20-byte HASH160(pubKey)>
 *
 * Callers compute HASH160 externally (e.g. via neurai-key / their crypto
 * stack). This helper only encodes the scriptPubKey once the hash is known.
 */
export declare function encodeP2WPKHScriptPubKey(pubKeyHash: Uint8Array): Uint8Array;
