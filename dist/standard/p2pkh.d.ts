/**
 * Pay-to-Public-Key-Hash (P2PKH) scriptPubKey.
 * Layout: OP_DUP OP_HASH160 0x14 <20-byte PKH> OP_EQUALVERIFY OP_CHECKSIG
 */
export declare function encodeP2PKHScriptPubKey(pubKeyHash: Uint8Array): Uint8Array;
