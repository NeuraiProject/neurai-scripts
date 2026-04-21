/**
 * Classic bare m-of-n multisig via OP_CHECKMULTISIG, plus the P2SH wrapper
 * that is normally used in practice.
 *
 *   redeemScript = <m> <pubkey_1> ... <pubkey_n> <n> OP_CHECKMULTISIG
 *   P2SH spk     = OP_HASH160 0x14 <HASH160(redeemScript)> OP_EQUAL
 *
 * OP_CHECKMULTISIG caps n at 20 pubkeys (see `MAX_PUBKEYS_PER_MULTISIG` in
 * the Neurai interpreter). Bare multisig outputs are still consensus-valid
 * but non-standard for relay; the P2SH wrapping is what mempool accepts.
 */
export declare const MULTISIG_MAX_PUBKEYS = 20;
export interface MultisigParams {
    /** Number of required signatures (1..n). */
    m: number;
    /** Compressed (33B) or uncompressed (65B) secp256k1 pubkeys, ordered. */
    pubKeys: Uint8Array[];
}
export declare function encodeMultisigRedeemScript({ m, pubKeys }: MultisigParams): Uint8Array;
export declare function encodeMultisigRedeemScriptHex(params: MultisigParams): string;
/**
 * P2SH scriptPubKey wrapping any redeem script. Pass the 20-byte HASH160 of
 * the redeem script (RIPEMD160(SHA256(redeemScript))) — compute it
 * externally via the caller's crypto stack.
 */
export declare function encodeP2SHScriptPubKey(redeemScriptHash160: Uint8Array): Uint8Array;
