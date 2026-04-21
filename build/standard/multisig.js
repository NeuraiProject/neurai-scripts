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
import { bytesToHex, concatBytes } from '../core/bytes.js';
import { pushBytes, pushInt } from '../core/script-builder.js';
import { OP_CHECKMULTISIG, OP_EQUAL, OP_HASH160 } from '../core/opcodes.js';
export const MULTISIG_MAX_PUBKEYS = 20;
function assertPubKey(pk, idx) {
    if (!(pk instanceof Uint8Array) || (pk.length !== 33 && pk.length !== 65)) {
        throw new Error(`pubKey[${idx}] must be 33 or 65 bytes (got ${pk?.length})`);
    }
}
export function encodeMultisigRedeemScript({ m, pubKeys }) {
    if (!Array.isArray(pubKeys) || pubKeys.length === 0) {
        throw new Error('pubKeys must be a non-empty array');
    }
    if (pubKeys.length > MULTISIG_MAX_PUBKEYS) {
        throw new Error(`pubKeys length ${pubKeys.length} exceeds OP_CHECKMULTISIG cap (${MULTISIG_MAX_PUBKEYS})`);
    }
    if (!Number.isInteger(m) || m < 1 || m > pubKeys.length) {
        throw new Error(`m must be an integer in [1, ${pubKeys.length}] (got ${m})`);
    }
    for (let i = 0; i < pubKeys.length; i += 1)
        assertPubKey(pubKeys[i], i);
    const parts = [pushInt(m)];
    for (const pk of pubKeys)
        parts.push(pushBytes(pk));
    parts.push(pushInt(pubKeys.length));
    parts.push(Uint8Array.of(OP_CHECKMULTISIG));
    return concatBytes(...parts);
}
export function encodeMultisigRedeemScriptHex(params) {
    return bytesToHex(encodeMultisigRedeemScript(params));
}
/**
 * P2SH scriptPubKey wrapping any redeem script. Pass the 20-byte HASH160 of
 * the redeem script (RIPEMD160(SHA256(redeemScript))) — compute it
 * externally via the caller's crypto stack.
 */
export function encodeP2SHScriptPubKey(redeemScriptHash160) {
    if (!(redeemScriptHash160 instanceof Uint8Array) || redeemScriptHash160.length !== 20) {
        throw new Error('redeemScriptHash160 must be a 20-byte Uint8Array');
    }
    return concatBytes(Uint8Array.of(OP_HASH160, 0x14), redeemScriptHash160, Uint8Array.of(OP_EQUAL));
}
