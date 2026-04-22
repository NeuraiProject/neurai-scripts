/**
 * Partial-Fill Sell Order covenant script (three-branch).
 *
 * The covenant has three branches selected by the top of the unlock stack:
 *
 *   OP_IF                  ← Cancel: seller signs, recovers remainder.
 *   OP_ELSE OP_IF          ← Full fill: buyer drains the covenant entirely.
 *                            No continuation output is required.
 *   OP_ELSE OP_ELSE        ← Partial fill: buyer takes N < total. A
 *                            continuation UTXO at vout[2] preserves the
 *                            covenant with amount = total - N.
 *
 * Output layout:
 *
 *   output[0] = XNA payment to seller   (value >= N * unitPriceSats)
 *   output[1] = asset to buyer          (tokenId, amount == N)
 *   output[2] = covenant continuation   (only for partial fill;
 *                                        same AuthScript commitment,
 *                                        amount == inputAmount - N)
 *   output[3+] = optional buyer change  (not constrained by the covenant)
 *
 * Continuity — the remainder UTXO reuses the spent covenant's AuthScript v1
 * commitment via `OP_OUTPUTAUTHCOMMITMENT(2) == OP_TXFIELD(0x02)` (NIP-023).
 * Comparing commitments rather than full scriptPubKeys is mandatory because
 * the remainder's asset wrapper carries a different `amountRaw` than the
 * spent UTXO's wrapper.
 *
 * Unlock stack shapes (scriptSig pushes, top → bottom):
 *
 *   Cancel:        <sig> <pubkey> <1>
 *   Full fill:            <1>       <0>       (full-flag=1, cancel-flag=0)
 *   Partial fill:  <N>    <0>       <0>       (N, full-flag=0, cancel-flag=0)
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`) and
 * commits to a 20-byte PKH — this variant only accepts legacy P2PKH
 * addresses as the seller destination. For AuthScript bech32m destinations
 * and post-quantum signing, use `buildPartialFillScriptPQ`.
 */
import { decodeAddress } from '@neuraiproject/neurai-create-transaction';
import { bytesToHex } from '../../core/bytes.js';
import { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';
import { ASSETFIELD_AMOUNT, ASSETFIELD_NAME, OP_CHECKSIG, OP_DROP, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_GREATERTHANOREQUAL, OP_HASH160, OP_IF, OP_INPUTASSETFIELD, OP_MUL, OP_OUTPUTASSETFIELD, OP_OUTPUTAUTHCOMMITMENT, OP_OUTPUTSCRIPT, OP_OUTPUTVALUE, OP_OVER, OP_SUB, OP_SWAP, OP_TXFIELD, OP_VERIFY, TXFIELD_AUTHSCRIPT_COMMITMENT } from '../../core/opcodes.js';
import { ScriptBuilder } from '../../core/script-builder.js';
export { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';
const ASSET_NAME_MAX = 32;
function decodeSellerAddress(sellerAddress) {
    if (typeof sellerAddress !== 'string' || sellerAddress.length === 0) {
        throw new Error('sellerAddress is required');
    }
    const decoded = decodeAddress(sellerAddress);
    if (decoded.type !== 'p2pkh') {
        throw new Error(`sellerAddress must be a legacy P2PKH address (the legacy partial-fill covenant uses OP_HASH160 + OP_CHECKSIG); ` +
            `got ${decoded.type}. Use buildPartialFillScriptPQ for AuthScript destinations.`);
    }
    const pkh = Uint8Array.from(decoded.hash);
    if (pkh.length !== 20) {
        throw new Error(`decoded sellerAddress produced a ${pkh.length}-byte hash, expected 20`);
    }
    return pkh;
}
function assertTokenId(tokenId) {
    if (typeof tokenId !== 'string' || tokenId.length === 0) {
        throw new Error('tokenId is required');
    }
    if (!/^[A-Z0-9._]+$/.test(tokenId)) {
        throw new Error(`tokenId "${tokenId}" is not a valid Neurai asset name`);
    }
    if (tokenId.length > ASSET_NAME_MAX) {
        throw new Error(`tokenId exceeds ${ASSET_NAME_MAX} bytes`);
    }
}
function assertPrice(priceSats) {
    if (typeof priceSats !== 'bigint') {
        throw new Error('unitPriceSats must be a bigint (satoshis per indivisible unit)');
    }
    if (priceSats <= 0n) {
        throw new Error('unitPriceSats must be > 0');
    }
    if (priceSats > 0x7fffffffffffffffn) {
        throw new Error('unitPriceSats exceeds int64 range');
    }
}
/**
 * Build the `scriptPubKey` of a Partial-Fill Sell Order covenant UTXO.
 * Returns raw bytes; wrap with `bytesToHex` for wire format.
 */
export function buildPartialFillScript(params) {
    const { sellerAddress, tokenId, unitPriceSats } = params;
    const sellerPubKeyHash = decodeSellerAddress(sellerAddress);
    assertTokenId(tokenId);
    assertPrice(unitPriceSats);
    const sellerScriptPubKey = encodeP2PKHScriptPubKey(sellerPubKeyHash);
    const tokenIdBytes = new TextEncoder().encode(tokenId);
    const b = new ScriptBuilder();
    // ════════ Cancel branch (outer IF) ════════
    // scriptSig: <sig> <pubkey> <1>
    b.op(OP_IF)
        .op(OP_DUP, OP_HASH160)
        .pushBytes(sellerPubKeyHash)
        .op(OP_EQUALVERIFY, OP_CHECKSIG)
        .op(OP_ELSE);
    // ════════ Fill branches (outer ELSE: inner IF/ELSE) ════════
    b.op(OP_IF);
    // ──────── Full-fill branch (inner IF) ────────
    // scriptSig: <1> <0>    ( full-flag=1, cancel-flag=0 )
    // Stack entering: [ ]
    //
    // N is derived from the spent UTXO's asset amount, so the buyer does not
    // push N. The entire covenant is drained to vout[1]; no vout[2] is
    // constrained and none is required (consensus forbids zero-amount asset
    // transfers, so the partial-fill continuity check is simply skipped).
    // 1. N = inputAmount
    b.pushInt(0)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_INPUTASSETFIELD); // [ N ]
    // 2. output[0].value >= N * unitPriceSats
    b.op(OP_DUP) // [ N, N ]
        .pushInt(unitPriceSats) // [ N, N, price ]
        .op(OP_MUL) // [ N, N*price ]
        .pushInt(0) // [ N, N*price, 0 ]
        .op(OP_OUTPUTVALUE) // [ N, N*price, value ]
        .op(OP_SWAP) // [ N, value, N*price ]
        .op(OP_GREATERTHANOREQUAL)
        .op(OP_VERIFY); // [ N ]
    // 3. output[0].scriptPubKey == sellerScriptPubKey
    b.pushInt(0)
        .op(OP_OUTPUTSCRIPT) // [ N, spk_out0 ]
        .pushBytes(sellerScriptPubKey)
        .op(OP_EQUALVERIFY); // [ N ]
    // 4. output[1].asset.amount == N
    b.op(OP_DUP) // [ N, N ]
        .pushInt(1)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD) // [ N, N, amount_out1 ]
        .op(OP_EQUALVERIFY); // [ N ]
    // 5. output[1].asset.name == tokenId
    b.pushInt(1)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD) // [ N, name_out1 ]
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY); // [ N ]
    // 6. Drop N, leave TRUE on the stack.
    b.op(OP_DROP).pushInt(1);
    // ──────── Partial-fill branch (inner ELSE) ────────
    // scriptSig: <N> <0> <0>   ( N, full-flag=0, cancel-flag=0 )
    // Stack entering: [ N ]
    b.op(OP_ELSE);
    // 1. Payment value (output 0) >= N * unitPriceSats
    b.op(OP_DUP) // [ N, N ]
        .pushInt(unitPriceSats) // [ N, N, price ]
        .op(OP_MUL) // [ N, N*price ]
        .pushInt(0) // [ N, N*price, 0 ]
        .op(OP_OUTPUTVALUE) // [ N, N*price, value ]
        .op(OP_SWAP) // [ N, value, N*price ]
        .op(OP_GREATERTHANOREQUAL)
        .op(OP_VERIFY); // [ N ]
    // 2. Payment scriptPubKey (output 0)
    b.pushInt(0)
        .op(OP_OUTPUTSCRIPT) // [ N, spk_out0 ]
        .pushBytes(sellerScriptPubKey)
        .op(OP_EQUALVERIFY); // [ N ]
    // 3. Asset to buyer (output 1) amount == N
    b.op(OP_DUP) // [ N, N ]
        .pushInt(1)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD)
        .op(OP_EQUALVERIFY); // [ N ]
    // 4. Asset to buyer (output 1) name == tokenId
    b.pushInt(1)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD)
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY); // [ N ]
    // 5. Continuation (output 2): same AuthScript commitment as spent UTXO
    //    (NIP-023 — see file-level comment).
    b.pushInt(2)
        .op(OP_OUTPUTAUTHCOMMITMENT)
        .pushInt(TXFIELD_AUTHSCRIPT_COMMITMENT)
        .op(OP_TXFIELD)
        .op(OP_EQUALVERIFY); // [ N ]
    // 6. Continuation name == tokenId
    b.pushInt(2)
        .pushInt(ASSETFIELD_NAME)
        .op(OP_OUTPUTASSETFIELD)
        .pushBytes(tokenIdBytes)
        .op(OP_EQUALVERIFY); // [ N ]
    // 7. Continuation amount == inputAmount - N
    b.pushInt(2)
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_OUTPUTASSETFIELD) // [ N, rem_amount ]
        .op(OP_OVER) // [ N, rem_amount, N ]
        .pushInt(0) // [ N, rem_amount, N, 0 ]
        .pushInt(ASSETFIELD_AMOUNT)
        .op(OP_INPUTASSETFIELD) // [ N, rem_amount, N, in_amount ]
        .op(OP_SWAP) // [ N, rem_amount, in_amount, N ]
        .op(OP_SUB) // [ N, rem_amount, in_amount - N ]
        .op(OP_EQUALVERIFY); // [ N ]
    // 8. Drop N, leave TRUE on the stack.
    b.op(OP_DROP).pushInt(1);
    b.op(OP_ENDIF); // closes full/partial inner IF
    b.op(OP_ENDIF); // closes outer cancel/fill IF
    return b.build();
}
/** Hex convenience wrapper for `buildPartialFillScript`. */
export function buildPartialFillScriptHex(params) {
    return bytesToHex(buildPartialFillScript(params));
}
// Re-export atomic helpers so parse.ts and callers can reuse them.
export { pushBytes, pushInt } from '../../core/script-builder.js';
