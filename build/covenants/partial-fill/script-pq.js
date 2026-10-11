/**
 * PQ (post-quantum) variant of the Partial-Fill Sell Order covenant.
 *
 * Identical fill branches (full + partial) to the legacy covenant, but the
 * **cancel** branch accepts an ML-DSA-44 signature instead of an ECDSA one.
 * This requires:
 *   - `SCRIPT_VERIFY_CHECKSIGFROMSTACK` (for OP_CSFS) active
 *   - `SCRIPT_VERIFY_TXHASH` (for OP_TXHASH) active
 *   - NIP-18 (`MAX_PQ_SCRIPT_ELEMENT_SIZE = 3072`) active, so the ~2.4 KB
 *     signature and ~1.3 KB pubkey can be pushed to the script stack
 *
 * All three are active on DePIN-Test testnet.
 *
 * Cancel-branch flow (scriptSig pushes `<sig> <pubkey> OP_1`):
 *
 *   1. OP_DUP OP_SHA256 <commitment> OP_EQUALVERIFY   → pubkey matches
 *   2. <selector> OP_TXHASH                           → message = H(tx)
 *   3. OP_SWAP OP_CHECKSIGFROMSTACK                   → CSFS verifies sig
 *
 * The message that gets signed is **SHA256(OP_TXHASH(selector))** — CSFS
 * single-SHA256s its message argument before verification, and OP_TXHASH
 * produces its own 32-byte NIP-042 tagged hash, so the seller computes:
 *   `sign(pqSeckey, SHA256(TaggedHash("NeuraiTxHash", mask || selected_tx_fields)))`
 *
 * The fill branches, including the input-0 binding, are shared with the
 * ECDSA variant — see `./fill-branches.ts`.
 */
import { bytesToHex } from '../../core/bytes.js';
import { encodeSellerScriptPubKey } from '../../address.js';
import { OP_CHECKSIGFROMSTACK, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256, OP_SWAP, OP_TXHASH } from '../../core/opcodes.js';
import { ScriptBuilder } from '../../core/script-builder.js';
import { assertExpiration } from './expiration.js';
import { appendFillBranches } from './fill-branches.js';
const ASSET_NAME_MAX = 32;
export const DEFAULT_PQ_TXHASH_SELECTOR = 0x1ff;
function assertCommitment(commitment) {
    if (!(commitment instanceof Uint8Array) || commitment.length !== 32) {
        throw new Error('pubKeyCommitment must be a 32-byte Uint8Array (SHA256 of pubKey)');
    }
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
        throw new Error('unitPriceSats must be a bigint');
    }
    if (priceSats <= 0n) {
        throw new Error('unitPriceSats must be > 0');
    }
    if (priceSats > 0x7fffffffffffffffn) {
        throw new Error('unitPriceSats exceeds int64 range');
    }
}
function assertSelector(selector) {
    if (!Number.isInteger(selector) || selector < 0 || selector > 0x1ff) {
        throw new Error('txHashSelector must be in the NIP-042 range (0x001..0x1ff)');
    }
    if (selector === 0) {
        throw new Error('txHashSelector 0x000 is rejected by OP_TXHASH');
    }
}
/**
 * Build the scriptPubKey of a PQ Partial-Fill Sell Order covenant UTXO.
 */
export function buildPartialFillScriptPQ(params) {
    const { paymentAddress, pubKeyCommitment, tokenId, unitPriceSats, txHashSelector = DEFAULT_PQ_TXHASH_SELECTOR } = params;
    assertCommitment(pubKeyCommitment);
    assertTokenId(tokenId);
    assertPrice(unitPriceSats);
    assertSelector(txHashSelector);
    const expiration = assertExpiration(params.expiration);
    const payment = encodeSellerScriptPubKey(paymentAddress);
    const tokenIdBytes = new TextEncoder().encode(tokenId);
    const b = new ScriptBuilder();
    // ════════ Cancel branch (PQ via OP_CHECKSIGFROMSTACK) ════════
    // scriptSig: <sigPQ> <pubKeyPQ> <1>
    // After OP_IF consumes the flag: [ sig, pubKey ]
    //
    // NIP-042 consumes exactly two raw little-endian bytes. CScriptNum and
    // OP_N encodings are invalid even when they represent the same mask.
    b.op(OP_IF)
        .op(OP_DUP) // [ sig, pubKey, pubKey ]
        .op(OP_SHA256) // [ sig, pubKey, H(pubKey) ]
        .pushBytes(pubKeyCommitment) // [ sig, pubKey, H(pubKey), commitment ]
        .op(OP_EQUALVERIFY) // [ sig, pubKey ]
        .pushBytes(Uint8Array.of(txHashSelector & 0xff, txHashSelector >> 8)) // [ sig, pubKey, selector ]
        .op(OP_TXHASH) // [ sig, pubKey, txHash ]
        .op(OP_SWAP) // [ sig, txHash, pubKey ]
        .op(OP_CHECKSIGFROMSTACK) // [ 1 | 0 ]
        .op(OP_ELSE);
    // ════════ Fill branches (outer ELSE) ════════
    appendFillBranches(b, {
        paymentScriptPubKey: payment.bytes,
        tokenIdBytes,
        unitPriceSats,
        expiration
    });
    b.op(OP_ENDIF); // cancel / fill
    return b.build();
}
export function buildPartialFillScriptPQHex(params) {
    return bytesToHex(buildPartialFillScriptPQ(params));
}
