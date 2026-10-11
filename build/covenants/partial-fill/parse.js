/**
 * Parser for the Partial-Fill Sell Order covenant (three-branch, ECDSA cancel).
 *
 * Extracts `(sellerPubKeyHash, paymentScriptPubKey, unitPriceSats, tokenId)`
 * from a scriptPubKey that was produced by `buildPartialFillScript`. Walks
 * the exact byte layout emitted by the builder and fails on any deviation —
 * this is deliberate, so a downstream indexer can unambiguously classify a
 * UTXO as "partial-fill order" or "unknown script" with no false positives.
 * Covenants built before the input-0 binding (neurai-scripts < 0.10.0) are
 * rejected: their fill branches can be drained through a foreign input 0.
 */
import { bytesToHex, hexToBytes } from '../../core/bytes.js';
import { OP_CHECKSIG, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_HASH160, OP_IF } from '../../core/opcodes.js';
import { assertTrailing, expectByte, makeCursor, readPush } from '../../core/script-parser.js';
import { readFillBranches } from './fill-branches.js';
/**
 * Parse a covenant scriptPubKey and extract its parameters. Throws with a
 * descriptive message if the bytes don't match the partial-fill template.
 */
export function parsePartialFillScript(script, network = 'xna-test') {
    const bytes = typeof script === 'string' ? hexToBytes(script) : script;
    const c = makeCursor(bytes);
    // ═════ Outer IF — Cancel branch ═════
    expectByte(c, OP_IF, 'OP_IF (outer cancel)');
    expectByte(c, OP_DUP, 'OP_DUP (cancel)');
    expectByte(c, OP_HASH160, 'OP_HASH160');
    const sellerPubKeyHash = readPush(c, 'sellerPubKeyHash');
    if (sellerPubKeyHash.length !== 20) {
        throw new Error(`parse: sellerPubKeyHash is ${sellerPubKeyHash.length} bytes, expected 20`);
    }
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (cancel)');
    expectByte(c, OP_CHECKSIG, 'OP_CHECKSIG (cancel)');
    expectByte(c, OP_ELSE, 'OP_ELSE (outer → fill)');
    // ═════ Outer ELSE — input-0 binding + fill branches ═════
    const fill = readFillBranches(c);
    expectByte(c, OP_ENDIF, 'OP_ENDIF (outer)');
    assertTrailing(c);
    return {
        network,
        sellerPubKeyHash,
        paymentScriptPubKey: fill.paymentScriptPubKey,
        unitPriceSats: fill.unitPriceSats,
        tokenId: fill.tokenId,
        expiration: fill.expiration,
        scriptHex: bytesToHex(bytes)
    };
}
