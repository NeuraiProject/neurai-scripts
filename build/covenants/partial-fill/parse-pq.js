/**
 * Parser for the PQ Partial-Fill Sell Order covenant (three-branch).
 * Returns the same economic parameters as the legacy parser, plus the
 * payment scriptPubKey bytes (which may be P2PKH or AuthScript) and the
 * configured TXHASH selector.
 *
 * The fill branches (and their input-0 binding) are read by the shared
 * `readFillBranches`; covenants built before the binding are rejected.
 */
import { bytesToHex, hexToBytes } from '../../core/bytes.js';
import { OP_CHECKSIGFROMSTACK, OP_DUP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256, OP_SWAP, OP_TXHASH } from '../../core/opcodes.js';
import { assertTrailing, expectByte, makeCursor, readPush } from '../../core/script-parser.js';
import { readFillBranches } from './fill-branches.js';
/** Quick discriminator without throwing — useful for indexers. */
export function isPartialFillScriptPQ(script) {
    const bytes = typeof script === 'string' ? hexToBytes(script) : script;
    // PQ cancel starts with: OP_IF OP_DUP OP_SHA256
    return (bytes.length > 3 &&
        bytes[0] === OP_IF &&
        bytes[1] === OP_DUP &&
        bytes[2] === OP_SHA256);
}
/**
 * Parse a PQ partial-fill covenant. Throws if the bytes do not match the
 * exact layout produced by `buildPartialFillScriptPQ`.
 */
export function parsePartialFillScriptPQ(script, network = 'xna-test') {
    const bytes = typeof script === 'string' ? hexToBytes(script) : script;
    const c = makeCursor(bytes);
    // ═════ Outer IF — Cancel branch (PQ) ═════
    expectByte(c, OP_IF, 'OP_IF (outer cancel)');
    expectByte(c, OP_DUP, 'OP_DUP (cancel)');
    expectByte(c, OP_SHA256, 'OP_SHA256');
    const pubKeyCommitment = readPush(c, 'pubKeyCommitment');
    if (pubKeyCommitment.length !== 32) {
        throw new Error(`parse-pq: pubKeyCommitment must be 32 bytes, got ${pubKeyCommitment.length}`);
    }
    expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (cancel)');
    const selectorBytes = readPush(c, 'txHashSelector');
    if (selectorBytes.length !== 2) {
        throw new Error(`parse-pq: txHashSelector must be a two-byte LE push, got ${selectorBytes.length} bytes`);
    }
    const txHashSelector = selectorBytes[0] | (selectorBytes[1] << 8);
    if (txHashSelector === 0 || txHashSelector > 0x1ff) {
        throw new Error(`parse-pq: txHashSelector 0x${txHashSelector.toString(16)} is rejected by OP_TXHASH`);
    }
    expectByte(c, OP_TXHASH, 'OP_TXHASH');
    expectByte(c, OP_SWAP, 'OP_SWAP');
    expectByte(c, OP_CHECKSIGFROMSTACK, 'OP_CHECKSIGFROMSTACK');
    expectByte(c, OP_ELSE, 'OP_ELSE (outer → fill)');
    // ═════ Outer ELSE — input-0 binding + fill branches ═════
    const fill = readFillBranches(c);
    expectByte(c, OP_ENDIF, 'OP_ENDIF (outer)');
    assertTrailing(c);
    return {
        network,
        pubKeyCommitment,
        tokenId: fill.tokenId,
        unitPriceSats: fill.unitPriceSats,
        txHashSelector,
        expiration: fill.expiration,
        paymentScriptPubKey: fill.paymentScriptPubKey,
        scriptHex: bytesToHex(bytes)
    };
}
