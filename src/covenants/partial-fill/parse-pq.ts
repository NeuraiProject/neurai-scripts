/**
 * Parser for the PQ Partial-Fill Sell Order covenant (three-branch).
 * Returns the same economic parameters as the legacy parser, plus the
 * payment scriptPubKey bytes (which may be P2PKH or AuthScript) and the
 * configured TXHASH selector.
 *
 * The full-fill and partial-fill branches share `(paymentScriptPubKey,
 * unitPriceSats, tokenId)`. The parser reads both branches and verifies
 * consistency; inconsistency throws.
 */

import { bytesEqual, bytesToHex, hexToBytes } from '../../core/bytes.js';
import {
  OP_0,
  OP_1,
  OP_2,
  OP_CHECKSIGFROMSTACK,
  OP_DROP,
  OP_DUP,
  OP_ELSE,
  OP_ENDIF,
  OP_EQUALVERIFY,
  OP_GREATERTHANOREQUAL,
  OP_IF,
  OP_INPUTASSETFIELD,
  OP_MUL,
  OP_OUTPUTASSETFIELD,
  OP_OUTPUTAUTHCOMMITMENT,
  OP_OUTPUTSCRIPT,
  OP_OUTPUTVALUE,
  OP_OVER,
  OP_SHA256,
  OP_SUB,
  OP_SWAP,
  OP_TXFIELD,
  OP_TXHASH,
  OP_VERIFY,
  TXFIELD_AUTHSCRIPT_COMMITMENT
} from '../../core/opcodes.js';
import {
  assertTrailing,
  expectByte,
  makeCursor,
  readPush,
  readPushPositiveInt,
  readPushUint8
} from '../../core/script-parser.js';
import type { Network, ParsedPartialFillOrderPQ } from '../../types.js';

/** Quick discriminator without throwing — useful for indexers. */
export function isPartialFillScriptPQ(script: Uint8Array | string): boolean {
  const bytes = typeof script === 'string' ? hexToBytes(script) : script;
  // PQ cancel starts with: OP_IF OP_DUP OP_SHA256
  return (
    bytes.length > 3 &&
    bytes[0] === OP_IF &&
    bytes[1] === OP_DUP &&
    bytes[2] === OP_SHA256
  );
}

/**
 * Parse a PQ partial-fill covenant. Throws if the bytes do not match the
 * exact layout produced by `buildPartialFillScriptPQ`.
 */
export function parsePartialFillScriptPQ(
  script: Uint8Array | string,
  network: Network = 'xna-test'
): ParsedPartialFillOrderPQ {
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
  const txHashSelector = readPushUint8(c, 'txHashSelector');
  if (txHashSelector < 1) {
    throw new Error(`parse-pq: txHashSelector 0x00 is rejected by OP_TXHASH`);
  }
  expectByte(c, OP_TXHASH, 'OP_TXHASH');
  expectByte(c, OP_SWAP, 'OP_SWAP');
  expectByte(c, OP_CHECKSIGFROMSTACK, 'OP_CHECKSIGFROMSTACK');
  expectByte(c, OP_ELSE, 'OP_ELSE (outer → fill)');

  // ═════ Inner IF — Full-fill branch ═════
  expectByte(c, OP_IF, 'OP_IF (inner full-fill)');

  expectByte(c, OP_0, 'OP_0 (input idx, full)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, full)');
  expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD (full)');

  expectByte(c, OP_DUP, 'OP_DUP (price, full)');
  const unitPriceSatsFull = readPushPositiveInt(c, 'unitPriceSats (full)');
  expectByte(c, OP_MUL, 'OP_MUL (full)');
  expectByte(c, OP_0, 'OP_0 (payment idx, full)');
  expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE (full)');
  expectByte(c, OP_SWAP, 'OP_SWAP (full)');
  expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GE (full)');
  expectByte(c, OP_VERIFY, 'OP_VERIFY (full)');

  expectByte(c, OP_0, 'OP_0 (payment spk idx, full)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment full)');
  const paymentScriptPubKeyFull = readPush(c, 'paymentScriptPubKey (full)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment full)');

  expectByte(c, OP_DUP, 'OP_DUP (buyer amount, full)');
  expectByte(c, OP_1, 'OP_1 (buyer idx, full)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, full)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount, full)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount, full)');

  expectByte(c, OP_1, 'OP_1 (buyer idx, full)');
  expectByte(c, OP_1, 'OP_1 (NAME sel, full)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name, full)');
  const tokenIdFull = readPush(c, 'tokenId (full)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name, full)');

  expectByte(c, OP_DROP, 'OP_DROP (full)');
  expectByte(c, OP_1, 'OP_1 (true, full)');

  expectByte(c, OP_ELSE, 'OP_ELSE (inner → partial fill)');

  // ═════ Inner ELSE — Partial-fill branch ═════
  expectByte(c, OP_DUP, 'OP_DUP (price, partial)');
  const unitPriceSatsPartial = readPushPositiveInt(c, 'unitPriceSats (partial)');
  expectByte(c, OP_MUL, 'OP_MUL (partial)');
  expectByte(c, OP_0, 'OP_0 (payment idx, partial)');
  expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE (partial)');
  expectByte(c, OP_SWAP, 'OP_SWAP (partial)');
  expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GE (partial)');
  expectByte(c, OP_VERIFY, 'OP_VERIFY (partial)');

  expectByte(c, OP_0, 'OP_0 (payment spk idx, partial)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment partial)');
  const paymentScriptPubKeyPartial = readPush(c, 'paymentScriptPubKey (partial)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment partial)');

  expectByte(c, OP_DUP, 'OP_DUP (buyer amount, partial)');
  expectByte(c, OP_1, 'OP_1 (buyer idx, partial)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, partial)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount, partial)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount, partial)');

  expectByte(c, OP_1, 'OP_1 (buyer idx, partial)');
  expectByte(c, OP_1, 'OP_1 (NAME sel, partial)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name, partial)');
  const tokenIdPartial1 = readPush(c, 'tokenId partial #1');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name, partial)');

  // Continuation commitment
  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_OUTPUTAUTHCOMMITMENT, 'OP_OUTPUTAUTHCOMMITMENT (remainder)');
  expectByte(c, OP_2, 'OP_2 (TXFIELD sel: AUTHSCRIPT_COMMITMENT)');
  if (TXFIELD_AUTHSCRIPT_COMMITMENT !== 0x02) throw new Error('unexpected TXFIELD selector constant');
  expectByte(c, OP_TXFIELD, 'OP_TXFIELD');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder auth)');

  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_1, 'OP_1 (NAME sel)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
  const tokenIdPartial2 = readPush(c, 'tokenId partial #2');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder name)');

  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder amount)');
  expectByte(c, OP_OVER, 'OP_OVER');
  expectByte(c, OP_0, 'OP_0 (input idx)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel)');
  expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD');
  expectByte(c, OP_SWAP, 'OP_SWAP');
  expectByte(c, OP_SUB, 'OP_SUB');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder amount)');

  expectByte(c, OP_DROP, 'OP_DROP (partial)');
  expectByte(c, OP_1, 'OP_1 (true, partial)');

  expectByte(c, OP_ENDIF, 'OP_ENDIF (inner)');
  expectByte(c, OP_ENDIF, 'OP_ENDIF (outer)');
  assertTrailing(c);

  // Cross-branch consistency.
  if (!bytesEqual(paymentScriptPubKeyFull, paymentScriptPubKeyPartial)) {
    throw new Error('parse-pq: paymentScriptPubKey differs between full-fill and partial-fill branches');
  }
  if (!bytesEqual(tokenIdFull, tokenIdPartial1)) {
    throw new Error('parse-pq: tokenId differs between full-fill and partial-fill branches');
  }
  if (!bytesEqual(tokenIdPartial1, tokenIdPartial2)) {
    throw new Error('parse-pq: tokenId differs between buyer and remainder partial checks');
  }
  if (unitPriceSatsFull !== unitPriceSatsPartial) {
    throw new Error('parse-pq: unitPriceSats differs between full-fill and partial-fill branches');
  }

  const tokenId = new TextDecoder('utf-8', { fatal: true }).decode(tokenIdFull);

  return {
    network,
    pubKeyCommitment,
    tokenId,
    unitPriceSats: unitPriceSatsFull,
    txHashSelector,
    paymentScriptPubKey: paymentScriptPubKeyFull,
    scriptHex: bytesToHex(bytes)
  };
}
