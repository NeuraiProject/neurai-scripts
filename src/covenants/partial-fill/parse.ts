/**
 * Parser for the Partial-Fill Sell Order covenant (three-branch).
 *
 * Extracts `(sellerPubKeyHash, unitPriceSats, tokenId)` from a scriptPubKey
 * that was produced by `buildPartialFillScript`. Walks the exact byte
 * layout emitted by the builder and fails on any deviation — this is
 * deliberate, so a downstream indexer can unambiguously classify a UTXO as
 * "partial-fill order" or "unknown script" with no false positives.
 *
 * The full-fill and partial-fill branches share `(sellerScriptPubKey,
 * unitPriceSats, tokenId)`. The parser reads both branches and verifies
 * consistency; inconsistency throws.
 */

import { bytesEqual, bytesToHex, hexToBytes } from '../../core/bytes.js';
import {
  ASSETFIELD_AMOUNT,
  ASSETFIELD_NAME,
  OP_0,
  OP_1,
  OP_2,
  OP_CHECKSIG,
  OP_DROP,
  OP_DUP,
  OP_ELSE,
  OP_ENDIF,
  OP_EQUALVERIFY,
  OP_GREATERTHANOREQUAL,
  OP_HASH160,
  OP_IF,
  OP_INPUTASSETFIELD,
  OP_MUL,
  OP_OUTPUTASSETFIELD,
  OP_OUTPUTAUTHCOMMITMENT,
  OP_OUTPUTSCRIPT,
  OP_OUTPUTVALUE,
  OP_OVER,
  OP_SUB,
  OP_SWAP,
  OP_TXFIELD,
  OP_VERIFY,
  TXFIELD_AUTHSCRIPT_COMMITMENT
} from '../../core/opcodes.js';
import {
  assertTrailing,
  expectByte,
  makeCursor,
  readPush,
  readPushPositiveInt
} from '../../core/script-parser.js';
import type { Network, ParsedPartialFillOrder } from '../../types.js';

/**
 * Parse a covenant scriptPubKey and extract its parameters. Throws with a
 * descriptive message if the bytes don't match the partial-fill template.
 */
export function parsePartialFillScript(
  script: Uint8Array | string,
  network: Network = 'xna-test'
): ParsedPartialFillOrder {
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

  // ═════ Inner IF — Full-fill branch ═════
  expectByte(c, OP_IF, 'OP_IF (inner full-fill)');

  // N = inputAmount
  expectByte(c, OP_0, 'OP_0 (input idx, full)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, full)');
  if (ASSETFIELD_AMOUNT !== 0x02) throw new Error('unexpected AMOUNT selector constant');
  expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD (full)');

  // payment value check
  expectByte(c, OP_DUP, 'OP_DUP (price, full)');
  const unitPriceSatsFull = readPushPositiveInt(c, 'unitPriceSats (full)');
  expectByte(c, OP_MUL, 'OP_MUL (full)');
  expectByte(c, OP_0, 'OP_0 (payment idx, full)');
  expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE (full)');
  expectByte(c, OP_SWAP, 'OP_SWAP (full)');
  expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GREATERTHANOREQUAL (full)');
  expectByte(c, OP_VERIFY, 'OP_VERIFY (payment full)');

  // payment spk
  expectByte(c, OP_0, 'OP_0 (spk idx, full)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment full)');
  const sellerSpkFull = readPush(c, 'sellerScriptPubKey (full)');
  const expectedSpk = new Uint8Array([
    OP_DUP, OP_HASH160, 0x14, ...sellerPubKeyHash, OP_EQUALVERIFY, OP_CHECKSIG
  ]);
  if (!bytesEqual(sellerSpkFull, expectedSpk)) {
    throw new Error('parse: full-fill seller scriptPubKey does not match the cancel PKH');
  }
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment spk full)');

  // buyer amount == N (full)
  expectByte(c, OP_DUP, 'OP_DUP (buyer amount, full)');
  expectByte(c, OP_1, 'OP_1 (buyer idx, full)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, full)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount, full)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount, full)');

  // buyer name == tokenId (full)
  expectByte(c, OP_1, 'OP_1 (buyer idx, full)');
  expectByte(c, OP_1, 'OP_1 (NAME sel, full)');
  if (ASSETFIELD_NAME !== 0x01) throw new Error('unexpected NAME selector constant');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name, full)');
  const tokenIdFull = readPush(c, 'tokenId (full)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name, full)');

  // tail (full)
  expectByte(c, OP_DROP, 'OP_DROP (full)');
  expectByte(c, OP_1, 'OP_1 (true, full)');

  expectByte(c, OP_ELSE, 'OP_ELSE (inner → partial fill)');

  // ═════ Inner ELSE — Partial-fill branch ═════
  // Payment value
  expectByte(c, OP_DUP, 'OP_DUP (price, partial)');
  const unitPriceSatsPartial = readPushPositiveInt(c, 'unitPriceSats (partial)');
  expectByte(c, OP_MUL, 'OP_MUL (partial)');
  expectByte(c, OP_0, 'OP_0 (pay idx, partial)');
  expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE (partial)');
  expectByte(c, OP_SWAP, 'OP_SWAP (partial)');
  expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GREATERTHANOREQUAL (partial)');
  expectByte(c, OP_VERIFY, 'OP_VERIFY (payment partial)');

  // Payment spk
  expectByte(c, OP_0, 'OP_0 (spk idx, partial)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment partial)');
  const sellerSpkPartial = readPush(c, 'sellerScriptPubKey (partial)');
  if (!bytesEqual(sellerSpkPartial, expectedSpk)) {
    throw new Error('parse: partial-fill seller scriptPubKey does not match the cancel PKH');
  }
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment spk partial)');

  // Buyer amount
  expectByte(c, OP_DUP, 'OP_DUP (buyer amount, partial)');
  expectByte(c, OP_1, 'OP_1 (buyer idx, partial)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, partial)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount, partial)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount, partial)');

  // Buyer name
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

  // Continuation name
  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_1, 'OP_1 (NAME sel)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
  const tokenIdPartial2 = readPush(c, 'tokenId partial #2');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder name)');

  // Continuation amount
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

  // Tail (partial)
  expectByte(c, OP_DROP, 'OP_DROP (partial)');
  expectByte(c, OP_1, 'OP_1 (true, partial)');

  // Close the nested structure
  expectByte(c, OP_ENDIF, 'OP_ENDIF (inner)');
  expectByte(c, OP_ENDIF, 'OP_ENDIF (outer)');
  assertTrailing(c);

  // Cross-branch consistency: all three (full token, partial name #1,
  // partial name #2) must agree, and the two unit prices must match.
  if (!bytesEqual(tokenIdFull, tokenIdPartial1)) {
    throw new Error('parse: tokenId differs between full-fill and partial-fill branches');
  }
  if (!bytesEqual(tokenIdPartial1, tokenIdPartial2)) {
    throw new Error('parse: tokenId bytes differ between buyer and remainder partial checks');
  }
  if (unitPriceSatsFull !== unitPriceSatsPartial) {
    throw new Error('parse: unitPriceSats differs between full-fill and partial-fill branches');
  }
  const tokenId = new TextDecoder('utf-8', { fatal: true }).decode(tokenIdFull);

  return {
    network,
    sellerPubKeyHash,
    unitPriceSats: unitPriceSatsFull,
    tokenId,
    scriptHex: bytesToHex(bytes)
  };
}
