/**
 * Parser for the Partial-Fill Sell Order covenant.
 *
 * Extracts `(sellerPubKeyHash, unitPriceSats, tokenId)` from a scriptPubKey
 * that was produced by `buildPartialFillScript`. The parser walks the exact
 * byte layout emitted by the builder and fails on any deviation — this is
 * deliberate, so a downstream indexer can unambiguously classify a UTXO as
 * "partial-fill order" or "unknown script" with no false positives.
 */

import { bytesEqual, bytesToHex, hexToBytes } from '../../core/bytes.js';
import {
  ASSETFIELD_AMOUNT,
  ASSETFIELD_NAME,
  OP_0,
  OP_1,
  OP_2,
  OP_3,
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
  OP_OUTPUTSCRIPT,
  OP_OUTPUTVALUE,
  OP_OVER,
  OP_SUB,
  OP_SWAP,
  OP_TXFIELD,
  OP_VERIFY,
  TXFIELD_SCRIPTPUBKEY
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

  // ───── Cancel branch prefix ─────
  expectByte(c, OP_IF, 'OP_IF');
  expectByte(c, OP_DUP, 'OP_DUP (cancel)');
  expectByte(c, OP_HASH160, 'OP_HASH160');
  const sellerPubKeyHash = readPush(c, 'sellerPubKeyHash');
  if (sellerPubKeyHash.length !== 20) {
    throw new Error(`parse: sellerPubKeyHash is ${sellerPubKeyHash.length} bytes, expected 20`);
  }
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (cancel)');
  expectByte(c, OP_CHECKSIG, 'OP_CHECKSIG (cancel)');
  expectByte(c, OP_ELSE, 'OP_ELSE');

  // ───── Payment value check ─────
  expectByte(c, OP_DUP, 'OP_DUP (price)');
  const unitPriceSats = readPushPositiveInt(c, 'unitPriceSats');
  expectByte(c, OP_MUL, 'OP_MUL');
  expectByte(c, OP_0, 'OP_0 (payment idx)');
  expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE');
  expectByte(c, OP_SWAP, 'OP_SWAP');
  expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GREATERTHANOREQUAL');
  expectByte(c, OP_VERIFY, 'OP_VERIFY (payment)');

  // ───── Payment scriptPubKey check ─────
  expectByte(c, OP_0, 'OP_0 (spk idx)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment)');
  const sellerSpk = readPush(c, 'sellerScriptPubKey');
  // Must be P2PKH with our PKH.
  const expectedSpk = new Uint8Array([
    OP_DUP, OP_HASH160, 0x14, ...sellerPubKeyHash, OP_EQUALVERIFY, OP_CHECKSIG
  ]);
  if (!bytesEqual(sellerSpk, expectedSpk)) {
    throw new Error('parse: embedded seller scriptPubKey does not match the cancel PKH');
  }
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment spk)');

  // ───── Buyer asset amount check (output 1) ─────
  expectByte(c, OP_DUP, 'OP_DUP (buyer amount)');
  expectByte(c, OP_1, 'OP_1 (buyer idx)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
  if (ASSETFIELD_AMOUNT !== 0x02) throw new Error('unexpected AMOUNT selector constant');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount)');

  // ───── Buyer asset name check (output 1) ─────
  expectByte(c, OP_1, 'OP_1 (buyer idx)');
  expectByte(c, OP_1, 'OP_1 (NAME selector)');
  if (ASSETFIELD_NAME !== 0x01) throw new Error('unexpected NAME selector constant');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name)');
  const tokenIdBytes1 = readPush(c, 'tokenId #1');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name)');

  // ───── Remainder continuity: same scriptPubKey ─────
  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (remainder)');
  expectByte(c, OP_3, 'OP_3 (TXFIELD selector)');
  if (TXFIELD_SCRIPTPUBKEY !== 0x03) throw new Error('unexpected TXFIELD selector constant');
  expectByte(c, OP_TXFIELD, 'OP_TXFIELD');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder spk)');

  // ───── Remainder tokenId check ─────
  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_1, 'OP_1 (NAME selector)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
  const tokenIdBytes2 = readPush(c, 'tokenId #2');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder name)');

  // ───── Remainder amount == input amount - N ─────
  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder amount)');
  expectByte(c, OP_OVER, 'OP_OVER');
  expectByte(c, OP_0, 'OP_0 (input idx)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
  expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD');
  expectByte(c, OP_SWAP, 'OP_SWAP');
  expectByte(c, OP_SUB, 'OP_SUB');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder amount)');

  // ───── Tail ─────
  expectByte(c, OP_DROP, 'OP_DROP');
  expectByte(c, OP_1, 'OP_1 (true)');
  expectByte(c, OP_ENDIF, 'OP_ENDIF');
  assertTrailing(c);

  if (!bytesEqual(tokenIdBytes1, tokenIdBytes2)) {
    throw new Error('parse: tokenId bytes differ between buyer and remainder checks');
  }
  const tokenId = new TextDecoder('utf-8', { fatal: true }).decode(tokenIdBytes1);

  return {
    network,
    sellerPubKeyHash,
    unitPriceSats,
    tokenId,
    scriptHex: bytesToHex(bytes)
  };
}
