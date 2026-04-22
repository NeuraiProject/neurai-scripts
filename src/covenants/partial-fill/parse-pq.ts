/**
 * Parser for the PQ Partial-Fill Sell Order covenant. Returns the same
 * economic parameters as the legacy parser, plus the payment scriptPubKey
 * bytes (which may be P2PKH or AuthScript) and the configured TXHASH
 * selector.
 */

import { bytesEqual, bytesToHex, hexToBytes } from '../../core/bytes.js';
import {
  OP_0,
  OP_1,
  OP_2,
  OP_3,
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

  // ───── Cancel branch (PQ) ─────
  expectByte(c, OP_IF, 'OP_IF');
  expectByte(c, OP_DUP, 'OP_DUP (cancel)');
  expectByte(c, OP_SHA256, 'OP_SHA256');
  const pubKeyCommitment = readPush(c, 'pubKeyCommitment');
  if (pubKeyCommitment.length !== 32) {
    throw new Error(`parse-pq: pubKeyCommitment must be 32 bytes, got ${pubKeyCommitment.length}`);
  }
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (cancel)');
  // Selector is read as an unsigned byte — consensus OP_TXHASH treats the
  // on-stack element as uint8, and the builder emits a raw 1-byte push so
  // selectors 0x80..0xff round-trip correctly (plan v3 bug B).
  const txHashSelector = readPushUint8(c, 'txHashSelector');
  if (txHashSelector < 1) {
    throw new Error(`parse-pq: txHashSelector 0x00 is rejected by OP_TXHASH`);
  }
  expectByte(c, OP_TXHASH, 'OP_TXHASH');
  expectByte(c, OP_SWAP, 'OP_SWAP');
  expectByte(c, OP_CHECKSIGFROMSTACK, 'OP_CHECKSIGFROMSTACK');
  expectByte(c, OP_ELSE, 'OP_ELSE');

  // ───── Fill branch ─────
  expectByte(c, OP_DUP, 'OP_DUP (price)');
  const unitPriceSats = readPushPositiveInt(c, 'unitPriceSats');
  expectByte(c, OP_MUL, 'OP_MUL');
  expectByte(c, OP_0, 'OP_0 (payment idx)');
  expectByte(c, OP_OUTPUTVALUE, 'OP_OUTPUTVALUE');
  expectByte(c, OP_SWAP, 'OP_SWAP');
  expectByte(c, OP_GREATERTHANOREQUAL, 'OP_GE');
  expectByte(c, OP_VERIFY, 'OP_VERIFY');

  expectByte(c, OP_0, 'OP_0 (payment spk idx)');
  expectByte(c, OP_OUTPUTSCRIPT, 'OP_OUTPUTSCRIPT (payment)');
  const paymentScriptPubKey = readPush(c, 'paymentScriptPubKey');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (payment)');

  expectByte(c, OP_DUP, 'OP_DUP (buyer amount)');
  expectByte(c, OP_1, 'OP_1 (buyer idx)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT selector)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer amount)');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer amount)');

  expectByte(c, OP_1, 'OP_1 (buyer idx)');
  expectByte(c, OP_1, 'OP_1 (NAME selector)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (buyer name)');
  const tokenIdBytes1 = readPush(c, 'tokenId #1');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (buyer name)');

  // Remainder continuity: same AuthScript commitment (NIP-023)
  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_OUTPUTAUTHCOMMITMENT, 'OP_OUTPUTAUTHCOMMITMENT (remainder)');
  expectByte(c, OP_2, 'OP_2 (TXFIELD selector: AUTHSCRIPT_COMMITMENT)');
  if (TXFIELD_AUTHSCRIPT_COMMITMENT !== 0x02) throw new Error('unexpected TXFIELD selector constant');
  expectByte(c, OP_TXFIELD, 'OP_TXFIELD');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder auth)');

  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_1, 'OP_1 (NAME selector)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
  const tokenIdBytes2 = readPush(c, 'tokenId #2');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder name)');

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

  expectByte(c, OP_DROP, 'OP_DROP');
  expectByte(c, OP_1, 'OP_1 (true)');
  expectByte(c, OP_ENDIF, 'OP_ENDIF');
  assertTrailing(c);

  if (!bytesEqual(tokenIdBytes1, tokenIdBytes2)) {
    throw new Error('parse-pq: tokenId differs between buyer and remainder checks');
  }

  const tokenId = new TextDecoder('utf-8', { fatal: true }).decode(tokenIdBytes1);

  return {
    network,
    pubKeyCommitment,
    tokenId,
    unitPriceSats,
    txHashSelector,
    paymentScriptPubKey,
    scriptHex: bytesToHex(bytes)
  };
}
