/**
 * Buyer fill branches shared by both Partial-Fill Sell Order variants
 * (ECDSA cancel in `./script.ts`, ML-DSA-44 cancel in `./script-pq.ts`).
 * The variants only differ in their cancel branch; everything after the
 * outer `OP_ELSE` is emitted and parsed here.
 *
 * Input-0 binding. The fill branches read the order's asset amount with
 * `<0> OP_INPUTASSETFIELD` and constrain outputs 0..2 by fixed index. Input
 * indices are absolute and Script cannot ask for the index of the input
 * being evaluated, so without a binding a buyer could:
 *   - put a foreign asset UTXO at input 0 and the order at input 1: the
 *     order then prices the fill by the foreign amount and the rest of the
 *     order leaves through an unconstrained output;
 *   - spend several identical orders together, every one of them satisfied
 *     by the same payment output.
 * The fill block therefore opens with
 *
 *   <0x80 0x00> OP_TXHASH <INPUT_ZERO_TXHASH> OP_EQUALVERIFY
 *
 * NIP-042 mask 0x0080 commits only to the index of the input being
 * evaluated, so the digest equals the constant exactly when this covenant
 * is spent as input 0. At most one order per transaction can take a fill
 * branch; the seller's cancel branch is not bound.
 *
 * Layout (after the variant's `OP_IF <cancel> OP_ELSE`):
 *
 *   <0x80 0x00> OP_TXHASH <INPUT_ZERO_TXHASH> OP_EQUALVERIFY
 *   OP_IF                                                  ← full fill, unlock <1> <0>
 *     [expiration gate]
 *     <0> <2> OP_INPUTASSETFIELD                           (N = order amount)
 *     DUP <price> MUL <0> OUTPUTVALUE SWAP GE VERIFY       (payment value)
 *     <0> OUTPUTSCRIPT <paymentSpk> EQUALVERIFY            (payment destination)
 *     DUP <1> <2> OUTPUTASSETFIELD EQUALVERIFY             (buyer amount == N)
 *     <1> <1> OUTPUTASSETFIELD <tokenId> EQUALVERIFY       (buyer asset name)
 *     DROP <1>
 *   OP_ELSE                                                ← partial fill, unlock <N> <0> <0>
 *     [expiration gate]
 *     payment value, payment destination, buyer amount, buyer name (as above)
 *     <2> OUTPUTAUTHCOMMITMENT <2> TXFIELD EQUALVERIFY     (continuation, NIP-023)
 *     <2> <1> OUTPUTASSETFIELD <tokenId> EQUALVERIFY       (continuation name)
 *     <2> <2> OUTPUTASSETFIELD OVER <0> <2> INPUTASSETFIELD SWAP SUB EQUALVERIFY
 *     DROP <1>
 *   OP_ENDIF
 */

import { bytesEqual, hexToBytes } from '../../core/bytes.js';
import {
  ASSETFIELD_AMOUNT,
  ASSETFIELD_NAME,
  OP_0,
  OP_1,
  OP_2,
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
  OP_SUB,
  OP_SWAP,
  OP_TXFIELD,
  OP_TXHASH,
  OP_VERIFY,
  TXFIELD_AUTHSCRIPT_COMMITMENT,
  TXHASH_CURRENT_INDEX
} from '../../core/opcodes.js';
import type { ScriptBuilder } from '../../core/script-builder.js';
import type { Cursor } from '../../core/script-parser.js';
import { expectByte, readPush, readPushPositiveInt } from '../../core/script-parser.js';
import type { PartialFillExpiration } from '../../types.js';
import {
  appendExpirationGate,
  assertSameExpiration,
  readOptionalExpirationGate
} from './expiration.js';

/** NIP-042 mask (two bytes, little-endian) selecting only the current input index. */
export const INPUT_INDEX_TXHASH_SELECTOR = Uint8Array.of(TXHASH_CURRENT_INDEX, 0x00);

/**
 * `OP_TXHASH(0x0080)` evaluated at input 0:
 * `SHA256(tag || tag || 80 00 || 00 00 00 00)` with `tag = SHA256("NeuraiTxHash")`.
 */
export const INPUT_ZERO_TXHASH = hexToBytes(
  '419632cabaf8bb70b96a8c92c4601a9c2ba11e96841daebc9d98f4835eeb0e36'
);

export interface FillBranchParams {
  /** scriptPubKey output 0 must pay (any destination type, no asset suffix). */
  paymentScriptPubKey: Uint8Array;
  tokenIdBytes: Uint8Array;
  unitPriceSats: bigint;
  expiration?: PartialFillExpiration;
}

export interface ParsedFillBranches {
  paymentScriptPubKey: Uint8Array;
  tokenId: string;
  unitPriceSats: bigint;
  expiration?: PartialFillExpiration;
}

function appendPaymentAndBuyerChecks(b: ScriptBuilder, p: FillBranchParams): void {
  // output[0].value >= N * unitPriceSats                      [ N ]
  b.op(OP_DUP)
    .pushInt(p.unitPriceSats)
    .op(OP_MUL)
    .pushInt(0)
    .op(OP_OUTPUTVALUE)
    .op(OP_SWAP)
    .op(OP_GREATERTHANOREQUAL)
    .op(OP_VERIFY);

  // output[0].scriptPubKey == paymentScriptPubKey             [ N ]
  b.pushInt(0)
    .op(OP_OUTPUTSCRIPT)
    .pushBytes(p.paymentScriptPubKey)
    .op(OP_EQUALVERIFY);

  // output[1].asset.amount == N                               [ N ]
  b.op(OP_DUP)
    .pushInt(1)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD)
    .op(OP_EQUALVERIFY);

  // output[1].asset.name == tokenId                           [ N ]
  b.pushInt(1)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD)
    .pushBytes(p.tokenIdBytes)
    .op(OP_EQUALVERIFY);
}

/** Emit the input-0 binding and both fill branches, ending with the inner `OP_ENDIF`. */
export function appendFillBranches(b: ScriptBuilder, p: FillBranchParams): void {
  b.pushBytes(INPUT_INDEX_TXHASH_SELECTOR)
    .op(OP_TXHASH)
    .pushBytes(INPUT_ZERO_TXHASH)
    .op(OP_EQUALVERIFY);

  // ──────── Full fill: N is the whole order, no continuation ────────
  b.op(OP_IF);
  appendExpirationGate(b, p.expiration);
  b.pushInt(0)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_INPUTASSETFIELD);   // [ N ]
  appendPaymentAndBuyerChecks(b, p);
  b.op(OP_DROP).pushInt(1);

  // ──────── Partial fill: buyer pushes N, remainder continues at output 2 ────────
  b.op(OP_ELSE);
  appendExpirationGate(b, p.expiration);
  appendPaymentAndBuyerChecks(b, p);

  // Continuation keeps the spent order's AuthScript commitment (NIP-023).
  b.pushInt(2)
    .op(OP_OUTPUTAUTHCOMMITMENT)
    .pushInt(TXFIELD_AUTHSCRIPT_COMMITMENT)
    .op(OP_TXFIELD)
    .op(OP_EQUALVERIFY);
  b.pushInt(2)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD)
    .pushBytes(p.tokenIdBytes)
    .op(OP_EQUALVERIFY);
  // output[2].asset.amount == orderAmount - N
  b.pushInt(2)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD)   // [ N, rem ]
    .op(OP_OVER)               // [ N, rem, N ]
    .pushInt(0)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_INPUTASSETFIELD)    // [ N, rem, N, in ]
    .op(OP_SWAP)               // [ N, rem, in, N ]
    .op(OP_SUB)                // [ N, rem, in - N ]
    .op(OP_EQUALVERIFY);
  b.op(OP_DROP).pushInt(1);

  b.op(OP_ENDIF);
}

function readPaymentAndBuyerChecks(
  c: Cursor,
  label: string
): { unitPriceSats: bigint; paymentScriptPubKey: Uint8Array; tokenId: Uint8Array } {
  expectByte(c, OP_DUP, `OP_DUP (price, ${label})`);
  const unitPriceSats = readPushPositiveInt(c, `unitPriceSats (${label})`);
  expectByte(c, OP_MUL, `OP_MUL (${label})`);
  expectByte(c, OP_0, `OP_0 (payment idx, ${label})`);
  expectByte(c, OP_OUTPUTVALUE, `OP_OUTPUTVALUE (${label})`);
  expectByte(c, OP_SWAP, `OP_SWAP (${label})`);
  expectByte(c, OP_GREATERTHANOREQUAL, `OP_GREATERTHANOREQUAL (${label})`);
  expectByte(c, OP_VERIFY, `OP_VERIFY (payment, ${label})`);

  expectByte(c, OP_0, `OP_0 (spk idx, ${label})`);
  expectByte(c, OP_OUTPUTSCRIPT, `OP_OUTPUTSCRIPT (${label})`);
  const paymentScriptPubKey = readPush(c, `paymentScriptPubKey (${label})`);
  expectByte(c, OP_EQUALVERIFY, `OP_EQUALVERIFY (payment spk, ${label})`);

  expectByte(c, OP_DUP, `OP_DUP (buyer amount, ${label})`);
  expectByte(c, OP_1, `OP_1 (buyer idx, ${label})`);
  expectByte(c, OP_2, `OP_2 (AMOUNT sel, ${label})`);
  expectByte(c, OP_OUTPUTASSETFIELD, `OP_OUTPUTASSETFIELD (buyer amount, ${label})`);
  expectByte(c, OP_EQUALVERIFY, `OP_EQUALVERIFY (buyer amount, ${label})`);

  expectByte(c, OP_1, `OP_1 (buyer idx, ${label})`);
  expectByte(c, OP_1, `OP_1 (NAME sel, ${label})`);
  expectByte(c, OP_OUTPUTASSETFIELD, `OP_OUTPUTASSETFIELD (buyer name, ${label})`);
  const tokenId = readPush(c, `tokenId (${label})`);
  expectByte(c, OP_EQUALVERIFY, `OP_EQUALVERIFY (buyer name, ${label})`);

  return { unitPriceSats, paymentScriptPubKey, tokenId };
}

/**
 * Parse what `appendFillBranches` emits. Both branches must agree on price,
 * payment destination, tokenId and expiration; any deviation throws.
 */
export function readFillBranches(c: Cursor): ParsedFillBranches {
  const selector = readPush(c, 'input-0 binding selector');
  if (!bytesEqual(selector, INPUT_INDEX_TXHASH_SELECTOR)) {
    throw new Error(
      'parse: fill branches must open with the input-0 binding <0x8000> OP_TXHASH (covenants without it ' +
        'can be drained through a foreign input 0 and are not supported)'
    );
  }
  expectByte(c, OP_TXHASH, 'OP_TXHASH (input-0 binding)');
  const digest = readPush(c, 'input-0 binding digest');
  if (!bytesEqual(digest, INPUT_ZERO_TXHASH)) {
    throw new Error('parse: input-0 binding digest is not OP_TXHASH(0x0080) at input 0');
  }
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (input-0 binding)');

  // ═════ Full fill ═════
  expectByte(c, OP_IF, 'OP_IF (full fill)');
  const expirationFull = readOptionalExpirationGate(c, OP_0, 'full');
  expectByte(c, OP_0, 'OP_0 (input idx, full)');
  expectByte(c, OP_2, 'OP_2 (AMOUNT sel, full)');
  expectByte(c, OP_INPUTASSETFIELD, 'OP_INPUTASSETFIELD (full)');
  const full = readPaymentAndBuyerChecks(c, 'full');
  expectByte(c, OP_DROP, 'OP_DROP (full)');
  expectByte(c, OP_1, 'OP_1 (true, full)');

  // ═════ Partial fill ═════
  expectByte(c, OP_ELSE, 'OP_ELSE (partial fill)');
  const expirationPartial = readOptionalExpirationGate(c, OP_DUP, 'partial');
  const partial = readPaymentAndBuyerChecks(c, 'partial');

  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_OUTPUTAUTHCOMMITMENT, 'OP_OUTPUTAUTHCOMMITMENT (remainder)');
  expectByte(c, OP_2, 'OP_2 (TXFIELD sel: AUTHSCRIPT_COMMITMENT)');
  expectByte(c, OP_TXFIELD, 'OP_TXFIELD');
  expectByte(c, OP_EQUALVERIFY, 'OP_EQUALVERIFY (remainder auth)');

  expectByte(c, OP_2, 'OP_2 (remainder idx)');
  expectByte(c, OP_1, 'OP_1 (NAME sel)');
  expectByte(c, OP_OUTPUTASSETFIELD, 'OP_OUTPUTASSETFIELD (remainder name)');
  const remainderTokenId = readPush(c, 'tokenId (remainder)');
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
  expectByte(c, OP_ENDIF, 'OP_ENDIF (fill branches)');

  if (!bytesEqual(full.tokenId, partial.tokenId) || !bytesEqual(partial.tokenId, remainderTokenId)) {
    throw new Error('parse: tokenId differs between the fill checks');
  }
  if (full.unitPriceSats !== partial.unitPriceSats) {
    throw new Error('parse: unitPriceSats differs between full-fill and partial-fill branches');
  }
  if (!bytesEqual(full.paymentScriptPubKey, partial.paymentScriptPubKey)) {
    throw new Error('parse: payment scriptPubKey differs between full-fill and partial-fill branches');
  }
  assertSameExpiration(expirationFull, expirationPartial, 'full-fill and partial-fill branches');

  return {
    paymentScriptPubKey: full.paymentScriptPubKey,
    tokenId: new TextDecoder('utf-8', { fatal: true }).decode(full.tokenId),
    unitPriceSats: full.unitPriceSats,
    expiration: expirationFull
  };
}
