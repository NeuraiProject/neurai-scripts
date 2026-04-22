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
 * produces its own 32-byte hash, so the seller computes:
 *   `sign(pqSeckey, SHA256(doubleSHA256(selected_tx_fields)))`
 *
 * Fill branches are identical in structure to the legacy variant — see
 * `./script.ts` for the three-branch layout description.
 */

import { bytesToHex } from '../../core/bytes.js';
import { encodeSellerScriptPubKey } from '../../address.js';
import {
  ASSETFIELD_AMOUNT,
  ASSETFIELD_NAME,
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
import { ScriptBuilder } from '../../core/script-builder.js';
import type { PartialFillOrderPQParams } from '../../types.js';

const ASSET_NAME_MAX = 32;
export const DEFAULT_PQ_TXHASH_SELECTOR = 0xff;

function assertCommitment(commitment: Uint8Array): void {
  if (!(commitment instanceof Uint8Array) || commitment.length !== 32) {
    throw new Error('pubKeyCommitment must be a 32-byte Uint8Array (SHA256 of pubKey)');
  }
}

function assertTokenId(tokenId: string): void {
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

function assertPrice(priceSats: bigint): void {
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

function assertSelector(selector: number): void {
  if (!Number.isInteger(selector) || selector < 0 || selector > 0xff) {
    throw new Error('txHashSelector must be a single byte (0x00..0xff)');
  }
  if (selector === 0) {
    throw new Error('txHashSelector 0x00 is rejected by OP_TXHASH');
  }
}

/**
 * Build the scriptPubKey of a PQ Partial-Fill Sell Order covenant UTXO.
 */
export function buildPartialFillScriptPQ(params: PartialFillOrderPQParams): Uint8Array {
  const {
    paymentAddress,
    pubKeyCommitment,
    tokenId,
    unitPriceSats,
    txHashSelector = DEFAULT_PQ_TXHASH_SELECTOR
  } = params;

  assertCommitment(pubKeyCommitment);
  assertTokenId(tokenId);
  assertPrice(unitPriceSats);
  assertSelector(txHashSelector);

  const payment = encodeSellerScriptPubKey(paymentAddress);
  const tokenIdBytes = new TextEncoder().encode(tokenId);

  const b = new ScriptBuilder();

  // ════════ Cancel branch (PQ via OP_CHECKSIGFROMSTACK) ════════
  // scriptSig: <sigPQ> <pubKeyPQ> <1>
  // After OP_IF consumes the flag: [ sig, pubKey ]
  //
  // The selector MUST be pushed as a raw 1-byte element — consensus rejects
  // any stack item of size ≠ 1. Using `pushInt(selector)` would work for
  // 1..127 but emit a 2-byte CScriptNum for 0x80..0xff (sign-disambiguation
  // pad), which makes OP_TXHASH fail with SCRIPT_ERR_TXHASH.
  b.op(OP_IF)
    .op(OP_DUP)                                 // [ sig, pubKey, pubKey ]
    .op(OP_SHA256)                              // [ sig, pubKey, H(pubKey) ]
    .pushBytes(pubKeyCommitment)                // [ sig, pubKey, H(pubKey), commitment ]
    .op(OP_EQUALVERIFY)                         // [ sig, pubKey ]
    .pushBytes(Uint8Array.of(txHashSelector))   // [ sig, pubKey, selector ]
    .op(OP_TXHASH)                              // [ sig, pubKey, txHash ]
    .op(OP_SWAP)                                // [ sig, txHash, pubKey ]
    .op(OP_CHECKSIGFROMSTACK)                   // [ 1 | 0 ]
    .op(OP_ELSE);

  // ════════ Fill branches (inner IF: full / ELSE: partial) ════════
  b.op(OP_IF);

  // ──────── Full-fill branch ────────
  // scriptSig: <1> <0>
  // Stack entering: [ ]

  // 1. N = inputAmount
  b.pushInt(0)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_INPUTASSETFIELD);

  // 2. Payment value (output 0) >= N * unitPriceSats
  b.op(OP_DUP)
    .pushInt(unitPriceSats)
    .op(OP_MUL)
    .pushInt(0)
    .op(OP_OUTPUTVALUE)
    .op(OP_SWAP)
    .op(OP_GREATERTHANOREQUAL)
    .op(OP_VERIFY);

  // 3. Payment scriptPubKey (output 0)
  b.pushInt(0)
    .op(OP_OUTPUTSCRIPT)
    .pushBytes(payment.bytes)
    .op(OP_EQUALVERIFY);

  // 4. Asset to buyer (output 1) amount == N
  b.op(OP_DUP)
    .pushInt(1)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD)
    .op(OP_EQUALVERIFY);

  // 5. Asset to buyer (output 1) name == tokenId
  b.pushInt(1)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD)
    .pushBytes(tokenIdBytes)
    .op(OP_EQUALVERIFY);

  b.op(OP_DROP).pushInt(1);

  // ──────── Partial-fill branch ────────
  // scriptSig: <N> <0> <0>
  // Stack entering: [ N ]
  b.op(OP_ELSE);

  // 1. Payment value (output 0) >= N * unitPriceSats
  b.op(OP_DUP)
    .pushInt(unitPriceSats)
    .op(OP_MUL)
    .pushInt(0)
    .op(OP_OUTPUTVALUE)
    .op(OP_SWAP)
    .op(OP_GREATERTHANOREQUAL)
    .op(OP_VERIFY);

  // 2. Payment scriptPubKey (output 0)
  b.pushInt(0)
    .op(OP_OUTPUTSCRIPT)
    .pushBytes(payment.bytes)
    .op(OP_EQUALVERIFY);

  // 3. Asset to buyer (output 1) amount == N
  b.op(OP_DUP)
    .pushInt(1)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD)
    .op(OP_EQUALVERIFY);

  // 4. Asset to buyer (output 1) name == tokenId
  b.pushInt(1)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD)
    .pushBytes(tokenIdBytes)
    .op(OP_EQUALVERIFY);

  // 5. Continuation (output 2): same AuthScript commitment as spent (NIP-023)
  b.pushInt(2)
    .op(OP_OUTPUTAUTHCOMMITMENT)
    .pushInt(TXFIELD_AUTHSCRIPT_COMMITMENT)
    .op(OP_TXFIELD)
    .op(OP_EQUALVERIFY);

  // 6. Continuation name == tokenId
  b.pushInt(2)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD)
    .pushBytes(tokenIdBytes)
    .op(OP_EQUALVERIFY);

  // 7. Continuation amount == inputAmount - N
  b.pushInt(2)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD)
    .op(OP_OVER)
    .pushInt(0)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_INPUTASSETFIELD)
    .op(OP_SWAP)
    .op(OP_SUB)
    .op(OP_EQUALVERIFY);

  b.op(OP_DROP).pushInt(1);

  b.op(OP_ENDIF);             // full / partial
  b.op(OP_ENDIF);             // cancel / fill

  return b.build();
}

export function buildPartialFillScriptPQHex(params: PartialFillOrderPQParams): string {
  return bytesToHex(buildPartialFillScriptPQ(params));
}
