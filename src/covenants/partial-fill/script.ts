/**
 * Partial-Fill Sell Order covenant script (three-branch), ECDSA cancel.
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
 * The order must be input 0 for either fill branch to succeed: see the
 * input-0 binding in `./fill-branches.ts`.
 *
 * Unlock stack shapes (scriptSig pushes, top → bottom):
 *
 *   Cancel:        <sig> <pubkey> <1>
 *   Full fill:            <1>       <0>       (full-flag=1, cancel-flag=0)
 *   Partial fill:  <N>    <0>       <0>       (N, full-flag=0, cancel-flag=0)
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`)
 * against a 20-byte key hash. The payment destination is independent of
 * that key: a legacy P2PKH seller passes `sellerAddress` (both at once),
 * any other seller with a secp256k1 key — typically a strict ECDSA v3
 * `nq1r…` wallet — passes `paymentAddress` and `sellerPubKeyHash`. For
 * post-quantum cancellation use `buildPartialFillScriptPQ`.
 */

import { decodeAddress } from '@neuraiproject/neurai-create-transaction';
import { bytesToHex } from '../../core/bytes.js';
import { encodeSellerScriptPubKey } from '../../address.js';
import { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';
import {
  OP_CHECKSIG,
  OP_DUP,
  OP_ELSE,
  OP_ENDIF,
  OP_EQUALVERIFY,
  OP_HASH160,
  OP_IF
} from '../../core/opcodes.js';
import { ScriptBuilder } from '../../core/script-builder.js';
import type { PartialFillOrderParams } from '../../types.js';
import { assertExpiration } from './expiration.js';
import { appendFillBranches } from './fill-branches.js';

export { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';

const ASSET_NAME_MAX = 32;

function decodeSellerAddress(sellerAddress: string): Uint8Array {
  if (typeof sellerAddress !== 'string' || sellerAddress.length === 0) {
    throw new Error('sellerAddress is required');
  }
  const decoded = decodeAddress(sellerAddress);
  if (decoded.type !== 'p2pkh') {
    throw new Error(
      `sellerAddress must be a legacy P2PKH address; got ${decoded.type}. A seller with another address ` +
        `type passes paymentAddress and sellerPubKeyHash, or uses buildPartialFillScriptPQ for a PQ key.`
    );
  }
  const pkh = Uint8Array.from(decoded.hash);
  if (pkh.length !== 20) {
    throw new Error(
      `decoded sellerAddress produced a ${pkh.length}-byte hash, expected 20`
    );
  }
  return pkh;
}

/** Cancel key hash and payment scriptPubKey from either form of seller params. */
function resolveSeller(params: PartialFillOrderParams): {
  sellerPubKeyHash: Uint8Array;
  paymentScriptPubKey: Uint8Array;
} {
  const { sellerAddress, paymentAddress, sellerPubKeyHash } = params;
  if (sellerAddress !== undefined) {
    if (paymentAddress !== undefined || sellerPubKeyHash !== undefined) {
      throw new Error('pass either sellerAddress, or paymentAddress with sellerPubKeyHash, not both');
    }
    const pkh = decodeSellerAddress(sellerAddress);
    return { sellerPubKeyHash: pkh, paymentScriptPubKey: encodeP2PKHScriptPubKey(pkh) };
  }
  if (paymentAddress === undefined || sellerPubKeyHash === undefined) {
    throw new Error('sellerAddress, or paymentAddress with sellerPubKeyHash, is required');
  }
  if (!(sellerPubKeyHash instanceof Uint8Array) || sellerPubKeyHash.length !== 20) {
    throw new Error('sellerPubKeyHash must be a 20-byte Uint8Array (HASH160 of the compressed public key)');
  }
  return {
    sellerPubKeyHash: Uint8Array.from(sellerPubKeyHash),
    paymentScriptPubKey: encodeSellerScriptPubKey(paymentAddress).bytes
  };
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
export function buildPartialFillScript(params: PartialFillOrderParams): Uint8Array {
  const { tokenId, unitPriceSats } = params;
  const { sellerPubKeyHash, paymentScriptPubKey } = resolveSeller(params);
  assertTokenId(tokenId);
  assertPrice(unitPriceSats);
  const expiration = assertExpiration(params.expiration);

  const b = new ScriptBuilder();

  // ════════ Cancel branch (outer IF) ════════
  // scriptSig: <sig> <pubkey> <1>
  b.op(OP_IF)
    .op(OP_DUP, OP_HASH160)
    .pushBytes(sellerPubKeyHash)
    .op(OP_EQUALVERIFY, OP_CHECKSIG)
    .op(OP_ELSE);

  // ════════ Fill branches (outer ELSE) ════════
  appendFillBranches(b, {
    paymentScriptPubKey,
    tokenIdBytes: new TextEncoder().encode(tokenId),
    unitPriceSats,
    expiration
  });

  b.op(OP_ENDIF);             // closes outer cancel/fill IF

  return b.build();
}

/** Hex convenience wrapper for `buildPartialFillScript`. */
export function buildPartialFillScriptHex(params: PartialFillOrderParams): string {
  return bytesToHex(buildPartialFillScript(params));
}

// Re-export atomic helpers so parse.ts and callers can reuse them.
export { pushBytes, pushInt } from '../../core/script-builder.js';
