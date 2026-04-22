/**
 * Partial-Fill Sell Order covenant script.
 *
 * The covenant has two branches selected by the top of the unlock stack:
 *
 *   OP_IF   (unlock pushed 1)  → Cancel: seller signs, recovers remainder.
 *   OP_ELSE (unlock pushed 0)  → Public partial fill: buyer provides the
 *                                 fill amount `N` and the tx layout is
 *                                 validated byte by byte.
 *
 * The partial-fill branch enforces a fixed output layout so that the script
 * stays compact and parseable:
 *
 *   output[0] = XNA payment to seller   (value >= N * unitPriceSats)
 *   output[1] = asset to buyer          (tokenId, amount == N)
 *   output[2] = covenant remainder      (same AuthScript commitment, amount == in - N)
 *   output[3+] = optional buyer change  (not constrained by the covenant)
 *
 * The remainder UTXO reuses the spent covenant's AuthScript v1 commitment
 * via `OP_OUTPUTAUTHCOMMITMENT(2) == OP_TXFIELD(0x02)` (NIP-023). Comparing
 * commitments rather than full scriptPubKeys is mandatory here: the
 * remainder output's asset wrapper (`OP_XNA_ASSET ... OP_DROP`) encodes a
 * smaller `amountRaw` than the spent UTXO's wrapper, so the full-spk
 * equality used by earlier drafts was vacuously unsatisfiable on any
 * asset-wrapped covenant UTXO.
 *
 * The cancel branch uses classical ECDSA (`OP_HASH160 + OP_CHECKSIG`) and
 * commits to a 20-byte PKH. As a consequence this variant only accepts
 * legacy P2PKH addresses as the seller destination. For AuthScript bech32m
 * destinations and post-quantum signing, use `buildPartialFillScriptPQ`.
 */

import { decodeAddress } from '@neuraiproject/neurai-create-transaction';
import { bytesToHex } from '../../core/bytes.js';
import { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';
import {
  ASSETFIELD_AMOUNT,
  ASSETFIELD_NAME,
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
import { ScriptBuilder } from '../../core/script-builder.js';
import type { PartialFillOrderParams } from '../../types.js';

export { encodeP2PKHScriptPubKey } from '../../standard/p2pkh.js';

const ASSET_NAME_MAX = 32;

function decodeSellerAddress(sellerAddress: string): Uint8Array {
  if (typeof sellerAddress !== 'string' || sellerAddress.length === 0) {
    throw new Error('sellerAddress is required');
  }
  const decoded = decodeAddress(sellerAddress);
  if (decoded.type !== 'p2pkh') {
    throw new Error(
      `sellerAddress must be a legacy P2PKH address (the legacy partial-fill covenant uses OP_HASH160 + OP_CHECKSIG); ` +
        `got ${decoded.type}. Use buildPartialFillScriptPQ for AuthScript destinations.`
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
  // 8-byte signed int ceiling: values beyond this cannot be produced by OP_MUL
  // inside the covenant without overflow (CScriptNum is int64).
  if (priceSats > 0x7fffffffffffffffn) {
    throw new Error('unitPriceSats exceeds int64 range');
  }
}

/**
 * Build the `scriptPubKey` of a Partial-Fill Sell Order covenant UTXO.
 * Returns raw bytes; wrap with `bytesToHex` for wire format.
 */
export function buildPartialFillScript(params: PartialFillOrderParams): Uint8Array {
  const { sellerAddress, tokenId, unitPriceSats } = params;
  const sellerPubKeyHash = decodeSellerAddress(sellerAddress);
  assertTokenId(tokenId);
  assertPrice(unitPriceSats);

  const sellerScriptPubKey = encodeP2PKHScriptPubKey(sellerPubKeyHash);
  const tokenIdBytes = new TextEncoder().encode(tokenId);

  const b = new ScriptBuilder();

  // ───────── Cancel branch (IF) ─────────
  // scriptSig expected: <sig> <pubkey> OP_1
  b.op(OP_IF)
    .op(OP_DUP, OP_HASH160)
    .pushBytes(sellerPubKeyHash)
    .op(OP_EQUALVERIFY, OP_CHECKSIG)
    .op(OP_ELSE);

  // ───────── Partial-fill branch (ELSE) ─────────
  // scriptSig expected: <N> OP_0
  //
  // Stack invariant entering the ELSE branch: [ N ]

  // 1. Payment value to seller (output 0)
  //    require outputValue(0) >= N * unitPriceSats
  b.op(OP_DUP)              // [ N, N ]
    .pushInt(unitPriceSats) // [ N, N, price ]
    .op(OP_MUL)             // [ N, N*price ]
    .pushInt(0)             // [ N, N*price, 0 ]
    .op(OP_OUTPUTVALUE)     // [ N, N*price, value ]
    .op(OP_SWAP)            // [ N, value, N*price ]
    .op(OP_GREATERTHANOREQUAL)
    .op(OP_VERIFY);         // [ N ]

  // 2. Payment scriptPubKey must equal Alice's (output 0)
  b.pushInt(0)
    .op(OP_OUTPUTSCRIPT)    // [ N, scriptPubKey_out0 ]
    .pushBytes(sellerScriptPubKey)
    .op(OP_EQUALVERIFY);    // [ N ]

  // 3. Asset delivered to buyer (output 1): amount == N
  b.op(OP_DUP)              // [ N, N ]
    .pushInt(1)             // [ N, N, 1 ]
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD) // [ N, N, amount_out1 ]
    .op(OP_EQUALVERIFY);    // [ N ]

  // 4. Asset delivered to buyer (output 1): name == tokenId
  b.pushInt(1)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD) // [ N, name_out1 ]
    .pushBytes(tokenIdBytes)
    .op(OP_EQUALVERIFY);    // [ N ]

  // 5. Remainder covenant continuity (output 2): same AuthScript commitment
  //    as spent. NIP-023: comparing 32-byte commitments rather than full
  //    scriptPubKeys, because the remainder's asset wrapper carries a
  //    different `amountRaw` than the spent UTXO's wrapper.
  b.pushInt(2)
    .op(OP_OUTPUTAUTHCOMMITMENT)      // [ N, auth_out2 ]
    .pushInt(TXFIELD_AUTHSCRIPT_COMMITMENT)
    .op(OP_TXFIELD)                   // [ N, auth_out2, spent_auth ]
    .op(OP_EQUALVERIFY);              // [ N ]

  // 6. Remainder output: same tokenId
  b.pushInt(2)
    .pushInt(ASSETFIELD_NAME)
    .op(OP_OUTPUTASSETFIELD) // [ N, name_out2 ]
    .pushBytes(tokenIdBytes)
    .op(OP_EQUALVERIFY);    // [ N ]

  // 7. Remainder output: amount == inputAssetAmount - N
  b.pushInt(2)
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_OUTPUTASSETFIELD) // [ N, rem_amount ]
    .op(OP_OVER)             // [ N, rem_amount, N ]       -- copy N under top
    .pushInt(0)              // [ N, rem_amount, N, 0 ]
    .pushInt(ASSETFIELD_AMOUNT)
    .op(OP_INPUTASSETFIELD)  // [ N, rem_amount, N, in_amount ]
    .op(OP_SWAP)             // [ N, rem_amount, in_amount, N ]
    .op(OP_SUB)              // [ N, rem_amount, in_amount - N ]
    .op(OP_EQUALVERIFY);     // [ N ]

  // Drop N, leave TRUE on the stack so the ELSE branch evaluates as success.
  b.op(OP_DROP).pushInt(1);

  b.op(OP_ENDIF);

  return b.build();
}

/** Hex convenience wrapper for `buildPartialFillScript`. */
export function buildPartialFillScriptHex(params: PartialFillOrderParams): string {
  return bytesToHex(buildPartialFillScript(params));
}

// Re-export atomic helpers so parse.ts and callers can reuse them.
export { pushBytes, pushInt } from '../../core/script-builder.js';
