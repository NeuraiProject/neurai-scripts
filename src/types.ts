/**
 * Neurai chain discriminator: `xna` = mainnet, `xna-test` = testnet/regtest.
 *
 * Only the chain matters here. In neurai-key 5 the label `xna` also names
 * the ECDSA witness v3 address type; parsed P2PKH hashes are formatted as
 * Legacy Base58 (neurai-key `xna-legacy` / `xna-legacy-test`) whatever this
 * label says.
 *
 * This type intentionally appears only on the **parse side** of the API —
 * as an optional argument to the parsers and as a field on the parsed
 * result types. It is **not** part of any builder's input.
 *
 * Rationale: the covenant scriptPubKey bytes do not encode network. A
 * legacy covenant is a fixed sequence of opcodes and a 20-byte PKH; a PQ
 * covenant is opcodes plus a 32-byte commitment and the raw bytes of the
 * payment scriptPubKey. None of those change between `xna` and
 * `xna-test`. What differs across networks is:
 *
 *   - The *address encoding* used by the caller (base58 prefix for
 *     P2PKH, bech32m HRP for AuthScript), validated by `decodeAddress`
 *     when the builder receives an address string.
 *   - The *consensus flags* gating the DePIN-Test opcodes; those live on
 *     the node, not in the script bytes.
 *
 * So builders take an address string (whose prefix already carries the
 * network) and parsers take an explicit `network` label (so the caller
 * can later format `sellerPubKeyHash` or interpret `paymentScriptPubKey`
 * in the correct context). Keep this split intact when adding new
 * covenants: do not reintroduce `network` into builder params.
 */
export type Network = 'xna' | 'xna-test';

export type PartialFillExpirationMode = 'height' | 'mtp';

export interface PartialFillExpiration {
  /**
   * Chain context used to decide whether the sale is still active.
   *
   * - `height`: compare against the candidate block height.
   * - `mtp`: compare against the previous block's median time past.
   */
  mode: PartialFillExpirationMode;
  /**
   * Expiry boundary. Fills are valid only while `value > chainContext`.
   * At exactly this height / MTP, and after it, only the seller cancel branch
   * can spend the order.
   */
  value: bigint;
}

/**
 * Seller of an ECDSA-cancel order, in one of two forms:
 *   - `sellerAddress` alone: a legacy P2PKH address that is both the
 *     payment destination and the cancel key hash;
 *   - `paymentAddress` with `sellerPubKeyHash`: any payment destination
 *     and the HASH160 of the secp256k1 key that may cancel. This is the
 *     form for a strict ECDSA v3 (`nq1r…`) seller, whose address program is
 *     a commitment and not a key hash.
 * Passing both forms, or neither, throws.
 */
export interface PartialFillOrderParams {
  /**
   * Legacy P2PKH seller (base58check, "t..." on testnet, "N..." on
   * mainnet). Its 20-byte PKH is hardcoded as the cancel key hash and the
   * payment output must be the P2PKH script of that same PKH. Bech32m
   * addresses are rejected here: use `paymentAddress` + `sellerPubKeyHash`.
   */
  sellerAddress?: string;

  /**
   * Destination for the XNA payment: legacy P2PKH, generic AuthScript v1
   * (`nc1p…`), strict PQ v2 (`pq1z…`) or strict ECDSA v3 (`nq1r…`). The
   * covenant hardcodes its full scriptPubKey. Requires `sellerPubKeyHash`.
   */
  paymentAddress?: string;

  /**
   * HASH160 of the compressed secp256k1 public key allowed to cancel the
   * order (20 bytes). Requires `paymentAddress`.
   */
  sellerPubKeyHash?: Uint8Array;

  /** Name of the asset being sold (e.g. "CAT"). */
  tokenId: string;

  /**
   * Price per single indivisible unit of the asset, expressed in satoshis of
   * XNA. The covenant multiplies this by the filled amount and enforces the
   * XNA output to Alice is `>=` that product.
   *
   * Example: selling at 1 XNA per whole token with `units = 0` (non-divisible)
   * means `unitPriceSats = 100_000_000n`.
   */
  unitPriceSats: bigint;

  /**
   * Optional sale expiry enforced with OP_CHAINCONTEXT. When set, both buyer
   * fill branches require `expiration.value > current height/MTP`. The seller
   * cancel branch remains available to recover the order.
   */
  expiration?: PartialFillExpiration;
}

export interface ParsedPartialFillOrder {
  /** Network the parser was invoked with (used for downstream address formatting). */
  network: Network;
  /**
   * 20-byte HASH160 of the key allowed to cancel, extracted from the
   * covenant's cancel branch. It equals the payment P2PKH hash only for
   * orders built with `sellerAddress`.
   */
  sellerPubKeyHash: Uint8Array;
  /** scriptPubKey bytes embedded in the covenant for the payment output. */
  paymentScriptPubKey: Uint8Array;
  /** Asset name parsed from the covenant. */
  tokenId: string;
  /** Unit price parsed from the covenant, in XNA satoshis. */
  unitPriceSats: bigint;
  /** Optional sale expiry parsed from OP_CHAINCONTEXT gates. */
  expiration?: PartialFillExpiration;
  /** Script hex the parser was fed. */
  scriptHex: string;
}

export interface OrderUtxo {
  txid: string;
  vout: number;
  /** scriptPubKey of the covenant UTXO (the output produced by the seller). */
  scriptPubKeyHex: string;
  /** Cantidad del asset dentro del UTXO covenant. */
  assetAmountRaw: bigint;
  /** Valor XNA del UTXO (normalmente el dust mínimo). */
  valueSats: bigint;
}

export interface TxInputRef {
  txid: string;
  vout: number;
  sequence?: number;
  scriptSigHex?: string;
}

/**
 * Variant of the partial-fill order whose cancel branch validates a
 * post-quantum (ML-DSA-44) signature via `OP_CHECKSIGFROMSTACK`. Requires
 * both `SCRIPT_VERIFY_CHECKSIGFROMSTACK` and NIP-18's
 * `MAX_PQ_SCRIPT_ELEMENT_SIZE` to be active (testnet as of DePIN-Test with
 * NIP-18 deployed; mainnet after fork).
 */
export interface PartialFillOrderPQParams {
  /**
   * Destination for the XNA payment to the seller: legacy P2PKH
   * (`N.../t...`), generic AuthScript v1 (`nc1p.../tnc1p...`), strict PQ v2
   * (`pq1z.../tpq1z...`) or strict ECDSA v3 (`nq1r.../tnq1r...`). The
   * covenant hardcodes the full scriptPubKey bytes (`OP_1`/`OP_2`/`OP_3`
   * prefix included) either way.
   */
  paymentAddress: string;
  /**
   * 32-byte commitment to the seller's PQ public key. The script checks
   * `SHA256(pubKey_on_stack) == pubKeyCommitment`. Caller must compute this
   * as SHA256 over the same pubKey bytes that will be pushed on spend
   * (typically 1313 bytes = 1-byte version prefix + 1312-byte ML-DSA-44 key).
   */
  pubKeyCommitment: Uint8Array;
  /** Asset name being sold. */
  tokenId: string;
  /** Price in XNA satoshis per indivisible unit of the asset. */
  unitPriceSats: bigint;
  /**
   * NIP-042 OP_TXHASH selector bound into the script as exactly two
   * little-endian bytes. Default `0x1ff` commits all nine fields, including
   * reference inputs. The seller signs `SHA256(OP_TXHASH(selector))` with
   * their PQ key at cancel time.
   */
  txHashSelector?: number;
  /**
   * Optional sale expiry enforced with OP_CHAINCONTEXT. When set, both buyer
   * fill branches require `expiration.value > current height/MTP`.
   */
  expiration?: PartialFillExpiration;
}

export interface ParsedPartialFillOrderPQ
  extends Omit<PartialFillOrderPQParams, 'paymentAddress'> {
  /** Network the parser was invoked with (used for downstream address formatting). */
  network: Network;
  /** scriptPubKey bytes embedded in the covenant for the payment output. */
  paymentScriptPubKey: Uint8Array;
  scriptHex: string;
  /** Echoes the resolved selector so the caller can assert against a default. */
  txHashSelector: number;
}
