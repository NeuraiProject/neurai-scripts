/**
 * Neurai network discriminator.
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

export interface PartialFillOrderParams {
  /**
   * Seller destination. Must be a legacy P2PKH address (base58check,
   * "t..." on testnet, "N..." on mainnet). The legacy covenant uses
   * `OP_HASH160 + OP_CHECKSIG` in its cancel branch, so AuthScript
   * bech32m addresses are rejected — use `buildPartialFillScriptPQ` for
   * post-quantum / AuthScript destinations. The decoded 20-byte PKH is
   * hardcoded into the covenant (cancel branch + payment scriptPubKey).
   */
  sellerAddress: string;

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
}

export interface ParsedPartialFillOrder {
  /** Network the parser was invoked with (used for downstream address formatting). */
  network: Network;
  /**
   * Seller's 20-byte pubkey hash, extracted from the covenant's cancel
   * branch. The caller can base58check-encode this with the network's
   * legacy prefix to recover the seller address when needed.
   */
  sellerPubKeyHash: Uint8Array;
  /** Asset name parsed from the covenant. */
  tokenId: string;
  /** Unit price parsed from the covenant, in XNA satoshis. */
  unitPriceSats: bigint;
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
   * Destination for the XNA payment to the seller. Can be legacy P2PKH
   * (`N.../t...`) OR AuthScript bech32m v1 (`nq1.../tnq1...`). The covenant
   * hardcodes the full scriptPubKey bytes either way.
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
   * OP_TXHASH selector byte bound into the script. Default `0xff` (all
   * eight fields). The seller must sign `SHA256(OP_TXHASH(selector))` with
   * their PQ key at cancel time. See
   * `doc/new-opcodes-depin-branch.md` §2.1 for the bit → field mapping.
   */
  txHashSelector?: number;
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
