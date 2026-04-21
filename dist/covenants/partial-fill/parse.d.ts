/**
 * Parser for the Partial-Fill Sell Order covenant.
 *
 * Extracts `(sellerPubKeyHash, unitPriceSats, tokenId)` from a scriptPubKey
 * that was produced by `buildPartialFillScript`. The parser walks the exact
 * byte layout emitted by the builder and fails on any deviation — this is
 * deliberate, so a downstream indexer can unambiguously classify a UTXO as
 * "partial-fill order" or "unknown script" with no false positives.
 */
import type { Network, ParsedPartialFillOrder } from '../../types.js';
/**
 * Parse a covenant scriptPubKey and extract its parameters. Throws with a
 * descriptive message if the bytes don't match the partial-fill template.
 */
export declare function parsePartialFillScript(script: Uint8Array | string, network?: Network): ParsedPartialFillOrder;
