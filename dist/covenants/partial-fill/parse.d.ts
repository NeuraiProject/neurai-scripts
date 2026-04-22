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
import type { Network, ParsedPartialFillOrder } from '../../types.js';
/**
 * Parse a covenant scriptPubKey and extract its parameters. Throws with a
 * descriptive message if the bytes don't match the partial-fill template.
 */
export declare function parsePartialFillScript(script: Uint8Array | string, network?: Network): ParsedPartialFillOrder;
