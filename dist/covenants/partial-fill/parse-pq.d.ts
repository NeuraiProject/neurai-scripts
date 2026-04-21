/**
 * Parser for the PQ Partial-Fill Sell Order covenant. Returns the same
 * economic parameters as the legacy parser, plus the payment scriptPubKey
 * bytes (which may be P2PKH or AuthScript) and the configured TXHASH
 * selector.
 */
import type { Network, ParsedPartialFillOrderPQ } from '../../types.js';
/** Quick discriminator without throwing — useful for indexers. */
export declare function isPartialFillScriptPQ(script: Uint8Array | string): boolean;
/**
 * Parse a PQ partial-fill covenant. Throws if the bytes do not match the
 * exact layout produced by `buildPartialFillScriptPQ`.
 */
export declare function parsePartialFillScriptPQ(script: Uint8Array | string, network?: Network): ParsedPartialFillOrderPQ;
