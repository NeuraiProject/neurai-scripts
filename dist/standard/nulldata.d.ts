/**
 * Provably-unspendable OP_RETURN (null-data) output scripts.
 * Layout: OP_RETURN <push> [<push> ...]
 *
 * Neurai inherits the Bitcoin Core standard policy cap of 80 bytes of
 * payload for a relayed null-data output. Outputs over that cap are still
 * consensus-valid but will not be relayed by default mempool policy; use
 * the `allowNonStandard` option to opt in explicitly.
 */
export declare const NULLDATA_STANDARD_MAX_SIZE = 80;
export interface EncodeNullDataOptions {
    /** Bypass the 80-byte standard-policy cap. Default: false. */
    allowNonStandard?: boolean;
}
export declare function encodeNullDataScript(payload: Uint8Array | Uint8Array[], options?: EncodeNullDataOptions): Uint8Array;
