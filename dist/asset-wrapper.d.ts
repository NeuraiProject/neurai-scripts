/**
 * Asset-transfer wrapper split helper.
 *
 * Neurai asset UTXOs have a scriptPubKey of the form
 *
 *     <prefix scriptPubKey bytes> OP_XNA_ASSET <pushdata(payload)> OP_DROP
 *
 * where `prefix` is the recipient's standard script (typically a P2PKH, an
 * AuthScript witness v1, or a bare covenant such as the partial-fill sell
 * order), and `payload` serializes a `CAssetTransfer`:
 *
 *     payload = rvn_prefix (0x72 0x76 0x6e) || type_marker (0x74 transfer)
 *             || VarStr(assetName)
 *             || int64LE(amountRaw)
 *             [ || messageRef (optional) || int64LE(expireTime) (optional) ]
 *
 * This helper separates the two halves so consumers can validate the prefix
 * (e.g. feed it to `parsePartialFillScript`) while independently reading the
 * asset data displayed to the user. The optional payload tail
 * (`message` + `expireTime`) is tolerated but not exposed — the first
 * version only needs `assetName` and `amountRaw`.
 *
 * Bare (non-wrapped) scriptPubKeys round-trip through this helper by
 * returning `prefixHex === input` and `assetTransfer === null`.
 */
export interface AssetTransferPayload {
    /** ASCII asset name as declared in the VarStr field. */
    assetName: string;
    /** Raw satoshi-scaled amount from the int64LE field. Display units = raw / 1e8. */
    amountRaw: bigint;
    /** Hex of the full payload bytes (starting at the `rvn` magic, ending at
     *  the last byte before OP_DROP). Includes optional tail when present. */
    payloadHex: string;
}
export interface SplitAssetWrappedResult {
    /** Bytes of the scriptPubKey BEFORE the OP_XNA_ASSET wrapper, hex. Equal
     *  to the input when the script carries no asset wrapper. */
    prefixHex: string;
    /** Parsed asset-transfer data, or null if the input has no asset wrapper. */
    assetTransfer: AssetTransferPayload | null;
}
/**
 * Parse an asset-transfer-wrapped scriptPubKey. Accepts both wrapped and
 * bare forms. Throws on structural malformation (truncated pushdata,
 * missing OP_DROP after payload, bad magic, unsupported pushdata width).
 */
export declare function splitAssetWrappedScriptPubKey(spkHex: string): SplitAssetWrappedResult;
