/**
 * Minimal byte helpers. A subset of what `neurai-create-transaction` exposes,
 * duplicated here to keep this package free of runtime coupling beyond its
 * declared `dependencies` field. All sizes are little-endian, per Neurai.
 */
export declare function ensureHex(hex: string, label?: string): string;
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;
export declare function concatBytes(...parts: Uint8Array[]): Uint8Array;
export declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;
