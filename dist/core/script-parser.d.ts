/**
 * Shared parsing primitives for strict covenant parsers. Each covenant
 * parser walks the exact byte layout emitted by its builder and fails on
 * any deviation; the primitives here centralize the cursor arithmetic,
 * pushdata decoding, and CScriptNum decoding so the legacy and PQ parsers
 * (and future covenant parsers) cannot drift in rigor.
 */
export interface Cursor {
    readonly bytes: Uint8Array;
    pos: number;
}
export declare function makeCursor(bytes: Uint8Array): Cursor;
/** Consume one byte and verify it equals `expected`. */
export declare function expectByte(c: Cursor, expected: number, label: string): void;
/** Fail if the cursor has not consumed every byte of the script. */
export declare function assertTrailing(c: Cursor): void;
/**
 * Read one pushdata element from the cursor. Supports direct pushes
 * (1..75 bytes), `OP_PUSHDATA1` and `OP_PUSHDATA2`. `OP_PUSHDATA4` is not
 * supported by any current covenant script and would overflow the
 * per-element cap anyway. Truncation is checked for all length fields
 * and payload ranges.
 */
export declare function readPush(c: Cursor, label: string): Uint8Array;
/**
 * Decode a `CScriptNum` byte vector (little-endian sign-magnitude, up to
 * 8 bytes) into a BigInt. Empty vector encodes 0.
 */
export declare function decodeScriptNum(data: Uint8Array, label: string): bigint;
/**
 * Read a push as a non-negative CScriptNum. Recognises OP_1..OP_16
 * shorthand. `OP_0` is not accepted because the covenant callers use this
 * only for values that are strictly positive (prices, selectors, indices).
 */
export declare function readPushPositiveInt(c: Cursor, label: string): bigint;
/**
 * Read a 1-byte selector as an UNSIGNED 8-bit integer (0..255). Accepts
 * two on-wire encodings, because old vs new covenant builders differ:
 *   - `OP_1..OP_16` shorthand (single opcode) → values 1..16.
 *   - `0x01 <byte>` raw 1-byte push → any value 1..255.
 *
 * Values 0x80..0xff MUST use the raw-push form; the CScriptNum encoding
 * would need a 0x00 padding byte and become 2 bytes on-stack, which
 * consensus `OP_TXHASH` rejects. The builder in `script-pq.ts` emits the
 * raw-push form unconditionally; the parser stays lenient so covenants
 * built by older tools (using OP_N for small values) still round-trip.
 */
export declare function readPushUint8(c: Cursor, label: string): number;
