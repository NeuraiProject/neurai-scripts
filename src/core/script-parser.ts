/**
 * Shared parsing primitives for strict covenant parsers. Each covenant
 * parser walks the exact byte layout emitted by its builder and fails on
 * any deviation; the primitives here centralize the cursor arithmetic,
 * pushdata decoding, and CScriptNum decoding so the legacy and PQ parsers
 * (and future covenant parsers) cannot drift in rigor.
 */

import { OP_1 } from './opcodes.js';

export interface Cursor {
  readonly bytes: Uint8Array;
  pos: number;
}

export function makeCursor(bytes: Uint8Array): Cursor {
  return { bytes, pos: 0 };
}

/** Consume one byte and verify it equals `expected`. */
export function expectByte(c: Cursor, expected: number, label: string): void {
  if (c.pos >= c.bytes.length) {
    throw new Error(`parse: unexpected end of script while reading ${label}`);
  }
  const got = c.bytes[c.pos];
  if (got !== expected) {
    throw new Error(
      `parse: expected ${label} = 0x${expected.toString(16)} at offset ${c.pos}, got 0x${got.toString(16)}`
    );
  }
  c.pos += 1;
}

/** Fail if the cursor has not consumed every byte of the script. */
export function assertTrailing(c: Cursor): void {
  if (c.pos !== c.bytes.length) {
    throw new Error(`parse: ${c.bytes.length - c.pos} trailing bytes after end of script`);
  }
}

/**
 * Read one pushdata element from the cursor. Supports direct pushes
 * (1..75 bytes), `OP_PUSHDATA1` and `OP_PUSHDATA2`. `OP_PUSHDATA4` is not
 * supported by any current covenant script and would overflow the
 * per-element cap anyway. Truncation is checked for all length fields
 * and payload ranges.
 */
export function readPush(c: Cursor, label: string): Uint8Array {
  if (c.pos >= c.bytes.length) {
    throw new Error(`parse: unexpected end of script while reading push for ${label}`);
  }
  const opcode = c.bytes[c.pos];
  c.pos += 1;

  // Short direct push: 1..75 bytes
  if (opcode >= 0x01 && opcode <= 0x4b) {
    const len = opcode;
    if (c.pos + len > c.bytes.length) {
      throw new Error(
        `parse: short push of ${len} bytes exceeds script length at ${label}`
      );
    }
    const data = c.bytes.slice(c.pos, c.pos + len);
    c.pos += len;
    return data;
  }

  // OP_PUSHDATA1
  if (opcode === 0x4c) {
    if (c.pos >= c.bytes.length) {
      throw new Error(`parse: truncated PUSHDATA1 length at ${label}`);
    }
    const len = c.bytes[c.pos];
    c.pos += 1;
    if (c.pos + len > c.bytes.length) {
      throw new Error(
        `parse: PUSHDATA1 of ${len} bytes exceeds script length at ${label}`
      );
    }
    const data = c.bytes.slice(c.pos, c.pos + len);
    c.pos += len;
    return data;
  }

  // OP_PUSHDATA2
  if (opcode === 0x4d) {
    if (c.pos + 2 > c.bytes.length) {
      throw new Error(`parse: truncated PUSHDATA2 length at ${label}`);
    }
    const len = c.bytes[c.pos] | (c.bytes[c.pos + 1] << 8);
    c.pos += 2;
    if (c.pos + len > c.bytes.length) {
      throw new Error(
        `parse: PUSHDATA2 of ${len} bytes exceeds script length at ${label}`
      );
    }
    const data = c.bytes.slice(c.pos, c.pos + len);
    c.pos += len;
    return data;
  }

  throw new Error(
    `parse: expected a pushdata opcode at ${label}, got 0x${opcode.toString(16)} at offset ${c.pos - 1}`
  );
}

/**
 * Decode a `CScriptNum` byte vector (little-endian sign-magnitude, up to
 * 8 bytes) into a BigInt. Empty vector encodes 0.
 */
export function decodeScriptNum(data: Uint8Array, label: string): bigint {
  if (data.length === 0) return 0n;
  if (data.length > 8) {
    throw new Error(`parse: CScriptNum at ${label} exceeds 8 bytes`);
  }
  let n = 0n;
  for (let i = 0; i < data.length - 1; i += 1) {
    n |= BigInt(data[i]) << BigInt(8 * i);
  }
  const last = data[data.length - 1];
  n |= BigInt(last & 0x7f) << BigInt(8 * (data.length - 1));
  if (last & 0x80) {
    n = -n;
  }
  return n;
}

/**
 * Read a push as a non-negative CScriptNum. Recognises OP_1..OP_16
 * shorthand. `OP_0` is not accepted because the covenant callers use this
 * only for values that are strictly positive (prices, selectors, indices).
 */
export function readPushPositiveInt(c: Cursor, label: string): bigint {
  if (c.pos >= c.bytes.length) {
    throw new Error(`parse: end of script at ${label}`);
  }
  const opcode = c.bytes[c.pos];
  if (opcode >= OP_1 && opcode <= 0x60) {
    c.pos += 1;
    return BigInt(opcode - OP_1 + 1);
  }
  const data = readPush(c, label);
  return decodeScriptNum(data, label);
}

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
export function readPushUint8(c: Cursor, label: string): number {
  if (c.pos >= c.bytes.length) {
    throw new Error(`parse: end of script at ${label}`);
  }
  const opcode = c.bytes[c.pos];
  if (opcode >= OP_1 && opcode <= 0x60) {
    c.pos += 1;
    return opcode - OP_1 + 1;
  }
  const data = readPush(c, label);
  if (data.length !== 1) {
    throw new Error(
      `parse: ${label} must be a single-byte push, got ${data.length} bytes`
    );
  }
  return data[0];
}
