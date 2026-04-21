/**
 * Low-level Script assembler. Emits the exact byte layout expected by the
 * Neurai interpreter: pushdata prefixes follow the same rules as Bitcoin
 * (direct push for 1..75 bytes, OP_PUSHDATA1/2/4 otherwise), and integers
 * are minimally-encoded as CScriptNum.
 */

import { bytesToHex, concatBytes, hexToBytes } from './bytes.js';
import { OP_0, OP_1NEGATE, OP_1, OP_16 } from './opcodes.js';

/**
 * Minimal CScriptNum encoding (Bitcoin consensus rules).
 *
 * - 0 → empty vector
 * - 1..16 → single opcode OP_1..OP_16 (handled in `pushInt`, not here)
 * - -1 → OP_1NEGATE (handled in `pushInt`)
 * - otherwise: sign-magnitude little-endian, with a sign bit on the last byte
 */
export function encodeScriptNum(value: bigint | number): Uint8Array {
  let n = typeof value === 'bigint' ? value : BigInt(value);
  if (n === 0n) return new Uint8Array();

  const negative = n < 0n;
  if (negative) n = -n;

  const result: number[] = [];
  while (n > 0n) {
    result.push(Number(n & 0xffn));
    n >>= 8n;
  }

  // If the most-significant bit is set, add a padding byte so the sign bit
  // is unambiguous. If negative, flip that sign bit instead.
  if (result[result.length - 1] & 0x80) {
    result.push(negative ? 0x80 : 0x00);
  } else if (negative) {
    result[result.length - 1] |= 0x80;
  }

  return Uint8Array.from(result);
}

/**
 * Emit a pushdata opcode followed by the payload. Chooses the shortest
 * valid encoding.
 *
 * Neurai Script caps stack elements at `MAX_SCRIPT_ELEMENT_SIZE = 520`
 * bytes by default, but NIP-18 raises the cap to
 * `MAX_PQ_SCRIPT_ELEMENT_SIZE = 3072` whenever
 * `SCRIPT_VERIFY_CHECKSIGFROMSTACK` is active (testnet today, mainnet once
 * the CSFS fork lands). The builder here emits pushes up to 3072 bytes so
 * it can target either regime; legacy scripts should stay under 520 bytes
 * per push, and the node will reject anything larger if the CSFS flag is
 * not set during evaluation.
 */
export function pushBytes(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    return Uint8Array.of(OP_0);
  }
  if (data.length <= 75) {
    return concatBytes(Uint8Array.of(data.length), data);
  }
  if (data.length <= 0xff) {
    return concatBytes(Uint8Array.of(0x4c, data.length), data);
  }
  if (data.length <= 3072) {
    return concatBytes(
      Uint8Array.of(0x4d, data.length & 0xff, (data.length >> 8) & 0xff),
      data
    );
  }
  throw new Error(
    `pushBytes: element of ${data.length} bytes exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE (3072)`
  );
}

/**
 * Emit a minimally-encoded integer push. Uses OP_1NEGATE, OP_0 and OP_1..OP_16
 * when available to match how the node's own templates look on the wire.
 */
export function pushInt(value: bigint | number): Uint8Array {
  const n = typeof value === 'bigint' ? value : BigInt(value);
  if (n === -1n) return Uint8Array.of(OP_1NEGATE);
  if (n === 0n) return Uint8Array.of(OP_0);
  if (n >= 1n && n <= 16n) {
    return Uint8Array.of(OP_1 + Number(n) - 1);
  }
  return pushBytes(encodeScriptNum(n));
}

export function pushHex(hex: string): Uint8Array {
  return pushBytes(hexToBytes(hex));
}

/** Fluent assembler for readable script definitions. */
export class ScriptBuilder {
  private readonly parts: Uint8Array[] = [];

  op(...opcodes: number[]): this {
    for (const op of opcodes) {
      if (!Number.isInteger(op) || op < 0 || op > 0xff) {
        throw new Error(`Invalid opcode byte: ${op}`);
      }
      this.parts.push(Uint8Array.of(op));
    }
    return this;
  }

  pushInt(value: bigint | number): this {
    this.parts.push(pushInt(value));
    return this;
  }

  pushBytes(data: Uint8Array): this {
    this.parts.push(pushBytes(data));
    return this;
  }

  pushHex(hex: string): this {
    this.parts.push(pushHex(hex));
    return this;
  }

  raw(bytes: Uint8Array): this {
    this.parts.push(bytes);
    return this;
  }

  build(): Uint8Array {
    return concatBytes(...this.parts);
  }

  buildHex(): string {
    return bytesToHex(this.build());
  }
}
