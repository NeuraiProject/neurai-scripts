import { describe, it, expect } from 'vitest';
import {
  encodeScriptNum,
  pushBytes,
  pushInt,
  ScriptBuilder
} from '../src/core/script-builder.js';
import { bytesToHex } from '../src/core/bytes.js';

describe('encodeScriptNum', () => {
  it('encodes 0 as an empty vector', () => {
    expect(encodeScriptNum(0n)).toEqual(new Uint8Array());
  });

  it('encodes small positive values without sign padding', () => {
    expect(bytesToHex(encodeScriptNum(1n))).toBe('01');
    expect(bytesToHex(encodeScriptNum(127n))).toBe('7f');
  });

  it('adds a sign-padding byte when high bit of MSB is set', () => {
    // 128 would encode as 0x80 which collides with the "negative zero"
    // marker; an extra 0x00 byte is required.
    expect(bytesToHex(encodeScriptNum(128n))).toBe('8000');
    expect(bytesToHex(encodeScriptNum(0xffn))).toBe('ff00');
  });

  it('encodes negatives by flipping the MSB sign bit', () => {
    expect(bytesToHex(encodeScriptNum(-1n))).toBe('81');
    expect(bytesToHex(encodeScriptNum(-128n))).toBe('8080');
  });

  it('encodes 1 XNA in satoshis as four little-endian bytes', () => {
    expect(bytesToHex(encodeScriptNum(100_000_000n))).toBe('00e1f505');
  });
});

describe('pushInt / pushBytes', () => {
  it('uses OP_0..OP_16 shorthand for 0..16', () => {
    expect(bytesToHex(pushInt(0))).toBe('00');
    expect(bytesToHex(pushInt(1))).toBe('51');
    expect(bytesToHex(pushInt(16))).toBe('60');
  });

  it('uses OP_1NEGATE for -1', () => {
    expect(bytesToHex(pushInt(-1))).toBe('4f');
  });

  it('uses a direct push for integers outside OP_N range', () => {
    expect(bytesToHex(pushInt(17))).toBe('0111');
    expect(bytesToHex(pushInt(100_000_000n))).toBe('0400e1f505');
  });

  it('switches to PUSHDATA1 past 75 bytes', () => {
    const data = new Uint8Array(76).fill(0x42);
    const encoded = pushBytes(data);
    expect(encoded[0]).toBe(0x4c);
    expect(encoded[1]).toBe(76);
    expect(encoded.length).toBe(2 + 76);
  });

  it('rejects pushes larger than MAX_PQ_SCRIPT_ELEMENT_SIZE (NIP-18 cap)', () => {
    const data = new Uint8Array(3073);
    expect(() => pushBytes(data)).toThrow(/exceeds MAX_PQ_SCRIPT_ELEMENT_SIZE/);
  });
});

describe('ScriptBuilder', () => {
  it('concatenates opcodes and pushes in order', () => {
    const hex = new ScriptBuilder()
      .op(0x76, 0xa9)
      .pushInt(1)
      .op(0x87)
      .buildHex();
    expect(hex).toBe('76a95187');
  });
});
