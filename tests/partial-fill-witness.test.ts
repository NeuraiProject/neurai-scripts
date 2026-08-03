import { describe, expect, it } from 'vitest';
import {
  buildAuthScriptWitnessNoAuth,
  buildCancelScriptSig,
  buildCancelWitnessStack,
  buildCancelWitnessStackPQ,
  buildFillScriptSig,
  buildFillWitnessStack,
  bytesToHex
} from '../src/index.js';

const hex = (elements: Uint8Array[]) => elements.map(bytesToHex);

describe('partial-fill witness stacks', () => {
  it('full fill: [<1>, <0>] as raw stack values (0 = empty element)', () => {
    expect(hex(buildFillWitnessStack(5n, 5n))).toEqual(['01', '']);
  });

  it('partial fill: [<N>, <0>, <0>] with minimal CScriptNum amount', () => {
    expect(hex(buildFillWitnessStack(2n, 5n))).toEqual(['02', '', '']);
    // 0x80 needs a sign-disambiguation byte: 128 → 8000
    expect(hex(buildFillWitnessStack(128n, 500n))).toEqual(['8000', '', '']);
    // multi-byte little-endian: 100_000_000 → 00e1f505
    expect(hex(buildFillWitnessStack(100_000_000n, 200_000_000n))).toEqual([
      '00e1f505',
      '',
      ''
    ]);
  });

  it('cancel: [<sig>, <pubkey>, <1>]', () => {
    const sig = Uint8Array.of(0x30, 0x44, 0x02, 0x20);
    const pubkey = new Uint8Array(33).fill(0x02);
    expect(hex(buildCancelWitnessStack(sig, pubkey))).toEqual([
      bytesToHex(sig),
      bytesToHex(pubkey),
      '01'
    ]);
  });

  it('PQ cancel: [<sigPQ>, <pubkey>, <1>] within the NIP-18 element cap', () => {
    const sigPQ = new Uint8Array(2421).fill(0xaa);
    const pubKey = new Uint8Array(1313).fill(0xbb);
    const stack = buildCancelWitnessStackPQ(sigPQ, pubKey);
    expect(stack).toHaveLength(3);
    expect(stack[0]).toBe(sigPQ);
    expect(stack[1]).toBe(pubKey);
    expect(bytesToHex(stack[2])).toBe('01');

    expect(() => buildCancelWitnessStackPQ(new Uint8Array(3073), pubKey)).toThrow(
      /MAX_PQ_SCRIPT_ELEMENT_SIZE/
    );
  });

  it('mirrors buildFillScriptSig/buildCancelScriptSig validations', () => {
    expect(() => buildFillWitnessStack(0n, 5n)).toThrow(/fill amount must be > 0/);
    expect(() => buildFillWitnessStack(6n, 5n)).toThrow(/exceeds the covenant total/);
    expect(() => buildFillWitnessStack(1n, 0n)).toThrow(/total must be > 0/);
    expect(() =>
      buildCancelWitnessStack(new Uint8Array(), new Uint8Array(33))
    ).toThrow(/non-empty/);
    expect(() =>
      buildCancelWitnessStack(Uint8Array.of(0x30), new Uint8Array(32))
    ).toThrow(/compressed \(33B\) or uncompressed \(65B\)/);
  });

  it('witness elements are values, not the scriptSig push encoding', () => {
    // The scriptSig blob for a partial fill of 2 is `52 00 00` (OP_2 OP_0
    // OP_0) — three PUSHES concatenated into one script. The witness stack
    // must instead carry the three VALUES: [0x02], empty, empty.
    expect(bytesToHex(buildFillScriptSig(2n, 5n))).toBe('520000');
    expect(hex(buildFillWitnessStack(2n, 5n))).toEqual(['02', '', '']);

    const sig = Uint8Array.of(0x30, 0x44);
    const pubkey = new Uint8Array(33).fill(0x02);
    // scriptSig prefixes each element with its push opcode…
    expect(bytesToHex(buildCancelScriptSig(sig, pubkey)).startsWith('02')).toBe(true);
    // …the witness stack carries them raw.
    expect(buildCancelWitnessStack(sig, pubkey)[0]).toBe(sig);
  });

  it('wraps into a full NoAuth witness: [0x00, ...args, covenant]', () => {
    const covenant = Uint8Array.of(0x51); // OP_TRUE stand-in
    const witness = buildAuthScriptWitnessNoAuth({
      args: buildFillWitnessStack(2n, 5n),
      witnessScript: covenant
    });
    expect(hex(witness)).toEqual(['00', '02', '', '', '51']);
  });
});
