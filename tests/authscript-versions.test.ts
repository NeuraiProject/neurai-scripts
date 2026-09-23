import { describe, expect, it } from 'vitest';
import {
  buildStrictWitnessECDSA,
  buildStrictWitnessPQ,
  encodeAuthScriptScriptPubKey,
  encodeSellerScriptPubKey,
  STRICT_PQ_PUBKEY_LENGTH
} from '../src/index.js';
import { bytesToHex } from '../src/core/bytes.js';

// scriptPubKeys reported by a regtest node (validateaddress) for addresses of
// each family.
const NODE_VECTORS = [
  {
    address: 'tnc1p8802g0lnexmnvj7up5f55wz4elvj7xf7ytm0n6t95adrhl4vfgcq4r7pld',
    kind: 'authscript',
    witnessVersion: 1,
    scriptPubKey: '512039dea43ff3c9b7364bdc0d134a3855cfd92f193e22f6f9e965a75a3bfeac4a30'
  },
  {
    address: 'tpq1z5age5p2v5q9w6qzadkjp4yep8gpr56q6mzd4fu6eus8ntulul6vq3q07pc',
    kind: 'pq',
    witnessVersion: 2,
    scriptPubKey: '5220a7519a054ca00aed005d6da41a93213a023a681ad89b54f359e40f35f3fcfe98'
  },
  {
    address: 'tnq1rwentz4njukcn400flwk5tu6s8fmzwd3e408nmkqz6dvfysgcdp2suqptef',
    kind: 'ecdsa',
    witnessVersion: 3,
    scriptPubKey: '53207666b15672e5b13abde9fbad45f3503a76273639abcf3dd802d3589241186855'
  }
] as const;

describe('AuthScript witness versions', () => {
  it('encodes OP_1 / OP_2 / OP_3 programs and defaults to v1', () => {
    const program = new Uint8Array(32).fill(0x11);
    expect(bytesToHex(encodeAuthScriptScriptPubKey(program))).toBe(`5120${'11'.repeat(32)}`);
    expect(bytesToHex(encodeAuthScriptScriptPubKey(program, 2))).toBe(`5220${'11'.repeat(32)}`);
    expect(bytesToHex(encodeAuthScriptScriptPubKey(program, 3))).toBe(`5320${'11'.repeat(32)}`);
    expect(() => encodeAuthScriptScriptPubKey(program, 4 as never)).toThrow(/1, 2 or 3/);
  });

  it.each(NODE_VECTORS)('encodes the seller scriptPubKey of $kind like the node', (vector) => {
    const spk = encodeSellerScriptPubKey(vector.address);
    expect(spk.kind).toBe(vector.kind);
    expect(spk.witnessVersion).toBe(vector.witnessVersion);
    expect(bytesToHex(spk.bytes)).toBe(vector.scriptPubKey);
    expect(bytesToHex(spk.hash)).toBe(vector.scriptPubKey.slice(4));
  });
});

describe('strict witness builders', () => {
  const pqPubKey = new Uint8Array(STRICT_PQ_PUBKEY_LENGTH).fill(0x22);
  pqPubKey[0] = 0x05;
  const ecdsaPubKey = new Uint8Array(33).fill(0x33);
  ecdsaPubKey[0] = 0x02;

  it('builds the 4-item PQ v2 stack', () => {
    const stack = buildStrictWitnessPQ({ signature: new Uint8Array(2421).fill(1), pubKey: pqPubKey });
    expect(stack.map((item) => item.length)).toEqual([1, 2421, 1313, 1]);
    expect(stack[0][0]).toBe(0x01);
    expect(stack[3][0]).toBe(0x51);
  });

  it('rejects PQ keys without the 0x05 prefix or with another length', () => {
    const unprefixed = pqPubKey.slice();
    unprefixed[0] = 0x04;
    expect(() => buildStrictWitnessPQ({ signature: Uint8Array.of(1), pubKey: unprefixed })).toThrow(/0x05/);
    expect(() => buildStrictWitnessPQ({ signature: Uint8Array.of(1), pubKey: pqPubKey.slice(1) })).toThrow(/1313/);
    expect(() =>
      buildStrictWitnessPQ({ signature: new Uint8Array(3073), pubKey: pqPubKey })
    ).toThrow(/exceeds/);
  });

  it('builds the 4-item ECDSA v3 stack', () => {
    const stack = buildStrictWitnessECDSA({ signature: new Uint8Array(71).fill(1), pubKey: ecdsaPubKey });
    expect(stack.map((item) => item.length)).toEqual([1, 71, 33, 1]);
    expect(stack[0][0]).toBe(0x02);
    expect(stack[3][0]).toBe(0x51);
  });

  it('rejects uncompressed ECDSA keys', () => {
    const uncompressed = new Uint8Array(65).fill(4);
    expect(() => buildStrictWitnessECDSA({ signature: Uint8Array.of(1), pubKey: uncompressed })).toThrow(/compressed/);
    expect(() => buildStrictWitnessECDSA({ signature: new Uint8Array(0), pubKey: ecdsaPubKey })).toThrow(/signature/);
  });
});
