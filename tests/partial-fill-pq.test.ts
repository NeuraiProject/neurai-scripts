import { describe, it, expect } from 'vitest';
import {
  buildPartialFillScriptPQ,
  buildPartialFillScriptPQHex,
  buildCancelScriptSigPQHex,
  parsePartialFillScriptPQ,
  parsePartialFillScript,
  isPartialFillScriptPQ,
  encodeSellerScriptPubKey,
  encodeAuthScriptScriptPubKey,
  DEFAULT_PQ_TXHASH_SELECTOR
} from '../src/index.js';
import { bytesToHex } from '../src/core/bytes.js';
import type { PartialFillOrderPQParams } from '../src/types.js';
import { testnetAuthScriptAddress } from './helpers.js';

// Valid Neurai testnet P2PKH (byte prefix 127 → "t..."). Reused across the
// neurai-create-transaction test suite.
const TESTNET_P2PKH = 'tKCkEUQGbZqX91vyo2mpZ23pmYwfWCVfan';

// We do not need a real PQ pubkey to test the byte layout — just 32 bytes
// of "commitment" that would come from SHA256 of the real pubkey.
const pubKeyCommitment = new Uint8Array(32).fill(0xcc);

const baseParams: PartialFillOrderPQParams = {
  paymentAddress: TESTNET_P2PKH,
  pubKeyCommitment,
  tokenId: 'CAT',
  unitPriceSats: 100_000_000n
};

describe('buildPartialFillScriptPQ', () => {
  it('emits a script starting with IF DUP SHA256 <32B commitment>', () => {
    const hex = buildPartialFillScriptPQHex(baseParams);
    expect(hex.startsWith('63' + '76' + 'a8' + '20' + 'cc'.repeat(32))).toBe(true);
  });

  it('embeds the default selector 0xff via a raw 1-byte push', () => {
    const hex = buildPartialFillScriptPQHex(baseParams);
    // After the commitment EQUALVERIFY, builder emits a raw 1-byte push
    // `01 <selector>` so OP_TXHASH sees a single-byte stack item. Using
    // `pushInt(0xff)` would emit `02 ff 00` (CScriptNum + 0x00 pad) which
    // consensus rejects with SCRIPT_ERR_TXHASH (plan v3 bug B).
    expect(hex).toContain('8801ffb5');
    //                     88        EQUALVERIFY on commitment
    //                       01ff    raw 1-byte push of 0xff
    //                           b5  OP_TXHASH
  });

  it('honours a custom selector byte in the 1..127 range', () => {
    const hex = buildPartialFillScriptPQHex({ ...baseParams, txHashSelector: 0x3f });
    expect(hex).toContain('88013fb5');
  });

  it('handles selector 0x80 (high bit set) — was broken by pushInt before v0.3.0', () => {
    const hex = buildPartialFillScriptPQHex({ ...baseParams, txHashSelector: 0x80 });
    // Must emit `01 80` — NOT `02 80 00` — so OP_TXHASH gets a 1-byte item.
    expect(hex).toContain('880180b5');
  });

  it('round-trips selector 0xff through parser (regression for v3 bug B)', () => {
    const hex = buildPartialFillScriptPQHex({ ...baseParams, txHashSelector: 0xff });
    expect(parsePartialFillScriptPQ(hex).txHashSelector).toBe(0xff);
  });

  it('round-trips selector 0x80 through parser', () => {
    const hex = buildPartialFillScriptPQHex({ ...baseParams, txHashSelector: 0x80 });
    expect(parsePartialFillScriptPQ(hex).txHashSelector).toBe(0x80);
  });

  it('parser accepts legacy OP_N shorthand for selectors 1..16 (backwards compat)', () => {
    // Hand-build the cancel branch preamble with OP_1 (single opcode 0x51)
    // instead of the new raw 1-byte push. Older on-chain covenants used
    // this form — the parser must keep accepting it.
    const hex = buildPartialFillScriptPQHex({ ...baseParams, txHashSelector: 0x01 });
    // Builder now emits `01 01`; patch to OP_1 (0x51) to simulate old form.
    const patched = hex.replace('880101b5', '8851b5');
    expect(patched).not.toBe(hex);
    expect(parsePartialFillScriptPQ(patched).txHashSelector).toBe(1);
  });

  it('ends the cancel branch with SWAP CHECKSIGFROMSTACK ELSE', () => {
    const hex = buildPartialFillScriptPQHex(baseParams);
    // OP_TXHASH b5, OP_SWAP 7c, OP_CHECKSIGFROMSTACK b4, OP_ELSE 67
    expect(hex).toContain('b57cb467');
  });

  it('rejects a non-32-byte commitment', () => {
    expect(() =>
      buildPartialFillScriptPQ({
        ...baseParams,
        pubKeyCommitment: new Uint8Array(20)
      })
    ).toThrow(/32-byte/);
  });

  it('rejects txHashSelector 0x00', () => {
    expect(() =>
      buildPartialFillScriptPQ({ ...baseParams, txHashSelector: 0 })
    ).toThrow(/rejected by OP_TXHASH/);
  });

  it('rejects txHashSelector out of byte range', () => {
    expect(() =>
      buildPartialFillScriptPQ({ ...baseParams, txHashSelector: 256 })
    ).toThrow(/single byte/);
  });

  it('builds end-to-end with an AuthScript bech32m paymentAddress', () => {
    const program = new Uint8Array(32).fill(0xab);
    const pqAddress = testnetAuthScriptAddress(program);

    const scriptHex = buildPartialFillScriptPQHex({
      ...baseParams,
      paymentAddress: pqAddress
    });
    const parsed = parsePartialFillScriptPQ(scriptHex);

    // AuthScript paymentScriptPubKey: OP_1 (0x51) 0x20 <32-byte program> = 34 bytes
    expect(parsed.paymentScriptPubKey.length).toBe(34);
    expect(parsed.paymentScriptPubKey[0]).toBe(0x51);
    expect(parsed.paymentScriptPubKey[1]).toBe(0x20);
    expect(bytesToHex(parsed.paymentScriptPubKey.slice(2))).toBe('ab'.repeat(32));

    // Economic parameters round-trip regardless of destination kind
    expect(parsed.tokenId).toBe('CAT');
    expect(parsed.unitPriceSats).toBe(100_000_000n);
    expect(bytesToHex(parsed.pubKeyCommitment)).toBe('cc'.repeat(32));
  });

  it('still builds end-to-end with a legacy P2PKH paymentAddress', () => {
    // Baseline so the AuthScript test above isn't the only E2E path covered.
    const scriptHex = buildPartialFillScriptPQHex(baseParams);
    const parsed = parsePartialFillScriptPQ(scriptHex);
    expect(parsed.paymentScriptPubKey.length).toBe(25); // P2PKH
  });

  it('sanity: standalone standard-script helpers are consistent with the builder', () => {
    // Keeps the old helper-level assertions as an invariant guard: if these
    // break, the end-to-end AuthScript test above will also break, but
    // isolated failures here pinpoint which piece regressed.
    const program = new Uint8Array(32).fill(0xab);
    const authScriptSpk = encodeAuthScriptScriptPubKey(program);
    expect(authScriptSpk[0]).toBe(0x51);
    expect(authScriptSpk[1]).toBe(0x20);
    expect(authScriptSpk.length).toBe(34);

    const spkP2PKH = encodeSellerScriptPubKey(TESTNET_P2PKH);
    expect(spkP2PKH.kind).toBe('p2pkh');
    expect(spkP2PKH.bytes.length).toBe(25);
  });
});

describe('parsePartialFillScriptPQ', () => {
  it('round-trips builder output', () => {
    const hex = buildPartialFillScriptPQHex(baseParams);
    const parsed = parsePartialFillScriptPQ(hex);
    expect(parsed.tokenId).toBe('CAT');
    expect(parsed.unitPriceSats).toBe(100_000_000n);
    expect(bytesToHex(parsed.pubKeyCommitment)).toBe('cc'.repeat(32));
    expect(parsed.txHashSelector).toBe(DEFAULT_PQ_TXHASH_SELECTOR);
    expect(parsed.paymentScriptPubKey.length).toBe(25); // P2PKH
  });

  it('round-trips a custom selector', () => {
    const hex = buildPartialFillScriptPQHex({ ...baseParams, txHashSelector: 0x3f });
    expect(parsePartialFillScriptPQ(hex).txHashSelector).toBe(0x3f);
  });

  it('rejects trailing bytes', () => {
    const hex = buildPartialFillScriptPQHex(baseParams) + 'ff';
    expect(() => parsePartialFillScriptPQ(hex)).toThrow(/trailing/);
  });

  it('refuses to parse a legacy (ECDSA) covenant', () => {
    // A legacy script starts `63 76 a9 ...` (OP_IF OP_DUP OP_HASH160), not
    // `63 76 a8 ...` (OP_IF OP_DUP OP_SHA256). Parser should fail fast.
    const legacyHead = '6376a914' + 'aa'.repeat(20);
    expect(() => parsePartialFillScriptPQ(legacyHead + '88ac')).toThrow();
  });
});

describe('isPartialFillScriptPQ (discriminator)', () => {
  it('returns true for a PQ covenant', () => {
    expect(isPartialFillScriptPQ(buildPartialFillScriptPQHex(baseParams))).toBe(true);
  });

  it('returns false for a legacy covenant head', () => {
    // Starts with OP_IF OP_DUP OP_HASH160 → not PQ.
    const legacyHead = '6376a914' + 'aa'.repeat(20) + '88ac67';
    expect(isPartialFillScriptPQ(legacyHead)).toBe(false);
  });

  it('returns false for unrelated scripts', () => {
    expect(isPartialFillScriptPQ('76a914' + 'bb'.repeat(20) + '88ac')).toBe(false);
  });
});

describe('legacy parser rejects PQ variant', () => {
  it('throws when fed a PQ script', () => {
    const pqHex = buildPartialFillScriptPQHex(baseParams);
    expect(() => parsePartialFillScript(pqHex)).toThrow();
  });
});

describe('buildCancelScriptSigPQ', () => {
  it('encodes <sig> <pubkey> OP_1 with PUSHDATA2 for PQ-sized elements', () => {
    // Simulated ML-DSA-44 dimensions.
    const sig = new Uint8Array(2421).fill(0x11);
    const pub = new Uint8Array(1313).fill(0x22);
    const hex = buildCancelScriptSigPQHex(sig, pub);

    // 2421 > 255 → PUSHDATA2 (0x4d + 2-byte LE length).
    // 2421 = 0x0975 → LE bytes 75 09.
    expect(hex.startsWith('4d7509' + '11'.repeat(2421))).toBe(true);
    // 1313 > 255 → PUSHDATA2. 1313 = 0x0521 → LE 21 05.
    expect(hex).toContain('4d2105' + '22'.repeat(1313));
    expect(hex.endsWith('51')).toBe(true); // OP_1 flag
  });

  it('rejects elements larger than MAX_PQ_SCRIPT_ELEMENT_SIZE', () => {
    const tooBig = new Uint8Array(3073);
    const ok = new Uint8Array(33);
    expect(() => buildCancelScriptSigPQHex(tooBig, ok)).toThrow(/exceeds MAX_PQ/);
    expect(() => buildCancelScriptSigPQHex(ok, tooBig)).toThrow(/exceeds MAX_PQ/);
  });
});

describe('encodeSellerScriptPubKey', () => {
  it('classifies a legacy testnet address as p2pkh with 25 bytes', () => {
    const out = encodeSellerScriptPubKey(TESTNET_P2PKH);
    expect(out.kind).toBe('p2pkh');
    expect(out.bytes.length).toBe(25);
    expect(out.hash.length).toBe(20);
    // Starts with OP_DUP OP_HASH160 push20
    expect(out.bytes[0]).toBe(0x76);
    expect(out.bytes[1]).toBe(0xa9);
    expect(out.bytes[2]).toBe(0x14);
    expect(out.bytes[out.bytes.length - 2]).toBe(0x88);
    expect(out.bytes[out.bytes.length - 1]).toBe(0xac);
  });
});
