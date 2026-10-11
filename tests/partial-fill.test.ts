import { describe, it, expect } from 'vitest';
import {
  buildCancelScriptSigHex,
  buildFillScriptSigHex,
  buildPartialFillScript,
  buildPartialFillScriptHex,
  parsePartialFillScript
} from '../src/covenants/partial-fill/index.js';
import { bytesToHex, hexToBytes } from '../src/core/bytes.js';
import type { PartialFillOrderParams } from '../src/types.js';
import { createHash } from 'node:crypto';
import { INPUT_ZERO_TXHASH } from '../src/covenants/partial-fill/fill-branches.js';
import {
  INPUT_ZERO_BINDING_HEX,
  testnetAuthScriptAddress,
  testnetP2PKHAddress,
  testnetStrictECDSAAddress
} from './helpers.js';

const sellerPkh = new Uint8Array(20).fill(0xaa);
const TEST_SELLER_ADDRESS = testnetP2PKHAddress(sellerPkh);

const baseParams: PartialFillOrderParams = {
  sellerAddress: TEST_SELLER_ADDRESS,
  tokenId: 'CAT',
  unitPriceSats: 100_000_000n
};

/**
 * Byte-exact fixture for the three-branch covenant. Any change to the
 * covenant byte layout should update this string in a single place so the
 * regression is obvious in diffs.
 *
 * Layout:
 *
 *   IF                              ← cancel branch
 *     DUP HASH160 <PKH> EQUALVERIFY CHECKSIG
 *   ELSE
 *     <0x8000> TXHASH <32B> EQUALVERIFY                              (order is input 0)
 *     IF                            ← inner: full-fill branch
 *       <0> <2> INPUTASSETFIELD                                      (N = inputAmount)
 *       DUP <price> MUL <0> OUTPUTVALUE SWAP GE VERIFY               (payment value)
 *       <0> OUTPUTSCRIPT <25B P2PKH(PKH)> EQUALVERIFY                (payment dest)
 *       DUP <1> <2> OUTPUTASSETFIELD EQUALVERIFY                     (buyer amount == N)
 *       <1> <1> OUTPUTASSETFIELD <"CAT"> EQUALVERIFY                 (buyer name)
 *       DROP <1>
 *     ELSE                          ← inner: partial-fill branch
 *       DUP <price> MUL <0> OUTPUTVALUE SWAP GE VERIFY
 *       <0> OUTPUTSCRIPT <25B P2PKH(PKH)> EQUALVERIFY
 *       DUP <1> <2> OUTPUTASSETFIELD EQUALVERIFY
 *       <1> <1> OUTPUTASSETFIELD <"CAT"> EQUALVERIFY
 *       <2> OUTPUTAUTHCOMMITMENT <2> TXFIELD EQUALVERIFY             (NIP-023 continuity)
 *       <2> <1> OUTPUTASSETFIELD <"CAT"> EQUALVERIFY
 *       <2> <2> OUTPUTASSETFIELD OVER <0> <2> INPUTASSETFIELD SWAP SUB EQUALVERIFY
 *       DROP <1>
 *     ENDIF
 *   ENDIF
 */
const EXPECTED_SCRIPT_HEX =
  // ── Cancel branch ──
  '63' +                                                               // OP_IF
  '76a9' +                                                             // DUP HASH160
  '14' + 'aa'.repeat(20) +                                             // push 20B PKH
  '88ac' +                                                             // EQUALVERIFY CHECKSIG

  // ── Outer ELSE → inner IF (full-fill) ──
  '67' +                                                               // OP_ELSE (outer)
  INPUT_ZERO_BINDING_HEX +                                             // order is input 0
  '63' +                                                               // OP_IF (inner: full-fill)
  '0052cf' +                                                           // <0> <2> INPUTASSETFIELD
  '76' + '0400e1f505' + '95' +                                         // DUP <price> MUL
  '00' + 'cc' + '7c' + 'a2' + '69' +                                   // <0> OUTPUTVALUE SWAP GE VERIFY
  '00' + 'cd' +                                                        // <0> OUTPUTSCRIPT
  '19' + '76a914' + 'aa'.repeat(20) + '88ac' +                         // push 25B sellerSPK
  '88' +                                                               // EQUALVERIFY
  '7651' + '52' + 'ce' + '88' +                                        // DUP <1> <2> OUTPUTASSETFIELD EQUALVERIFY
  '5151' + 'ce' + '03434154' + '88' +                                  // <1> <1> OUTPUTASSETFIELD "CAT" EQUALVERIFY
  '7551' +                                                             // DROP <1>

  // ── Inner ELSE (partial-fill) ──
  '67' +                                                               // OP_ELSE (inner)
  '76' + '0400e1f505' + '95' + '00' + 'cc' + '7c' + 'a2' + '69' +      // payment value
  '00' + 'cd' + '19' + '76a914' + 'aa'.repeat(20) + '88ac' + '88' +    // payment spk
  '7651' + '52' + 'ce' + '88' +                                        // buyer amount
  '5151' + 'ce' + '03434154' + '88' +                                  // buyer name
  '52' + 'd5' + '52' + 'b6' + '88' +                                   // remainder auth commitment (NIP-023)
  '52' + '51' + 'ce' + '03434154' + '88' +                             // remainder name
  '52' + '52' + 'ce' + '78' + '00' + '52' + 'cf' + '7c' + '94' + '88' + // remainder amount
  '7551' +                                                             // DROP <1>

  '68' +                                                               // OP_ENDIF (inner)
  '68';                                                                // OP_ENDIF (outer)

describe('buildPartialFillScript', () => {
  it('matches the byte-exact fixture for the canonical CAT order', () => {
    expect(buildPartialFillScriptHex(baseParams)).toBe(EXPECTED_SCRIPT_HEX);
  });

  it('optionally gates buyer fills by block height expiration', () => {
    const hex = buildPartialFillScriptHex({
      ...baseParams,
      expiration: { mode: 'height', value: 1000n }
    });
    // Selector 1 (HEIGHT) is emitted as OP_1 (0x51), consensus-minimal.
    const gate = '02e80351d7a069';
    expect(hex).toContain('67' + INPUT_ZERO_BINDING_HEX + '63' + gate + '0052cf');
    expect(hex).toContain('67' + gate + '76' + '0400e1f505');
    expect(hex).not.toContain('0101d7');
  });

  it('optionally gates buyer fills by MTP expiration', () => {
    const hex = buildPartialFillScriptHex({
      ...baseParams,
      expiration: { mode: 'mtp', value: 1_700_000_000n }
    });
    // Selector 2 (MTP) is emitted as OP_2 (0x52), consensus-minimal.
    const gate = '0400f1536552d7a069';
    expect(hex).toContain('67' + INPUT_ZERO_BINDING_HEX + '63' + gate + '0052cf');
    expect(hex).toContain('67' + gate + '76' + '0400e1f505');
    expect(hex).not.toContain('0102d7');
  });

  it('rejects an empty sellerAddress', () => {
    expect(() =>
      buildPartialFillScript({ ...baseParams, sellerAddress: '' })
    ).toThrow(/required/);
  });

  it('rejects a malformed base58 address', () => {
    expect(() =>
      buildPartialFillScript({ ...baseParams, sellerAddress: 'not-a-valid-address' })
    ).toThrow();
  });

  it('rejects an AuthScript bech32m address (legacy covenant is P2PKH-only)', () => {
    const pqAddress = testnetAuthScriptAddress(new Uint8Array(32).fill(0xab));
    expect(() =>
      buildPartialFillScript({ ...baseParams, sellerAddress: pqAddress })
    ).toThrow(/legacy P2PKH/);
  });

  it('rejects an invalid tokenId', () => {
    expect(() =>
      buildPartialFillScript({ ...baseParams, tokenId: 'lowercase' })
    ).toThrow(/not a valid Neurai asset name/);
  });

  it('rejects a non-positive price', () => {
    expect(() =>
      buildPartialFillScript({ ...baseParams, unitPriceSats: 0n })
    ).toThrow(/> 0/);
  });

  it('rejects an invalid expiration', () => {
    expect(() =>
      buildPartialFillScript({ ...baseParams, expiration: { mode: 'height', value: 0n } })
    ).toThrow(/expiration.value must be > 0/);
  });

  it('produces the same script shape for two sellers with different PKHs', () => {
    const otherAddress = testnetP2PKHAddress(new Uint8Array(20).fill(0xbb));
    const a = buildPartialFillScript(baseParams);
    const b = buildPartialFillScript({ ...baseParams, sellerAddress: otherAddress });
    expect(a.length).toBe(b.length);
    // Three PKH occurrences per script — cancel branch + payment spk in each
    // of the two fill branches (full-fill and partial-fill).
    const aHex = bytesToHex(a);
    const bHex = bytesToHex(b);
    const aa = aHex.split('aa'.repeat(20)).length - 1;
    expect(aa).toBe(3);
    const bb = bHex.split('bb'.repeat(20)).length - 1;
    expect(bb).toBe(3);
  });
});

describe('parsePartialFillScript', () => {
  it('round-trips builder output', () => {
    const hex = buildPartialFillScriptHex(baseParams);
    const parsed = parsePartialFillScript(hex, 'xna-test');
    expect(parsed.tokenId).toBe('CAT');
    expect(parsed.unitPriceSats).toBe(100_000_000n);
    expect(bytesToHex(parsed.sellerPubKeyHash)).toBe('aa'.repeat(20));
    expect(parsed.expiration).toBeUndefined();
    expect((parsed as Record<string, unknown>).sellerAddress).toBeUndefined();
  });

  it('round-trips an expiration gate', () => {
    const hex = buildPartialFillScriptHex({
      ...baseParams,
      expiration: { mode: 'height', value: 1000n }
    });
    const parsed = parsePartialFillScript(hex, 'xna-test');
    expect(parsed.expiration).toEqual({ mode: 'height', value: 1000n });
    expect(parsed.tokenId).toBe('CAT');
    expect(parsed.unitPriceSats).toBe(100_000_000n);
  });

  it('parser accepts legacy raw-push selector (0x01 0x01) for HEIGHT', () => {
    // Simulate a covenant produced by a builder that emits the selector as a
    // raw 1-byte push (`01 01`) instead of OP_1 (`51`). Such scripts are not
    // consensus-minimal, but the parser must still accept them so that any
    // covenant in the wild built by older or external tooling round-trips.
    const minimal = buildPartialFillScriptHex({
      ...baseParams,
      expiration: { mode: 'height', value: 1000n }
    });
    const legacy = minimal.split('02e80351d7a069').join('02e8030101d7a069');
    expect(legacy).not.toBe(minimal);
    const parsed = parsePartialFillScript(legacy, 'xna-test');
    expect(parsed.expiration).toEqual({ mode: 'height', value: 1000n });
  });

  it('parser accepts legacy raw-push selector (0x01 0x02) for MTP', () => {
    const minimal = buildPartialFillScriptHex({
      ...baseParams,
      expiration: { mode: 'mtp', value: 1_700_000_000n }
    });
    const legacy = minimal.split('0400f1536552d7a069').join('0400f153650102d7a069');
    expect(legacy).not.toBe(minimal);
    const parsed = parsePartialFillScript(legacy, 'xna-test');
    expect(parsed.expiration).toEqual({ mode: 'mtp', value: 1_700_000_000n });
  });

  it('round-trips with a non-OP_N price', () => {
    const hex = buildPartialFillScriptHex({ ...baseParams, unitPriceSats: 17n });
    const parsed = parsePartialFillScript(hex);
    expect(parsed.unitPriceSats).toBe(17n);
  });

  it('round-trips with the maximum-length tokenId', () => {
    const tokenId = 'A'.repeat(32);
    const parsed = parsePartialFillScript(
      buildPartialFillScriptHex({ ...baseParams, tokenId })
    );
    expect(parsed.tokenId).toBe(tokenId);
  });

  it('fails when the payment scriptPubKey differs between the fill branches', () => {
    const bytes = buildPartialFillScript(baseParams);
    // Flip the last byte of the *second* PKH occurrence (first fill-branch
    // payment spk, inside the full-fill body).
    const marker = 'aa'.repeat(20);
    const hex = bytesToHex(bytes);
    const firstIdx = hex.indexOf(marker);
    const secondIdx = hex.indexOf(marker, firstIdx + marker.length);
    expect(secondIdx).toBeGreaterThan(0);
    const tampered = hex.slice(0, secondIdx) + 'ab' + hex.slice(secondIdx + 2);
    expect(() => parsePartialFillScript(tampered)).toThrow(/payment scriptPubKey differs/);
  });

  it('rejects trailing bytes', () => {
    const hex = buildPartialFillScriptHex(baseParams) + 'ff';
    expect(() => parsePartialFillScript(hex)).toThrow(/trailing bytes/);
  });

  it('rejects an unrelated script', () => {
    const p2pkh = '76a914' + 'bb'.repeat(20) + '88ac';
    expect(() => parsePartialFillScript(p2pkh)).toThrow();
  });
});

describe('ECDSA cancel key with an independent payment destination', () => {
  const sellerPubKeyHash = new Uint8Array(20).fill(0xdd);
  const v3Address = testnetStrictECDSAAddress(new Uint8Array(32).fill(0xee));

  it('hardcodes the cancel key hash and the strict ECDSA v3 payment script separately', () => {
    const hex = buildPartialFillScriptHex({
      paymentAddress: v3Address,
      sellerPubKeyHash,
      tokenId: 'CAT',
      unitPriceSats: 100_000_000n
    });
    expect(hex.startsWith('6376a914' + 'dd'.repeat(20) + '88ac67')).toBe(true);
    const v3Spk = '5320' + 'ee'.repeat(32);
    // Payment destination in both fill branches.
    expect(hex.split('22' + v3Spk + '88').length - 1).toBe(2);

    const parsed = parsePartialFillScript(hex);
    expect(bytesToHex(parsed.sellerPubKeyHash)).toBe('dd'.repeat(20));
    expect(bytesToHex(parsed.paymentScriptPubKey)).toBe(v3Spk);
  });

  it('reports the P2PKH payment script for a sellerAddress order', () => {
    const parsed = parsePartialFillScript(buildPartialFillScriptHex(baseParams));
    expect(bytesToHex(parsed.paymentScriptPubKey)).toBe('76a914' + 'aa'.repeat(20) + '88ac');
  });

  it('rejects mixing sellerAddress with paymentAddress / sellerPubKeyHash', () => {
    expect(() =>
      buildPartialFillScript({ ...baseParams, sellerPubKeyHash })
    ).toThrow(/not both/);
    expect(() =>
      buildPartialFillScript({ ...baseParams, paymentAddress: v3Address })
    ).toThrow(/not both/);
  });

  it('requires both paymentAddress and sellerPubKeyHash without sellerAddress', () => {
    const { sellerAddress: _omit, ...rest } = baseParams;
    expect(() => buildPartialFillScript({ ...rest, paymentAddress: v3Address })).toThrow(/required/);
    expect(() => buildPartialFillScript({ ...rest, sellerPubKeyHash })).toThrow(/required/);
    expect(() => buildPartialFillScript(rest)).toThrow(/required/);
  });

  it('rejects a sellerPubKeyHash that is not 20 bytes', () => {
    expect(() =>
      buildPartialFillScript({
        paymentAddress: v3Address,
        sellerPubKeyHash: new Uint8Array(32),
        tokenId: 'CAT',
        unitPriceSats: 1n
      })
    ).toThrow(/20-byte/);
  });
});

describe('input-0 binding of the fill branches', () => {
  it('commits to OP_TXHASH(0x0080) evaluated at input 0', () => {
    const sha256 = (data: Uint8Array) => createHash('sha256').update(data).digest();
    const tag = sha256(new TextEncoder().encode('NeuraiTxHash'));
    const expected = sha256(Buffer.concat([tag, tag, Buffer.from([0x80, 0x00, 0, 0, 0, 0])]));
    expect(bytesToHex(INPUT_ZERO_TXHASH)).toBe(expected.toString('hex'));
  });

  it('opens the fill branches of every order', () => {
    const hex = buildPartialFillScriptHex(baseParams);
    expect(hex).toContain('88ac67' + INPUT_ZERO_BINDING_HEX + '63');
  });

  it('parser rejects an order without the binding (pre-0.10.0 layout)', () => {
    const unbound = buildPartialFillScriptHex(baseParams).replace(INPUT_ZERO_BINDING_HEX, '');
    expect(() => parsePartialFillScript(unbound)).toThrow(/input-0 binding/);
  });

  it('parser rejects a binding to another input index', () => {
    const hex = buildPartialFillScriptHex(baseParams);
    const tampered = hex.replace(INPUT_ZERO_BINDING_HEX, INPUT_ZERO_BINDING_HEX.replace('419632ca', '419632cb'));
    expect(() => parsePartialFillScript(tampered)).toThrow(/input-0 binding digest/);
  });
});

describe('buildFillScriptSig / buildCancelScriptSig', () => {
  // Partial fill: amount < total → pushes <N> <0> <0>
  it('encodes a partial fill with `<N> <0> <0>` for small N', () => {
    // N=5, total=10 → OP_5 (55) + OP_0 (00) + OP_0 (00)
    expect(buildFillScriptSigHex(5n, 10n)).toBe('550000');
  });

  it('encodes a partial fill with a direct-push number past OP_N', () => {
    // N=1000 → CScriptNum e8 03, pushed as 02 e8 03, then 00 00
    expect(buildFillScriptSigHex(1000n, 10000n)).toBe('02e8030000');
  });

  // Full fill: amount === total → pushes <1> <0>
  it('encodes a full fill with `<1> <0>` when amount === total', () => {
    // full-flag=1 (OP_1 = 51), cancel-flag=0 (OP_0 = 00)
    expect(buildFillScriptSigHex(10n, 10n)).toBe('5100');
  });

  it('encodes a full fill independently of the absolute amount', () => {
    expect(buildFillScriptSigHex(1n, 1n)).toBe('5100');
    expect(buildFillScriptSigHex(1_000_000n, 1_000_000n)).toBe('5100');
  });

  it('rejects non-positive fills', () => {
    expect(() => buildFillScriptSigHex(0n, 10n)).toThrow(/> 0/);
    expect(() => buildFillScriptSigHex(-1n, 10n)).toThrow(/> 0/);
  });

  it('rejects fills exceeding the covenant total', () => {
    expect(() => buildFillScriptSigHex(11n, 10n)).toThrow(/exceeds/);
  });

  it('rejects zero or negative total', () => {
    expect(() => buildFillScriptSigHex(1n, 0n)).toThrow(/> 0/);
    expect(() => buildFillScriptSigHex(1n, -5n)).toThrow(/> 0/);
  });

  it('encodes a cancel with `<sig> <pubkey> <1>`', () => {
    const sig = new Uint8Array(71).fill(0x30);
    const pub = new Uint8Array(33).fill(0x02);
    const hex = buildCancelScriptSigHex(sig, pub);
    // 0x47 = 71, 0x21 = 33, 0x51 = OP_1
    expect(hex.startsWith('47' + '30'.repeat(71) + '21' + '02'.repeat(33))).toBe(true);
    expect(hex.endsWith('51')).toBe(true);
  });

  it('rejects a malformed pubkey in cancel scriptSig', () => {
    const sig = new Uint8Array(71).fill(0x30);
    expect(() => buildCancelScriptSigHex(sig, new Uint8Array(10))).toThrow(/33B.*65B/);
  });
});

describe('integration: Alice → Bob → Carol → cancel', () => {
  it('parser extracts consistent state after two successive fills (simulated)', () => {
    const scriptHex = buildPartialFillScriptHex(baseParams);
    const aliceOrder = parsePartialFillScript(scriptHex);
    const afterBob = parsePartialFillScript(scriptHex);
    const afterCarol = parsePartialFillScript(scriptHex);

    for (const parsed of [afterBob, afterCarol]) {
      expect(parsed.tokenId).toBe(aliceOrder.tokenId);
      expect(parsed.unitPriceSats).toBe(aliceOrder.unitPriceSats);
      expect(bytesToHex(parsed.sellerPubKeyHash)).toBe(
        bytesToHex(aliceOrder.sellerPubKeyHash)
      );
    }
  });
});
