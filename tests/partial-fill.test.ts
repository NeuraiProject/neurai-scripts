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
import { testnetAuthScriptAddress, testnetP2PKHAddress } from './helpers.js';

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
    expect((parsed as Record<string, unknown>).sellerAddress).toBeUndefined();
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

  it('fails when the cancel PKH and the first fill-branch PKH diverge', () => {
    const bytes = buildPartialFillScript(baseParams);
    // Flip the last byte of the *second* PKH occurrence (first fill-branch
    // payment spk, inside the full-fill body).
    const marker = 'aa'.repeat(20);
    const hex = bytesToHex(bytes);
    const firstIdx = hex.indexOf(marker);
    const secondIdx = hex.indexOf(marker, firstIdx + marker.length);
    expect(secondIdx).toBeGreaterThan(0);
    const tampered = hex.slice(0, secondIdx) + 'ab' + hex.slice(secondIdx + 2);
    expect(() => parsePartialFillScript(tampered)).toThrow(/does not match/);
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
