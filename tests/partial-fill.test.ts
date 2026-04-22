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
 * Byte-exact fixture. Any change to the covenant byte layout should update
 * this string in a single place so the regression is obvious in diffs.
 * The PKH inside the script is still `aa * 20`; only the input form
 * changed from raw PKH to `sellerAddress`.
 *
 * Layout (hand-computed once, do not edit without reading the comment in
 * src/covenants/partial-fill/script.ts):
 *
 *   IF
 *     DUP HASH160 <PKH=aa*20> EQUALVERIFY CHECKSIG
 *   ELSE
 *     DUP <0400e1f505=100_000_000> MUL <0> OUTPUTVALUE SWAP GE VERIFY
 *     <0> OUTPUTSCRIPT <25B P2PKH(PKH)> EQUALVERIFY
 *     DUP <1> <2> OUTPUTASSETFIELD EQUALVERIFY
 *     <1> <1> OUTPUTASSETFIELD <"CAT"> EQUALVERIFY
 *     <2> OUTPUTAUTHCOMMITMENT <2> TXFIELD EQUALVERIFY  (NIP-023)
 *     <2> <1> OUTPUTASSETFIELD <"CAT"> EQUALVERIFY
 *     <2> <2> OUTPUTASSETFIELD OVER <0> <2> INPUTASSETFIELD SWAP SUB EQUALVERIFY
 *     DROP <1>
 *   ENDIF
 */
const EXPECTED_SCRIPT_HEX =
  '63' +                                                               // OP_IF
  '76a9' +                                                             // DUP HASH160
  '14' + 'aa'.repeat(20) +                                             // push PKH
  '88ac' +                                                             // EQUALVERIFY CHECKSIG
  '67' +                                                               // OP_ELSE
  '76' +                                                               // OP_DUP
  '0400e1f505' +                                                       // push 100_000_000
  '95' + '00' + 'cc' + '7c' + 'a2' + '69' +                            // MUL 0 OUTPUTVALUE SWAP GE VERIFY
  '00' + 'cd' +                                                        // 0 OUTPUTSCRIPT
  '19' + '76a914' + 'aa'.repeat(20) + '88ac' +                         // push sellerScriptPubKey (25B)
  '88' +                                                               // EQUALVERIFY
  '76' + '51' + '52' + 'ce' + '88' +                                   // DUP 1 2 OUTPUTASSETFIELD EQUALVERIFY
  '51' + '51' + 'ce' + '03434154' + '88' +                             // 1 1 OUTPUTASSETFIELD <"CAT"> EQUALVERIFY
  '52' + 'd5' + '52' + 'b6' + '88' +                                   // 2 OUTPUTAUTHCOMMITMENT 2 TXFIELD EQUALVERIFY (NIP-023)
  '52' + '51' + 'ce' + '03434154' + '88' +                             // 2 1 OUTPUTASSETFIELD <"CAT"> EQUALVERIFY
  '52' + '52' + 'ce' + '78' + '00' + '52' + 'cf' + '7c' + '94' + '88' +
  '75' + '51' +                                                        // DROP 1
  '68';                                                                // ENDIF

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
    // Exactly two PKH occurrences in the script (cancel branch + payment spk).
    const aHex = bytesToHex(a);
    const bHex = bytesToHex(b);
    const aa = aHex.split('aa'.repeat(20)).length - 1;
    expect(aa).toBe(2);
    const bb = bHex.split('bb'.repeat(20)).length - 1;
    expect(bb).toBe(2);
  });
});

describe('parsePartialFillScript', () => {
  it('round-trips builder output', () => {
    const hex = buildPartialFillScriptHex(baseParams);
    const parsed = parsePartialFillScript(hex, 'xna-test');
    expect(parsed.tokenId).toBe('CAT');
    expect(parsed.unitPriceSats).toBe(100_000_000n);
    expect(bytesToHex(parsed.sellerPubKeyHash)).toBe('aa'.repeat(20));
    // Parser does not synthesize an address string from the PKH.
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

  it('fails when the cancel PKH and payment PKH diverge', () => {
    const bytes = buildPartialFillScript(baseParams);
    // Flip the last byte of the *second* PKH (inside the payment-spk push).
    // The second occurrence starts later in the script; find it by scanning.
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
    // A bare P2PKH, not a partial-fill covenant.
    const p2pkh = '76a914' + 'bb'.repeat(20) + '88ac';
    expect(() => parsePartialFillScript(p2pkh)).toThrow();
  });
});

describe('buildFillScriptSig / buildCancelScriptSig', () => {
  it('encodes a fill with `<N> <0>` for small N', () => {
    // N=5 → OP_5 = 0x55, then OP_0 = 0x00
    expect(buildFillScriptSigHex(5n)).toBe('5500');
  });

  it('encodes a fill with a direct-push number past OP_N', () => {
    // N=1000 → CScriptNum e8 03, pushed as 02 e8 03, then OP_0 = 00
    expect(buildFillScriptSigHex(1000n)).toBe('02e80300');
  });

  it('rejects non-positive fills', () => {
    expect(() => buildFillScriptSigHex(0n)).toThrow(/> 0/);
    expect(() => buildFillScriptSigHex(-1n)).toThrow(/> 0/);
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
    // The script is self-replicating: both Bob's fill and Carol's fill
    // spend a covenant whose scriptPubKey bytes are IDENTICAL. This test
    // asserts exactly that: parsing the original order and parsing a
    // "virtual remainder" (same bytes) yields the same parameters.
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
