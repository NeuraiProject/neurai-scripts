import { describe, it, expect } from 'vitest';
import { splitAssetWrappedScriptPubKey } from '../src/index.js';

// Real testnet UTXOs captured via neurai-cli -testnet getaddressutxos on
// block 12814. Used as golden fixtures: any regression in the split will
// fail these first.
const REAL_PQ_TREST_SPK =
  '51201592eed3297863e3cf37dcd9ebc71b672e43f5e27f5d4bb08d8c79ad77fc3a2e' + // OP_1 OP_PUSHBYTES_32 <program>
  'c0' + // OP_XNA_ASSET
  '12' + // pushdata(18)
  '72766e74' + // "rvn" + transfer marker
  '0554524553' + '54' + // VarStr("TREST") = len5 + "TREST"
  '00e40b5402000000' + // int64LE(10_000_000_000)
  '75'; // OP_DROP
const REAL_PQ_PREFIX =
  '51201592eed3297863e3cf37dcd9ebc71b672e43f5e27f5d4bb08d8c79ad77fc3a2e';

const REAL_LEGACY_TREST_SPK =
  '76a914d57bac106ec4abbf707d4056444cd3e9f9659ec388ac' + // OP_DUP OP_HASH160 <pkh20> OP_EQUALVERIFY OP_CHECKSIG
  'c0' + '12' + '72766e7405545245535400e40b540200000075';
const REAL_LEGACY_PREFIX = '76a914d57bac106ec4abbf707d4056444cd3e9f9659ec388ac';

describe('splitAssetWrappedScriptPubKey — real testnet fixtures', () => {
  it('splits a PQ (witness v1) asset-wrapped UTXO into prefix + TREST transfer', () => {
    const result = splitAssetWrappedScriptPubKey(REAL_PQ_TREST_SPK);
    expect(result.prefixHex).toBe(REAL_PQ_PREFIX);
    expect(result.assetTransfer).not.toBeNull();
    expect(result.assetTransfer?.assetName).toBe('TREST');
    expect(result.assetTransfer?.amountRaw).toBe(10_000_000_000n);
    expect(result.assetTransfer?.payloadHex).toBe(
      '72766e7405545245535400e40b5402000000'
    );
  });

  it('splits a legacy P2PKH asset-wrapped UTXO into prefix + TREST transfer', () => {
    const result = splitAssetWrappedScriptPubKey(REAL_LEGACY_TREST_SPK);
    expect(result.prefixHex).toBe(REAL_LEGACY_PREFIX);
    expect(result.assetTransfer).not.toBeNull();
    expect(result.assetTransfer?.assetName).toBe('TREST');
    expect(result.assetTransfer?.amountRaw).toBe(10_000_000_000n);
  });
});

describe('splitAssetWrappedScriptPubKey — bare scriptPubKeys', () => {
  it('round-trips a bare P2PKH (no wrapper)', () => {
    const result = splitAssetWrappedScriptPubKey(REAL_LEGACY_PREFIX);
    expect(result.prefixHex).toBe(REAL_LEGACY_PREFIX);
    expect(result.assetTransfer).toBeNull();
  });

  it('round-trips a bare AuthScript v1 (no wrapper)', () => {
    const result = splitAssetWrappedScriptPubKey(REAL_PQ_PREFIX);
    expect(result.prefixHex).toBe(REAL_PQ_PREFIX);
    expect(result.assetTransfer).toBeNull();
  });

  it('handles an empty script', () => {
    const result = splitAssetWrappedScriptPubKey('');
    expect(result.prefixHex).toBe('');
    expect(result.assetTransfer).toBeNull();
  });
});

describe('splitAssetWrappedScriptPubKey — payload with optional tail', () => {
  // Build a synthetic wrapper with a non-empty message + expireTime tail.
  // The helper must parse assetName + amountRaw correctly and ignore the
  // trailing bytes (exposing them only via payloadHex).
  //
  // payload layout:
  //   rvn|t || len(3) || "CAT" || int64LE(50000) || 32 bytes of "message" ||
  //   int64LE(expireTime)
  function buildWrappedWithTail(): string {
    const prefix = REAL_LEGACY_PREFIX;
    const name = 'CAT';
    const nameLen = name.length.toString(16).padStart(2, '0');
    const nameHex = Buffer.from(name, 'ascii').toString('hex');
    const amountLE = '50c3000000000000'; // int64LE(50000)
    const messageRef = 'aa'.repeat(32);
    const expireLE = 'f0f1f2f3f4f5f6f7';
    const payloadHex = '72766e74' + nameLen + nameHex + amountLE + messageRef + expireLE;
    const payloadLen = (payloadHex.length / 2).toString(16).padStart(2, '0');
    return prefix + 'c0' + payloadLen + payloadHex + '75';
  }

  it('tolerates optional message + expireTime tail after amountRaw', () => {
    const spk = buildWrappedWithTail();
    const result = splitAssetWrappedScriptPubKey(spk);
    expect(result.prefixHex).toBe(REAL_LEGACY_PREFIX);
    expect(result.assetTransfer?.assetName).toBe('CAT');
    expect(result.assetTransfer?.amountRaw).toBe(50_000n);
    // Full payload including tail is preserved for consumers that want it.
    expect(result.assetTransfer?.payloadHex).toContain('aa'.repeat(32));
    expect(result.assetTransfer?.payloadHex).toContain('f0f1f2f3f4f5f6f7');
  });
});

describe('splitAssetWrappedScriptPubKey — malformed inputs', () => {
  it('throws on wrapper missing trailing OP_DROP', () => {
    // Trim the final 0x75 (OP_DROP).
    const truncated = REAL_PQ_TREST_SPK.slice(0, -2);
    expect(() => splitAssetWrappedScriptPubKey(truncated)).toThrow(/OP_DROP/);
  });

  it('throws on wrapper with trailing bytes after OP_DROP', () => {
    const withTrail = REAL_PQ_TREST_SPK + 'de';
    expect(() => splitAssetWrappedScriptPubKey(withTrail)).toThrow(/trailing/);
  });

  it('throws on payload shorter than the minimum transfer layout', () => {
    // OP_XNA_ASSET + pushdata(4) + "rvnx" + OP_DROP — too short, even with
    // correct prefix bytes.
    const spk = REAL_LEGACY_PREFIX + 'c0' + '04' + '72766e78' + '75';
    expect(() => splitAssetWrappedScriptPubKey(spk)).toThrow(/too short/);
  });

  it('throws on wrong magic', () => {
    // "xyz" + type 0x74 + varstr "AAA" + 8-byte amount
    const badPayload =
      '78797a74' + '03' + '414141' + '0000000000000000';
    const len = (badPayload.length / 2).toString(16).padStart(2, '0');
    const spk = REAL_LEGACY_PREFIX + 'c0' + len + badPayload + '75';
    expect(() => splitAssetWrappedScriptPubKey(spk)).toThrow(/magic mismatch/);
  });

  it('throws on wrong type marker (not transfer)', () => {
    // "rvn" + 0x71 (qualifier) + varstr "ABC" + 8-byte amount
    const badPayload =
      '72766e71' + '03' + '414243' + '0000000000000000';
    const len = (badPayload.length / 2).toString(16).padStart(2, '0');
    const spk = REAL_LEGACY_PREFIX + 'c0' + len + badPayload + '75';
    expect(() => splitAssetWrappedScriptPubKey(spk)).toThrow(/transfer/);
  });

  it('throws on truncated PUSHDATA1 length header', () => {
    // OP_PUSHDATA1 with no following length byte.
    const spk = REAL_LEGACY_PREFIX.slice(0, -4) + '4c';
    expect(() => splitAssetWrappedScriptPubKey(spk)).toThrow(/PUSHDATA1/);
  });

  it('throws on short push that would run past end of script', () => {
    // Prefix bytes 1..10: "01 ff" would declare a 1-byte push but with
    // length 0xff demanding 255 bytes. We keep the prefix but inject the
    // bad push at the very start so we exercise findTopLevelAssetOpcode.
    const spk = 'ff';
    // Actually `ff` is OP_INVALIDOPCODE at top level — not a push.
    // Instead use `01` (push 1 byte) with no payload:
    const spk2 = '01';
    expect(() => splitAssetWrappedScriptPubKey(spk2)).toThrow(/exceeds script length/);
  });

  it('does NOT mistake a 0xc0 byte inside a pushdata for OP_XNA_ASSET', () => {
    // Build a prefix that includes 0xc0 inside a push element. The walker
    // must skip it. We then append a real wrapper so the split still works.
    const innocentPrefix =
      '04' + 'c0c0c0c0' + // pushdata 4 bytes, all 0xc0
      '76' + 'a9' + '14' + 'd57bac106ec4abbf707d4056444cd3e9f9659ec3' + '88' + 'ac'; // then a real P2PKH
    const spk =
      innocentPrefix +
      'c0' + '12' + '72766e7405545245535400e40b540200000075';
    const result = splitAssetWrappedScriptPubKey(spk);
    expect(result.prefixHex).toBe(innocentPrefix);
    expect(result.assetTransfer?.assetName).toBe('TREST');
    expect(result.assetTransfer?.amountRaw).toBe(10_000_000_000n);
  });
});
