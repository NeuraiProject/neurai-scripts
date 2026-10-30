import { describe, expect, it } from 'vitest';
import {
  assetAuthProposalHash,
  buildAssetAuthArgs,
  buildAssetAuthPolicyScript,
  buildAssetAuthProposalMessage,
  buildAssetAuthVoteExecuteArgs,
  buildAssetAuthVoteLockScript,
  buildAssetAuthVoteReturnArgs,
  bytesToHex,
  hexToBytes,
  opcodes,
  parseAssetAuthPolicyScript
} from '../src/index.js';

const hex = (items: Uint8Array[]) => items.map(bytesToHex);
const ascii = (s: string) => bytesToHex(new TextEncoder().encode(s));

describe('P2AH policy script (NIP-054)', () => {
  it('lists the roles sorted by bytes, with small numbers as OP_n', () => {
    const script = buildAssetAuthPolicyScript({ M: 1, G: 2, roles: ['ROLEB!', 'ROLEA!'] });
    expect(bytesToHex(script)).toBe(
      '515152' + '06' + ascii('ROLEA!') + '06' + ascii('ROLEB!') + '52' + 'df'
    );
    expect(opcodes.OP_CHECKASSETAUTH).toBe(0xdf);
  });

  it('parses back what it builds, DEPIN owners included', () => {
    const policy = { M: 2, G: 3, roles: ['&DEVICE!', 'BOARD!', 'ADMIN!'] };
    const parsed = parseAssetAuthPolicyScript(buildAssetAuthPolicyScript(policy));
    expect(parsed).toEqual({ M: 2, G: 3, roles: ['&DEVICE!', 'ADMIN!', 'BOARD!'] });
  });

  it('rejects a role list the node would reject', () => {
    expect(() => parseAssetAuthPolicyScript(hexToBytes('515151' + '06' + ascii('ROLEB!') + '06' + ascii('ROLEA!') + '52df'))).toThrow(
      /strictly increasing/
    );
    expect(() => parseAssetAuthPolicyScript(hexToBytes('525151' + '06' + ascii('ROLEA!') + '51df'))).toThrow(/version/);
    expect(() => parseAssetAuthPolicyScript(hexToBytes('515151' + '06' + ascii('ROLEA!') + '52df'))).toThrow(/role count/);
    expect(() => parseAssetAuthPolicyScript(hexToBytes('51ac'))).toThrow(/not an OP_CHECKASSETAUTH/);
  });

  it.each([
    [{ M: 0, G: 1, roles: ['A!'] }, /1 <= M <= G <= 1/],
    [{ M: 2, G: 1, roles: ['A!', 'B!'] }, /1 <= M <= G <= 2/],
    [{ M: 1, G: 3, roles: ['A!', 'B!'] }, /1 <= M <= G <= 2/],
    [{ M: 1, G: 1, roles: ['A!', 'A!'] }, /listed twice/],
    [{ M: 1, G: 1, roles: ['GOLD'] }, /not an owner token/],
    [{ M: 1, G: 1, roles: [] }, /1 to 16/],
    [{ M: 1, G: 1, roles: Array.from({ length: 17 }, (_, i) => `R${i}!`) }, /1 to 16/]
  ])('rejects %j', (policy, error) => {
    expect(() => buildAssetAuthPolicyScript(policy)).toThrow(error);
  });
});

describe('P2AH custody arguments', () => {
  it('are minimal script numbers, 0 as the empty element', () => {
    expect(hex(buildAssetAuthArgs())).toEqual(['', '', '', '']);
    expect(hex(buildAssetAuthArgs({ c: 1, a: 2, T: 1000 }))).toEqual(['01', '02', '', 'e803']);
    expect(hex(buildAssetAuthArgs({ T: 0x7fffffff }))).toEqual(['', '', '', 'ffffff7f']);
  });

  it('reject what does not fit a 4-byte script number', () => {
    expect(() => buildAssetAuthArgs({ T: 0x80000000 })).toThrow(/T must be/);
    expect(() => buildAssetAuthArgs({ c: -1 })).toThrow(/c must be/);
    expect(() => buildAssetAuthArgs({ a: 1.5 })).toThrow(/a must be/);
  });
});

describe('P2AH proposal hash', () => {
  // The node's proposal_hash_vectors (src/test/assetauth_tests.cpp): inputs
  // 00..11:1 (final) and 00..22:0 (final - 1); outputs 9 XNA, 0.04 XNA and
  // 1 XNA to P2PKH e0.., b1.., e1..; c = a = b = 1, T = 1000.
  const p2pkh = (byte: string) => '1976a914' + byte.repeat(20) + '88ac';
  const RAW_TX =
    '02000000' + '02' +
    '11' + '00'.repeat(31) + '01000000' + '00' + 'ffffffff' +
    '22' + '00'.repeat(31) + '00000000' + '00' + 'feffffff' +
    '03' +
    '00e9a43500000000' + p2pkh('e0') +
    '00093d0000000000' + p2pkh('b1') +
    '00e1f50500000000' + p2pkh('e1') +
    '00000000';
  const proposal = { rawTx: RAW_TX, c: 1, a: 1, b: 1, T: 1000 };

  it('serializes m as the node does', () => {
    expect(bytesToHex(buildAssetAuthProposalMessage({ ...proposal, chain: 'regtest' }))).toBe(
      '02' + '02000000' + '00000000' + 'e8030000' + '010101' +
        '11' + '00'.repeat(31) + '01000000' + 'ffffffff' +
        '00e9a43500000000' + p2pkh('e0') +
        '00e1f50500000000' + p2pkh('e1') +
        '00'
    );
  });

  it.each([
    ['mainnet', '98c900705cdb1f6703248f117f2026850b2a27c93043c688102bbcc0e5525308'],
    ['testnet', 'ff8d6c87e36de48e0af7293fce80d076c4d0b48ba625def71e022e460f72417e'],
    ['regtest', '90ce27337ba58ba0e6f7e06e7fd7dde2841bed637109d63a73336c9de42b245f']
  ] as const)('matches the node vector on %s', (chain, expected) => {
    expect(bytesToHex(assetAuthProposalHash({ ...proposal, chain }))).toBe(expected);
  });

  it('ignores the inputs from c on and the outputs between prefix and suffix', () => {
    const skeleton =
      '02000000' + '01' + '11' + '00'.repeat(31) + '01000000' + '00' + 'ffffffff' +
      '02' + '00e9a43500000000' + p2pkh('e0') + '00e1f50500000000' + p2pkh('e1') + '00000000';
    expect(bytesToHex(assetAuthProposalHash({ ...proposal, rawTx: skeleton, chain: 'testnet' }))).toBe(
      'ff8d6c87e36de48e0af7293fce80d076c4d0b48ba625def71e022e460f72417e'
    );
  });

  it('refuses ranges outside the transaction', () => {
    expect(() => assetAuthProposalHash({ ...proposal, c: 3, chain: 'regtest' })).toThrow(/c \(3\) exceeds/);
    expect(() => assetAuthProposalHash({ ...proposal, a: 2, b: 2, chain: 'regtest' })).toThrow(/a \+ b \(4\) exceeds/);
    expect(() => assetAuthProposalHash({ ...proposal, chain: 'signet' as never })).toThrow(/unknown chain/);
  });
});

describe('P2AH vote lock', () => {
  const C = 'ab'.repeat(32);
  const RETURN = '76a914' + 'cd'.repeat(20) + '88ac';

  it('identifies the custody by its full destination and returns the token on both branches', () => {
    const script = buildAssetAuthVoteLockScript({ T: 300, custodyCommitment: C, returnScriptPubKey: RETURN });
    const T = '022c01';
    expect(bytesToHex(script)).toBe(
      '63' +
        '51d7' + T + 'a169' +
        '7c54c4' + '21' + '01' + C + '88' +
        'cd' + '19' + RETURN + '87' +
      '67' +
        '51d7' + T + 'a069' +
        '77cd' + '19' + RETURN + '87' +
      '68'
    );
  });

  it('builds the arguments of both branches', () => {
    expect(hex(buildAssetAuthVoteExecuteArgs({ custodyInput: 0, returnOutput: 2 }))).toEqual(['', '02', '01']);
    expect(hex(buildAssetAuthVoteReturnArgs({ returnOutput: 0 }))).toEqual(['', '', '']);
  });

  it('rejects a commitment that is not 32 bytes', () => {
    expect(() => buildAssetAuthVoteLockScript({ T: 1, custodyCommitment: 'ab', returnScriptPubKey: RETURN })).toThrow(
      /32 bytes/
    );
  });
});
