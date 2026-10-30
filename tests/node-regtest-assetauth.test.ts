import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getNoAuthAddress } from '@neuraiproject/neurai-key';
import {
  createAssetTransferOutput,
  createTransferWithMessageOutput,
  createUnsignedTransaction,
  createXnaOutput,
  parseTransaction,
  serializeTransaction,
  xnaToSatoshis
} from '@neuraiproject/neurai-create-transaction';
import {
  assetAuthProposalHash,
  buildAssetAuthArgs,
  buildAssetAuthPolicyScript,
  buildAssetAuthVoteExecuteArgs,
  buildAssetAuthVoteLockScript,
  buildAssetAuthVoteReturnArgs,
  buildAuthScriptWitnessNoAuth,
  bytesToHex
} from '../src/index.js';
import type { AssetAuthArgs } from '../src/index.js';

// End-to-end NIP-054 vectors (OP_CHECKASSETAUTH is active from block 0 on
// regtest): a P2AH custody built with buildAssetAuthPolicyScript holds an
// asset; it is spent by a direct owner-token signature (synchronous) and by a
// vote locked in buildAssetAuthVoteLockScript, carrying the hash from
// assetAuthProposalHash (asynchronous). The node wallet signs the P2PKH
// inputs; the NoAuth inputs get their witness from this library.
//
// Needs a node with NIP-054 (Neurai c665ba3 or later), in the container
// NEURAI_REGTEST_CONTAINER or at NEURAID_BIN / NEURAI_CLI_BIN.
const CONTAINER = process.env.NEURAI_REGTEST_CONTAINER ?? 'neurai-wt2';
const CONTAINER_NEURAID = process.env.NEURAI_REGTEST_CONTAINER_NEURAID ?? '/root/Neurai/src/neuraid';
const CONTAINER_CLI = process.env.NEURAI_REGTEST_CONTAINER_CLI ?? '/root/Neurai/src/neurai-cli';
const LOCAL_NEURAID = process.env.NEURAID_BIN ?? '';
const LOCAL_CLI = process.env.NEURAI_CLI_BIN ?? '';

function dockerAvailable(): boolean {
  try {
    return (
      execFileSync('docker', ['inspect', '-f', '{{.State.Running}}', CONTAINER], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
      }).trim() === 'true'
    );
  } catch {
    return false;
  }
}

const MODE: 'docker' | 'local' | 'skip' = dockerAvailable()
  ? 'docker'
  : LOCAL_NEURAID && LOCAL_CLI && existsSync(LOCAL_NEURAID) && existsSync(LOCAL_CLI)
    ? 'local'
    : 'skip';

const COIN = 100_000_000n;
const FEE = xnaToSatoshis(0.01);
const RPC_PORT = 31000 + (process.pid % 9000);
const DATADIR = `/tmp/neurai-regtest-assetauth-${process.pid}`;
const NODE_ARGS = ['-regtest', `-datadir=${DATADIR}`, '-rpcuser=t', '-rpcpassword=t', `-rpcport=${RPC_PORT}`];
const NETWORK = 'xna-authscript-test';

function sh(args: string[], allowFail = false): string {
  const [bin, ...rest] = MODE === 'docker' ? ['docker', 'exec', CONTAINER, ...args] : args;
  try {
    return execFileSync(bin, rest, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    if (allowFail) return '';
    throw error;
  }
}

const cli = (...args: Array<string | number>) =>
  sh([MODE === 'docker' ? CONTAINER_CLI : LOCAL_CLI, ...NODE_ARGS, ...args.map(String)]);
const cliJson = (...args: Array<string | number>) => JSON.parse(cli(...args));

interface Utxo {
  txid: string;
  vout: number;
  satoshis: bigint;
}

function assetUtxo(address: string, assetName: string): Utxo {
  const [u] = cliJson('getaddressutxos', JSON.stringify({ addresses: [address], assetName }));
  if (!u) throw new Error(`no ${assetName} utxo at ${address}`);
  return { txid: u.txid, vout: u.outputIndex, satoshis: BigInt(u.satoshis) };
}

/** A fresh XNA output of the node wallet, so every transaction has its own fee input. */
function feeUtxo(): Utxo {
  const address = cli('getnewaddress');
  const txid = cli('sendtoaddress', address, 1);
  // Read while it is in the mempool: this node runs without -txindex.
  const vout = cliJson('getrawtransaction', txid, 1).vout.find((o: any) => o.scriptPubKey.addresses?.[0] === address).n;
  cli('generate', 1);
  return { txid, vout, satoshis: COIN };
}

/**
 * The node wallet signs the P2PKH inputs (it cannot sign the NoAuth ones);
 * then each NoAuth input gets its witness. P2PKH signatures (SIGHASH_ALL) do
 * not cover witnesses, so the order does not matter.
 */
function finish(rawTx: string, witnesses: Record<number, Uint8Array[]>): { allowed: boolean; reason?: string; hex: string } {
  const signed = parseTransaction(cliJson('signrawtransaction', rawTx).hex);
  for (const [index, stack] of Object.entries(witnesses)) {
    signed.inputs[Number(index)].witness = stack.map(bytesToHex);
  }
  const hex = serializeTransaction(signed);
  const [result] = cliJson('testmempoolaccept', JSON.stringify([hex]), 'true');
  return { allowed: Boolean(result.allowed), reason: result['reject-reason'], hex };
}

function mine(hex: string): string {
  const txid = cli('sendrawtransaction', hex, 'true');
  cli('generate', 1);
  return txid;
}

describe.skipIf(MODE === 'skip')('P2AH custody e2e (NIP-054 OP_CHECKASSETAUTH)', () => {
  let marker: 'rvn' | 'xna';
  let OWNER = '';
  let D = '';
  const policy = buildAssetAuthPolicyScript({ M: 1, G: 2, roles: ['AAROLEB!', 'AAROLEA!'] });
  const custody = getNoAuthAddress(NETWORK, { witnessScript: policy });

  beforeAll(async () => {
    const neuraid = MODE === 'docker' ? CONTAINER_NEURAID : LOCAL_NEURAID;
    sh(['rm', '-rf', DATADIR]);
    sh(['mkdir', '-p', DATADIR]);
    sh([neuraid, ...NODE_ARGS, '-daemon', '-server=1', '-listen=0', '-assetindex=1', '-addressindex=1', `-port=${RPC_PORT + 1}`]);
    let ready = false;
    for (let attempt = 0; attempt < 60 && !ready; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      try {
        cli('getblockcount');
        ready = true;
      } catch {
        // RPC not up yet
      }
    }
    if (!ready) throw new Error('neuraid did not come up');
    cli('generate', 150);
    marker = cliJson('getblockchaininfo').asset_marker;
    OWNER = cli('getnewaddress');
    D = cli('getnewaddress');
    cli('issue', 'AAROLEA', 1, OWNER);
    cli('issue', 'AAROLEB', 1, OWNER);
    cli('issue', 'AAVAULT', 100);
    cli('generate', 1);
    cli('transfer', 'AAVAULT', 100, custody.address);
    cli('generate', 1);
  }, 180_000);

  afterAll(() => {
    try {
      cli('stop');
    } catch {
      // daemon already gone
    }
    sh(['rm', '-rf', DATADIR], true);
  });

  const custodyWitness = (args?: Partial<AssetAuthArgs>) =>
    buildAuthScriptWitnessNoAuth({ args: buildAssetAuthArgs(args), witnessScript: policy });

  it('spends the custody with a direct owner-token signature (synchronous)', () => {
    const vault = assetUtxo(custody.address, 'AAVAULT');
    const role = assetUtxo(OWNER, 'AAROLEA!');
    const fee = feeUtxo();
    const spend = (withRole: boolean) =>
      finish(
        createUnsignedTransaction({
          inputs: [vault, ...(withRole ? [role] : []), fee],
          outputs: [
            createAssetTransferOutput(D, 'AAVAULT', 10n * COIN, { assetMarker: marker }),
            createAssetTransferOutput(custody.address, 'AAVAULT', 90n * COIN, { assetMarker: marker }),
            ...(withRole ? [createAssetTransferOutput(OWNER, 'AAROLEA!', COIN, { assetMarker: marker })] : []),
            createXnaOutput(D, fee.satoshis - FEE)
          ]
        }),
        { 0: custodyWitness() }
      );

    const unapproved = spend(false);
    expect(unapproved.allowed).toBe(false);
    expect(unapproved.reason).toMatch(/not enough roles approve/);

    const approved = spend(true);
    expect(approved.allowed, `sync reject: ${approved.reason}`).toBe(true);
    mine(approved.hex);
    expect(cliJson('listassetbalancesbyaddress', D).AAVAULT).toBe(10);
  }, 120_000);

  it('executes a proposal with a vote cast before the execution exists (asynchronous)', () => {
    const vault = assetUtxo(custody.address, 'AAVAULT');
    const T = Number(cli('getblockcount')) + 20;
    const proposal = { c: 1, a: 2, b: 0, T };
    const prefix = [
      createAssetTransferOutput(D, 'AAVAULT', 10n * COIN, { assetMarker: marker }),
      createAssetTransferOutput(custody.address, 'AAVAULT', 80n * COIN, { assetMarker: marker })
    ];
    // The proposal covers the custody input and the prefix: a skeleton is enough.
    const H = assetAuthProposalHash({
      rawTx: createUnsignedTransaction({ inputs: [vault], outputs: prefix }),
      chain: 'regtest',
      ...proposal
    });

    // The holder of AAROLEA! votes: the token goes to a vote lock with H as its message.
    const returnSpk = createAssetTransferOutput(OWNER, 'AAROLEA!', COIN, { assetMarker: marker }).scriptPubKeyHex;
    const lockScript = buildAssetAuthVoteLockScript({ T, custodyCommitment: custody.commitment, returnScriptPubKey: returnSpk });
    const lock = getNoAuthAddress(NETWORK, { witnessScript: lockScript });
    const role = assetUtxo(OWNER, 'AAROLEA!');
    const voteFee = feeUtxo();
    const vote = finish(
      createUnsignedTransaction({
        inputs: [role, voteFee],
        outputs: [
          createTransferWithMessageOutput({
            address: lock.address,
            assetName: 'AAROLEA!',
            amountRaw: COIN,
            message: bytesToHex(H),
            assetMarker: marker
          }),
          createXnaOutput(OWNER, voteFee.satoshis - FEE)
        ]
      }),
      {}
    );
    expect(vote.allowed, `vote reject: ${vote.reason}`).toBe(true);
    mine(vote.hex);
    const voteUtxo = assetUtxo(lock.address, 'AAROLEA!');

    // Anyone executes: custody, the vote, a fee; the prefix, the return, the change.
    const execute = (outputs: typeof prefix) => {
      const fee = feeUtxo();
      return finish(
        createUnsignedTransaction({
          inputs: [vault, voteUtxo, fee],
          outputs: [...outputs, { valueSats: 0n, scriptPubKeyHex: returnSpk }, createXnaOutput(D, fee.satoshis - FEE)]
        }),
        {
          0: custodyWitness(proposal),
          1: buildAuthScriptWitnessNoAuth({
            args: buildAssetAuthVoteExecuteArgs({ custodyInput: 0, returnOutput: 2 }),
            witnessScript: lockScript
          })
        }
      );
    };

    // Another payment is another proposal: the vote does not count for it.
    const other = execute([
      createAssetTransferOutput(D, 'AAVAULT', 11n * COIN, { assetMarker: marker }),
      createAssetTransferOutput(custody.address, 'AAVAULT', 79n * COIN, { assetMarker: marker })
    ]);
    expect(other.allowed).toBe(false);
    expect(other.reason).toMatch(/carries a message that is not this proposal/);

    const executed = execute(prefix);
    expect(executed.allowed, `execution reject: ${executed.reason}`).toBe(true);
    mine(executed.hex);
    expect(cliJson('listassetbalancesbyaddress', D).AAVAULT).toBe(20);
    expect(cliJson('listassetbalancesbyaddress', OWNER)['AAROLEA!']).toBe(1);
  }, 180_000);

  it('gives an expired vote back to its holder, and only after T', () => {
    const T = Number(cli('getblockcount')) + 6;
    const returnSpk = createAssetTransferOutput(OWNER, 'AAROLEB!', COIN, { assetMarker: marker }).scriptPubKeyHex;
    const lockScript = buildAssetAuthVoteLockScript({ T, custodyCommitment: custody.commitment, returnScriptPubKey: returnSpk });
    const lock = getNoAuthAddress(NETWORK, { witnessScript: lockScript });
    const role = assetUtxo(OWNER, 'AAROLEB!');
    const voteFee = feeUtxo();
    const vote = finish(
      createUnsignedTransaction({
        inputs: [role, voteFee],
        outputs: [
          createTransferWithMessageOutput({
            address: lock.address,
            assetName: 'AAROLEB!',
            amountRaw: COIN,
            message: '11'.repeat(32),
            assetMarker: marker
          }),
          createXnaOutput(OWNER, voteFee.satoshis - FEE)
        ]
      }),
      {}
    );
    expect(vote.allowed, `vote reject: ${vote.reason}`).toBe(true);
    mine(vote.hex);
    const voteUtxo = assetUtxo(lock.address, 'AAROLEB!');

    const giveBack = () => {
      const fee = feeUtxo();
      return finish(
        createUnsignedTransaction({
          inputs: [voteUtxo, fee],
          outputs: [{ valueSats: 0n, scriptPubKeyHex: returnSpk }, createXnaOutput(OWNER, fee.satoshis - FEE)]
        }),
        {
          0: buildAuthScriptWitnessNoAuth({
            args: buildAssetAuthVoteReturnArgs({ returnOutput: 0 }),
            witnessScript: lockScript
          })
        }
      );
    };

    // giveBack mines the block of its fee input, and the spend is checked
    // for the block after that: both still at or below T here.
    expect(Number(cli('getblockcount')) + 2).toBeLessThanOrEqual(T);
    const early = giveBack();
    expect(early.allowed).toBe(false);

    cli('generate', 3);
    const back = giveBack();
    expect(back.allowed, `return reject: ${back.reason}`).toBe(true);
    mine(back.hex);
    expect(cliJson('listassetbalancesbyaddress', OWNER)['AAROLEB!']).toBe(1);
  }, 120_000);
});
