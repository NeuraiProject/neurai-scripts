import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getNoAuthAddress } from '@neuraiproject/neurai-key';
import {
  createAssetTransferOutput,
  createStandardAssetTransferTransaction,
  createXnaOutput,
  xnaToSatoshis
} from '@neuraiproject/neurai-create-transaction';
import {
  buildAuthScriptWitnessNoAuth,
  buildFillWitnessStack,
  bytesToHex,
  concatBytes,
  hexToBytes
} from '../src/index.js';

// End-to-end AuthScript (NoAuth) vector: deposit an asset into a covenant
// commitment derived with neurai-key, then SPEND it with the witness-stack
// builders. Admission of the deposit alone cannot detect a mis-derived
// commitment — only the spend can (WITNESS_PROGRAM_MISMATCH), so this is the
// exit-criteria vector of tmp/PLAN-ADAPTACION-NODO-2026-08.md §3.3.3.
//
// The committed witnessScript CONSUMES AND VERIFIES the full-fill args that
// `buildFillWitnessStack` produces — `OP_0 OP_EQUALVERIFY OP_1 OP_EQUAL`
// checks, through consensus execution, that the stack is exactly
// [<1>, <0>] (0 = empty element). It is not the full partial-fill covenant:
// satisfying that one under SIGVERSION_AUTHSCRIPT (introspection opcodes,
// AuthScript sighash for the cancel branch) remains the outstanding gate
// before the covenant flow is documented as supported.
//
// This package does not serialize witness transactions (and neither does
// neurai-create-transaction), so the spend is assembled by the test-local
// serializer below.
const WITNESS_SCRIPT_HEX = '00885187';

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

const FEE = xnaToSatoshis(0.01);
const RPC_PORT = 21000 + (process.pid % 9000);
const P2P_PORT = RPC_PORT + 1;
const DATADIR = `/tmp/neurai-regtest-authscript-${process.pid}`;

let D = '';

function sh(args: string[], allowFail = false): string {
  const [bin, ...rest] =
    MODE === 'docker' ? ['docker', 'exec', CONTAINER, ...args] : args;
  try {
    return execFileSync(bin, rest, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (error) {
    if (allowFail) return '';
    throw error;
  }
}

const NODE_ARGS = [
  '-regtest',
  `-datadir=${DATADIR}`,
  '-rpcuser=t',
  '-rpcpassword=t',
  `-rpcport=${RPC_PORT}`
];

function cli(...args: Array<string | number>): string {
  const bin = MODE === 'docker' ? CONTAINER_CLI : LOCAL_CLI;
  return sh([bin, ...NODE_ARGS, ...args.map(String)]);
}

function cliJson(...args: Array<string | number>): any {
  return JSON.parse(cli(...args));
}

function xnaUtxo(address: string, minXna: number): { txid: string; vout: number; amount: number } {
  const utxos = cliJson('listunspent', 1, 9999999, JSON.stringify([address]));
  const utxo = utxos
    .filter((u: any) => u.amount >= minXna)
    .sort((a: any, b: any) => a.amount - b.amount)[0];
  if (!utxo) throw new Error(`no XNA utxo >= ${minXna} at ${address}`);
  return utxo;
}

function assetUtxo(address: string, assetName: string): { txid: string; outputIndex: number } {
  const utxos = cliJson('getaddressutxos', JSON.stringify({ addresses: [address], assetName }));
  if (!utxos.length) throw new Error(`no ${assetName} utxo at ${address}`);
  return utxos[0];
}

function signAndTest(rawTx: string): { allowed: boolean; reason?: string; hex: string } {
  const signed = cliJson('signrawtransaction', rawTx);
  expect(signed.complete).toBe(true);
  const [result] = cliJson('testmempoolaccept', JSON.stringify([signed.hex]), 'true');
  return { allowed: Boolean(result.allowed), reason: result['reject-reason'], hex: signed.hex };
}

// ---------------------------------------------------------------------------
// Test-local witness-transaction serializer (BIP144 layout). Neither this
// package nor neurai-create-transaction serializes witness data; keep this
// helper test-only.
// ---------------------------------------------------------------------------

function varint(n: number): Uint8Array {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >> 8) & 0xff);
  throw new Error('varint: value too large for these vectors');
}

function u32LE(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

function u64LE(n: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, n, true);
  return out;
}

function txidLE(txidHex: string): Uint8Array {
  return hexToBytes(txidHex).reverse();
}

function serializeWitnessTx(
  inputs: Array<{ txid: string; vout: number }>,
  outputs: Array<{ valueSats: bigint; scriptPubKeyHex: string }>,
  witnesses: Uint8Array[][],
  version = 2,
  locktime = 0
): string {
  if (witnesses.length !== inputs.length) {
    throw new Error('one witness stack per input required');
  }
  const parts: Uint8Array[] = [
    u32LE(version),
    Uint8Array.of(0x00, 0x01), // segwit marker + flag
    varint(inputs.length)
  ];
  for (const input of inputs) {
    parts.push(txidLE(input.txid), u32LE(input.vout), varint(0), hexToBytes('ffffffff'));
  }
  parts.push(varint(outputs.length));
  for (const output of outputs) {
    const script = hexToBytes(output.scriptPubKeyHex);
    parts.push(u64LE(output.valueSats), varint(script.length), script);
  }
  for (const stack of witnesses) {
    parts.push(varint(stack.length));
    for (const element of stack) {
      parts.push(varint(element.length), element);
    }
  }
  parts.push(u32LE(locktime));
  return bytesToHex(concatBytes(...parts));
}

describe.skipIf(MODE === 'skip')('AuthScript NoAuth covenant e2e (deposit + witness spend)', () => {
  beforeAll(async () => {
    const neuraid = MODE === 'docker' ? CONTAINER_NEURAID : LOCAL_NEURAID;
    sh(['rm', '-rf', DATADIR]);
    sh(['mkdir', '-p', DATADIR]);
    sh([
      neuraid,
      ...NODE_ARGS,
      '-daemon',
      '-server=1',
      '-listen=0',
      '-assetindex=1',
      '-addressindex=1',
      `-port=${P2P_PORT}`
    ]);

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

    // Enough mature coinbases to fund the 1000 XNA root-asset burn.
    cli('generate', 150);
    D = cli('getnewaddress');
    cli('sendtoaddress', D, 20);
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

  it('deposits CARGO into a NoAuth commitment and spends it with buildFillWitnessStack', () => {
    // 1. Root asset issued by the node wallet (burn handled by the RPC).
    cli('issue', 'CARGO', 100, D, D);
    cli('generate', 1);

    // 2. Deposit: 5 CARGO + 1 XNA (future fee) into the NoAuth commitment,
    //    derived with neurai-key's public API. Plain transfers/payments legs.
    const witnessScript = hexToBytes(WITNESS_SCRIPT_HEX);
    const noauth = getNoAuthAddress('xna-pq-test', { witnessScript });

    const asset = assetUtxo(D, 'CARGO');
    const fees = xnaUtxo(D, 5);
    const deposit = createStandardAssetTransferTransaction({
      inputs: [
        { txid: asset.txid, vout: asset.outputIndex },
        { txid: fees.txid, vout: fees.vout }
      ],
      payments: [
        { address: noauth.address, valueSats: xnaToSatoshis(1) },
        { address: D, valueSats: xnaToSatoshis(fees.amount - 1) - FEE }
      ],
      transfers: [
        { address: noauth.address, assetName: 'CARGO', amountRaw: xnaToSatoshis(5) },
        { address: D, assetName: 'CARGO', amountRaw: xnaToSatoshis(95) }
      ]
    });

    const deposited = signAndTest(deposit.rawTx);
    expect(deposited.allowed, `deposit reject: ${deposited.reason}`).toBe(true);
    const depositTxid = cli('sendrawtransaction', deposited.hex, 'true');
    cli('generate', 1);

    const decoded = cliJson('decoderawtransaction', deposited.hex);
    const xnaVout = decoded.vout.findIndex(
      (v: any) => String(v.scriptPubKey.hex) === `5120${noauth.commitment}`
    );
    const assetVout = decoded.vout.findIndex((v: any) =>
      String(v.scriptPubKey.hex).startsWith(`5120${noauth.commitment}c0`)
    );
    expect(xnaVout).toBeGreaterThanOrEqual(0);
    expect(assetVout).toBeGreaterThanOrEqual(0);

    // 3. Spend both NoAuth UTXOs with the witness builders. The committed
    //    script verifies the exact full-fill stack: [<1>, <0>].
    const witness = buildAuthScriptWitnessNoAuth({
      args: buildFillWitnessStack(5n, 5n),
      witnessScript
    });
    expect(witness.map(bytesToHex)).toEqual(['00', '01', '', WITNESS_SCRIPT_HEX]);

    const spendHex = serializeWitnessTx(
      [
        { txid: depositTxid, vout: xnaVout },
        { txid: depositTxid, vout: assetVout }
      ],
      [
        createXnaOutput(D, xnaToSatoshis(1) - FEE),
        createAssetTransferOutput(D, 'CARGO', xnaToSatoshis(5))
      ],
      [witness, witness]
    );

    const [result] = cliJson('testmempoolaccept', JSON.stringify([spendHex]), 'true');
    expect(Boolean(result.allowed), `spend reject: ${result['reject-reason']}`).toBe(true);

    cli('sendrawtransaction', spendHex, 'true');
    cli('generate', 1);

    // The asset came back out of the covenant commitment: D holds all 100.
    expect(cliJson('listmyassets', 'CARGO')['CARGO']).toBe(100);
  }, 120_000);
});
