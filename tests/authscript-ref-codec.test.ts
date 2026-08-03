import { describe, expect, it } from 'vitest';
import {
  computeTxid,
  computeWtxid,
  parseTransaction,
  serializeTransaction
} from '@neuraiproject/neurai-create-transaction';
import { buildAuthScriptWitnessRef, bytesToHex } from '../src/index.js';

// Integration shape-test for the NIP-015 reference-script flow: this package
// builds the ref witness (0x03 + args + u32LE refIndex into tx.vrefin) and
// neurai-create-transaction's codec (0.5.1+) serializes the v3 transaction
// that carries the vrefin the witness points at. NIP-015 is NOT activated in
// consensus yet — a live regtest vector will be added once the node activates
// it; until then this round-trip pins the layout from the JS side.
//
// Type boundary, on purpose and explicit: buildAuthScriptWitnessRef returns
// Uint8Array[] (raw stack elements); serializeTransaction expects string[]
// (hex per element). The canonical conversion is `.map(bytesToHex)`.

const DUMMY_TXID = '11'.repeat(32);
const CARRIER_TXID = '22'.repeat(32);
const P2PKH_SPK = '76a914' + 'e2'.repeat(20) + '88ac';

describe('NIP-015 ref-script witness ↔ v3/vrefin codec round-trip', () => {
  it('survives serializeTransaction → parseTransaction byte for byte', () => {
    const witness = buildAuthScriptWitnessRef({
      refIndex: 0,
      args: [Uint8Array.of(0x01), new Uint8Array(0)]
    }).map(bytesToHex);

    // Witness shape: auth type 0x03 first, u32LE ref locator last.
    expect(witness[0]).toBe('03');
    expect(witness[witness.length - 1]).toBe('00000000');

    const vrefin = [{ txid: CARRIER_TXID, vout: 1 }];
    const tx = {
      version: 3,
      inputs: [
        {
          txid: DUMMY_TXID,
          vout: 0,
          scriptSigHex: '',
          sequence: 0xffffffff,
          witness
        }
      ],
      outputs: [{ valueSats: 1000n, scriptPubKeyHex: P2PKH_SPK }],
      vrefin,
      locktime: 0
    };

    const hex = serializeTransaction(tx);
    const decoded = parseTransaction(hex);

    expect(decoded.version).toBe(3);
    expect(decoded.vrefin).toEqual(vrefin);
    expect(decoded.inputs[0].witness).toEqual(witness);
    expect(decoded.outputs).toEqual(tx.outputs);

    // Witness present → wtxid must differ from txid.
    expect(computeWtxid(hex)).not.toBe(computeTxid(hex));
  });

  it('builder alone: refIndex is encoded as a u32LE locator', () => {
    // Pure builder shape-test — no transaction context, so no claim that this
    // index resolves to any vrefin entry.
    const witness = buildAuthScriptWitnessRef({ refIndex: 0x01020304 }).map(bytesToHex);
    expect(witness[witness.length - 1]).toBe('04030201');
  });

  it('a non-zero refIndex resolves to the vrefin entry it points at', () => {
    const witness = buildAuthScriptWitnessRef({ refIndex: 1 }).map(bytesToHex);
    expect(witness[witness.length - 1]).toBe('01000000');

    const vrefin = [
      { txid: CARRIER_TXID, vout: 0 },
      { txid: DUMMY_TXID, vout: 7 } // <- the entry refIndex 1 points at
    ];
    const hex = serializeTransaction({
      version: 3,
      inputs: [
        { txid: DUMMY_TXID, vout: 0, scriptSigHex: '', sequence: 0xffffffff, witness }
      ],
      outputs: [{ valueSats: 0n, scriptPubKeyHex: P2PKH_SPK }],
      vrefin,
      locktime: 0
    });

    const decoded = parseTransaction(hex);
    expect(decoded.inputs[0].witness).toEqual(witness);
    // The locator's semantic target survives the round-trip. NOTE: the codec
    // serializes bytes only — it does NOT validate that refIndex is in range
    // (that is NIP-015 consensus, not yet activated); this assertion is what
    // ties the index to its carrier here.
    expect(decoded.vrefin[1]).toEqual(vrefin[1]);
  });

  it('codec contract this flow relies on: vrefin demands version 3', () => {
    expect(() =>
      serializeTransaction({
        version: 2,
        inputs: [
          { txid: DUMMY_TXID, vout: 0, scriptSigHex: '', sequence: 0xffffffff }
        ],
        outputs: [{ valueSats: 0n, scriptPubKeyHex: P2PKH_SPK }],
        vrefin: [{ txid: CARRIER_TXID, vout: 0 }],
        locktime: 0
      })
    ).toThrow(/vrefin requires transaction version 3/);
  });
});
