# @neuraiproject/neurai-scripts

Script-assembly library for Neurai. Provides:

- **Core primitives** — opcode constants, `ScriptBuilder`, byte/hex helpers.
- **Standard scripts** — P2PKH, P2WPKH, P2WSH, AuthScript (+ witness
  builders for legacy ECDSA / PQ ML-DSA-44 / NoAuth / NIP-015 ref spends),
  OP_RETURN null-data, classic m-of-n multisig + P2SH wrapper.
- **Covenants** — partial-fill sell-order covenant (legacy and PQ variants)
  targeting the **DePIN-Test** opcode set (`OP_OUTPUTSCRIPT`,
  `OP_OUTPUTVALUE`, `OP_OUTPUTASSETFIELD`, `OP_INPUTASSETFIELD`,
  `OP_TXFIELD`, `OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK`, 64-bit
  `OP_MUL`/`OP_SUB`, …).

This is the canonical place to add new Neurai script builders; callers
compose transactions with
[`@neuraiproject/neurai-create-transaction`](https://www.npmjs.com/package/@neuraiproject/neurai-create-transaction)
and sign with
[`@neuraiproject/neurai-sign-transaction`](https://www.npmjs.com/package/@neuraiproject/neurai-sign-transaction).

> ⚠️ DePIN-Test opcodes, `OP_CHECKSIGFROMSTACK`, `OP_TXHASH`, and `vrefin`
> are gated by consensus flags active in **testnet / regtest** today.
> Mainnet activation follows the fork process described in the NIPs. The
> library accepts both `xna-test` and `xna` networks so the same call sites
> work once mainnet activates.

---

## Install

```bash
npm install @neuraiproject/neurai-scripts
```

Build from source:

```bash
npm install
npm run build
npm test
```

Three bundles are produced under `dist/`:

| File | Target |
|---|---|
| `dist/index.js` / `index.cjs` | Node (ESM / CJS) |
| `dist/browser.js` | Browser ESM |
| `dist/NeuraiScripts.global.js` | IIFE global (`window.NeuraiScripts`) |

---

## Module layout

```
src/
├── core/                   Low-level primitives
│   ├── opcodes.ts          Opcode bytes + TXFIELD / TXHASH / ASSETFIELD selectors
│   ├── script-builder.ts   CScriptNum encoding, pushBytes/Int/Hex, ScriptBuilder
│   ├── bytes.ts            Hex ↔ Uint8Array helpers (ensureHex, hexToBytes, …)
│   └── index.ts            Barrel
├── standard/               Standard scripts
│   ├── p2pkh.ts            encodeP2PKHScriptPubKey
│   ├── p2wpkh.ts           encodeP2WPKHScriptPubKey
│   ├── p2wsh.ts            encodeP2WSHScriptPubKey
│   ├── authscript.ts       encodeAuthScriptScriptPubKey + witness builders
│   ├── nulldata.ts         encodeNullDataScript (OP_RETURN)
│   ├── multisig.ts         encodeMultisigRedeemScript / encodeP2SHScriptPubKey
│   └── index.ts            Barrel
├── covenants/              Covenant scripts
│   ├── partial-fill/       Legacy (ECDSA cancel) + PQ (ML-DSA-44 via CSFS)
│   └── index.ts            Barrel
├── address.ts              encodeSellerScriptPubKey (bech32m / base58check → spk)
├── types.ts                Public types
├── entries/                Rollup entry points (node / browser / IIFE)
└── index.ts                Public API
```

All exports are available from the top-level entry:

```ts
import { ScriptBuilder, opcodes, encodeP2WPKHScriptPubKey, buildPartialFillScriptHex }
  from '@neuraiproject/neurai-scripts';
```

---

## Core primitives

### Opcode constants (`./core/opcodes.ts`)

Complete coverage of the classic Script opcodes (push values, control,
stack, arithmetic, bitwise, crypto) plus every DePIN-Test addition
(`OP_CHECKTEMPLATEVERIFY`, `OP_CHECKSIGFROMSTACK`, `OP_TXHASH`,
`OP_TXFIELD`, `OP_TXLOCKTIME`, `OP_OUTPUTVALUE`, `OP_OUTPUTSCRIPT`,
`OP_INPUTCOUNT`/`OP_OUTPUTCOUNT`, `OP_OUTPUTASSETFIELD`,
`OP_INPUTASSETFIELD`, `OP_REFINPUTCOUNT`/`OP_REFINPUTFIELD`/
`OP_REFINPUTASSETFIELD`, `OP_CAT`, `OP_SPLIT`, `OP_REVERSEBYTES`, 64-bit
`OP_MUL`/`OP_DIV`/`OP_MOD`).

Also exports selector tables:

```ts
// For OP_TXFIELD and OP_REFINPUTFIELD
opcodes.TXFIELD_VALUE                  // 0x01
opcodes.TXFIELD_AUTHSCRIPT_COMMITMENT  // 0x02
opcodes.TXFIELD_SCRIPTPUBKEY           // 0x03

// For OP_OUTPUTASSETFIELD / OP_INPUTASSETFIELD / OP_REFINPUTASSETFIELD
opcodes.ASSETFIELD_NAME                // 0x01
opcodes.ASSETFIELD_AMOUNT              // 0x02
opcodes.ASSETFIELD_UNITS               // 0x03
opcodes.ASSETFIELD_REISSUABLE          // 0x04
opcodes.ASSETFIELD_HAS_IPFS            // 0x05
opcodes.ASSETFIELD_IPFS_HASH           // 0x06
opcodes.ASSETFIELD_TYPE                // 0x07

// Bitmask selectors for OP_TXHASH (any non-zero combination is valid)
opcodes.TXHASH_VERSION            // 0x01
opcodes.TXHASH_LOCKTIME           // 0x02
opcodes.TXHASH_INPUT_PREVOUTS     // 0x04
opcodes.TXHASH_INPUT_SEQUENCES    // 0x08
opcodes.TXHASH_OUTPUTS            // 0x10
opcodes.TXHASH_CURRENT_PREVOUT    // 0x20
opcodes.TXHASH_CURRENT_SEQUENCE   // 0x40
opcodes.TXHASH_CURRENT_INDEX      // 0x80
opcodes.TXHASH_ALL                // 0xff
```

### `ScriptBuilder` (`./core/script-builder.ts`)

```ts
import { ScriptBuilder, opcodes } from '@neuraiproject/neurai-scripts';

const script = new ScriptBuilder()
  .op(opcodes.OP_DUP, opcodes.OP_HASH160)
  .pushBytes(pkh20)
  .op(opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG)
  .build();               // Uint8Array
// or .buildHex() → string
```

Also exported atomically: `pushBytes(data)`, `pushInt(value)`,
`pushHex(hex)`, `encodeScriptNum(value)`.

Push elements up to **3072 bytes** (NIP-18 cap when `CSFS` is active).
Larger pushes throw; legacy scripts should stay under 520 bytes per push.

### Byte helpers (`./core/bytes.ts`)

`ensureHex`, `hexToBytes`, `bytesToHex`, `concatBytes`, `bytesEqual`.

---

## Standard scripts

All encoders return raw `Uint8Array` bytes. Caller supplies the pre-hashed
inputs where applicable (we don't bake a crypto dep into this library).

### P2PKH — `encodeP2PKHScriptPubKey(pkh20)`

```ts
import { encodeP2PKHScriptPubKey } from '@neuraiproject/neurai-scripts';
// OP_DUP OP_HASH160 0x14 <pkh> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)
const spk = encodeP2PKHScriptPubKey(pubKeyHash20);
```

### P2WPKH — `encodeP2WPKHScriptPubKey(pkh20)`

```ts
// OP_0 0x14 <pkh> (22 bytes)
const spk = encodeP2WPKHScriptPubKey(pubKeyHash20);
```

### P2WSH — `encodeP2WSHScriptPubKey(witnessScriptSha256)`

```ts
// OP_0 0x20 <SHA256(witnessScript)> (34 bytes)
// Compute SHA256 via your crypto stack (not bundled here).
const spk = encodeP2WSHScriptPubKey(sha256(witnessScript));
```

### AuthScript — `encodeAuthScriptScriptPubKey(program32)` + witness builders

`scriptPubKey` layout: `OP_1 0x20 <32-byte program>`.

Four spend modes, selected by a 1-byte `auth_type` in the witness stack:

| Constant | Value | Meaning |
|---|---|---|
| `AUTHSCRIPT_NOAUTH` | `0x00` | No signature — gated by witnessScript alone |
| `AUTHSCRIPT_PQ` | `0x01` | ML-DSA-44 (post-quantum) |
| `AUTHSCRIPT_LEGACY` | `0x02` | secp256k1 ECDSA |
| `AUTHSCRIPT_REF` | `0x03` | NIP-015 reference-script spend (future) |

Witness-stack builders return `Uint8Array[]` — the array of raw stack
elements. Serialization into the transaction witness (compact-size +
length-prefixes) is done at tx-assembly time by
`neurai-create-transaction`.

```ts
import {
  encodeAuthScriptScriptPubKey,
  buildAuthScriptWitnessLegacy,
  buildAuthScriptWitnessPQ,
  buildAuthScriptWitnessNoAuth,
  buildAuthScriptWitnessRef
} from '@neuraiproject/neurai-scripts';

// Output spk
const spk = encodeAuthScriptScriptPubKey(program32);

// Legacy spend: [0x02, sig, pubkey, ...args, witnessScript]
const stackLegacy = buildAuthScriptWitnessLegacy({
  signature: derSigWithSighash,
  pubKey: compressedSecp256k1,
  args: [],
  witnessScript
});

// PQ spend (requires NIP-18): [0x01, sig(~2421 B), pubkey(~1313 B), ...args, witnessScript]
const stackPQ = buildAuthScriptWitnessPQ({
  signature: mlDsa44SigWithSighash,
  pubKey: versionedPqPubKey,
  args: [],
  witnessScript
});

// NoAuth (pure covenant): [0x00, ...args, witnessScript]
const stackNoAuth = buildAuthScriptWitnessNoAuth({ args, witnessScript });

// NIP-015 reference-script spend: [0x03, ...args, uint32LE(refIndex)]
const stackRef = buildAuthScriptWitnessRef({ refIndex: 2, args });
```

### Null-data (OP_RETURN) — `encodeNullDataScript(payload, options?)`

```ts
import { encodeNullDataScript } from '@neuraiproject/neurai-scripts';

// OP_RETURN <push>
const spk = encodeNullDataScript(someBytes);

// Multi-push payload
const spk2 = encodeNullDataScript([tagBytes, messageBytes]);

// Oversize (> 80 B) needs an explicit opt-in
const big = encodeNullDataScript(huge, { allowNonStandard: true });
```

`NULLDATA_STANDARD_MAX_SIZE = 80` (Neurai's mempool-relay cap inherited
from Bitcoin Core). Outputs over that are consensus-valid but not relayed
unless nodes run with `-acceptnonstdtxn=1`.

### Multisig — `encodeMultisigRedeemScript` + `encodeP2SHScriptPubKey`

Classic bare multisig is consensus-valid but non-standard for relay in
Neurai today. Typical usage wraps the redeem script in P2SH.

```ts
import {
  encodeMultisigRedeemScript,
  encodeP2SHScriptPubKey,
  MULTISIG_MAX_PUBKEYS  // 20
} from '@neuraiproject/neurai-scripts';

const redeemScript = encodeMultisigRedeemScript({
  m: 2,
  pubKeys: [pk1, pk2, pk3]     // each 33 or 65 bytes
});
// <2> <pk1> <pk2> <pk3> <3> OP_CHECKMULTISIG

// Wrap in P2SH (callers compute HASH160 externally):
const scriptPubKey = encodeP2SHScriptPubKey(hash160(redeemScript));
// OP_HASH160 0x14 <h160> OP_EQUAL
```

---

## Covenants

### Partial-Fill Sell Order

A partial-fill sell order lets a seller publish a lot of tokens at a
fixed price and lets any number of buyers take arbitrary fractions of
that lot without the seller having to come back online for each sale.
The covenant that guards the seller's output is the only rulebook: the
spending transaction is valid only if it pays the seller the correct XNA
amount, delivers the right asset quantity to the buyer, and forwards the
remainder into a new UTXO carrying the same covenant script. No
custodial DEX, no off-chain matching, no second signature from the
seller.

The covenant is **stateful via UTXO continuity**. The output at `vout[2]`
of every fill must carry the same AuthScript v1 commitment as the input
being spent (enforced on the fly by
`OP_OUTPUTAUTHCOMMITMENT == OP_TXFIELD 0x02`, NIP-023), so the covenant
self-replicates without hardcoding its own hash. Earlier drafts compared
full scriptPubKeys via `OP_OUTPUTSCRIPT`, but that is unsatisfiable on
asset-wrapped covenant UTXOs because the remainder's asset wrapper
encodes a different `amountRaw` than the spent UTXO's. The
remaining asset quantity is read directly from the input via
`OP_INPUTASSETFIELD` and the subtraction `inputAmount − N` is verified,
so the same script works for any remainder as the lot drains. Asset
name, buyer amount, payment destination script and payment value are all
checked against the covenant's hardcoded parameters using
`OP_OUTPUTASSETFIELD`, `OP_OUTPUTSCRIPT` and `OP_OUTPUTVALUE`. Consensus
enforces every rule; there is no trusted off-chain layer.

Three spending branches are selected by the top of the unlock stack:

- `OP_IF` (unlock pushed `1`) — **Cancel**. The seller signs and
  recovers the remainder. The legacy variant uses ECDSA
  (`OP_DUP OP_HASH160 <PKH> OP_EQUALVERIFY OP_CHECKSIG`); the PQ variant
  swaps this for `OP_CHECKSIGFROMSTACK` against an ML-DSA-44 signature
  (see *PQ variant* below).
- `OP_ELSE OP_IF` (unlock pushed `1 0`) — **Full fill**. Any buyer
  can drain the entire covenant in one transaction. The tx has two
  constrained outputs (`vout[0]` pays the seller, `vout[1]` delivers
  the asset to the buyer) and **no `vout[2]` continuation** — the
  covenant is fully consumed. Required because consensus rejects
  asset transfers with `amount == 0`, so a partial fill that would
  drain the lot is structurally impossible.
- `OP_ELSE OP_ELSE` (unlock pushed `N 0 0`) — **Partial fill**. Any
  buyer can take `N < total` by providing the fill amount; the
  covenant's `vout[2]` re-locks the remainder (`total − N` units)
  into an identical covenant UTXO. No seller signature is involved.

This maps naturally onto Neurai's mempool: multiple buyers can submit
their fill transactions in sequence, each one building on the previous
fill's `vout[2]` before confirmation. Neurai's default descendant limit
of 500 allows long chains of pending fills against a single published
order, and the whole chain confirms together when the next block is
mined. If the seller wants to stop the order at any point, she spends
the current live UTXO via the cancel branch.

#### Alice / Bob / Carol flow

1. **Alice** locks 100 CAT in a covenant UTXO (`buildPartialFillScript`).
   Price 1 XNA / CAT, P2PKH as payment destination.
2. **Bob** spends the covenant pushing `<5> <0>` as `scriptSig` and his
   XNA input. The script enforces:
   - `output[0]` pays Alice ≥ `5 * unitPriceSats` XNA
   - `output[1]` is a transfer of 5 CAT to Bob
   - `output[2]` is a new covenant UTXO with **the same** scriptPubKey
     and 95 CAT
3. **Carol** does the same on the new UTXO, leaving 90 CAT behind.
4. **Alice** signs the cancel branch on the latest UTXO and recovers her
   remaining 90 CAT. She has already received 10 XNA across Bob's and
   Carol's fills.

No second signature from Alice, no custodial server: the covenant script
is the rulebook.

#### Usage (legacy ECDSA cancel)

```ts
import {
  buildPartialFillScriptHex,
  buildFillScriptSigHex,
  buildCancelScriptSigHex,
  parsePartialFillScript
} from '@neuraiproject/neurai-scripts';

// 1) Alice publishes an order for 100 CAT at 1 XNA per CAT.
const scriptPubKeyHex = buildPartialFillScriptHex({
  sellerAddress: aliceP2PKHAddress,  // "t..." on testnet / "N..." on mainnet
  tokenId: 'CAT',
  unitPriceSats: 100_000_000n        // 1 XNA = 1e8 sats per indivisible unit
});
// Throws if the address is not a legacy P2PKH — the legacy covenant uses
// OP_HASH160 + OP_CHECKSIG on the cancel branch and cannot commit to an
// AuthScript program. Use `buildPartialFillScriptPQ` for bech32m / PQ
// destinations.

// 2) Bob spends 5 CAT from the covenant.
const bobScriptSigHex = buildFillScriptSigHex(5n);
// Fill-tx layout (built with neurai-create-transaction):
//   vin[0]   = covenant UTXO, scriptSig = bobScriptSigHex
//   vin[1+]  = buyer's XNA inputs (standard P2PKH, SIGHASH_ALL)
//   vout[0]  = unitPriceSats * 5 XNA to Alice
//   vout[1]  = 5 CAT to Bob
//   vout[2]  = 95 CAT back to the SAME covenant scriptPubKey
//   vout[3+] = buyer change (optional)

// 3) Alice cancels on the latest remainder UTXO.
const aliceCancelSig = /* produced by neurai-sign-transaction, SIGHASH_ALL */;
const cancelScriptSigHex = buildCancelScriptSigHex(aliceCancelSig, alicePubKey);

// 4) The DEX backend indexes active orders by parsing scriptPubKeys.
for (const utxo of candidateUtxos) {
  try {
    const order = parsePartialFillScript(utxo.scriptPubKeyHex, 'xna-test');
    // order.tokenId, order.unitPriceSats, order.sellerPubKeyHash, order.network
    // The parser returns the 20-byte PKH; base58check-encode with the
    // network's legacy prefix (0x35 mainnet / 0x7f testnet) if you need
    // to display the seller's address.
  } catch {
    // not a partial-fill covenant, skip
  }
}
```

#### Script layout (legacy, three-branch)

```
OP_IF                                                              // cancel branch
  OP_DUP OP_HASH160 <sellerPKH> OP_EQUALVERIFY OP_CHECKSIG
OP_ELSE
  OP_IF                                                            // full-fill branch
    # Stack entering: [ ]  (scriptSig pushed <1> <0>)
    <0> <0x02> OP_INPUTASSETFIELD                                  // N = inputAmount
    OP_DUP <unitPriceSats> OP_MUL
        <0> OP_OUTPUTVALUE OP_SWAP OP_GREATERTHANOREQUAL OP_VERIFY // payment value
    <0> OP_OUTPUTSCRIPT <sellerP2PKH> OP_EQUALVERIFY               // payment dest
    OP_DUP <1> <0x02> OP_OUTPUTASSETFIELD OP_EQUALVERIFY           // buyer amount == N
    <1> <0x01> OP_OUTPUTASSETFIELD <tokenId> OP_EQUALVERIFY        // buyer name
    OP_DROP OP_1                                                   // no vout[2] required
  OP_ELSE                                                          // partial-fill branch
    # Stack entering: [ N ]  (scriptSig pushed <N> <0> <0>)
    OP_DUP <unitPriceSats> OP_MUL
        <0> OP_OUTPUTVALUE OP_SWAP OP_GREATERTHANOREQUAL OP_VERIFY // payment value
    <0> OP_OUTPUTSCRIPT <sellerP2PKH> OP_EQUALVERIFY               // payment dest
    OP_DUP <1> <0x02> OP_OUTPUTASSETFIELD OP_EQUALVERIFY           // buyer amount == N
    <1> <0x01> OP_OUTPUTASSETFIELD <tokenId> OP_EQUALVERIFY        // buyer name
    <2> OP_OUTPUTAUTHCOMMITMENT <0x02> OP_TXFIELD OP_EQUALVERIFY   // continuity (NIP-023)
    <2> <0x01> OP_OUTPUTASSETFIELD <tokenId> OP_EQUALVERIFY        // remainder name
    <2> <0x02> OP_OUTPUTASSETFIELD OP_OVER
        <0> <0x02> OP_INPUTASSETFIELD OP_SWAP OP_SUB OP_EQUALVERIFY // remainder = in - N
    OP_DROP OP_1
  OP_ENDIF
OP_ENDIF
```

#### Limitations of v0.1

- **Payment only in XNA.** A `PaymentAsset` selector is planned for v0.2.
- **No `MinFill` / `MaxFill` / `Expiry`.** Planned for v0.2.
- **Fixed output layout** (`vout[0..2]`). The covenant rejects
  reorderings. Buyer change must go to `vout[3+]`.
- **AMM is out of scope.** Covered by a later phase of the NIP roadmap.

### Partial-Fill PQ variant (post-quantum seller, NIP-18)

With `OP_CHECKSIGFROMSTACK` (`CSFS`) and `OP_TXHASH` active, the cancel
branch can validate an **ML-DSA-44** signature in place of the classic
ECDSA `OP_CHECKSIG`. NIP-18 raises the per-element push cap to 3072 B so
the ~2421 B signature and ~1313 B pubkey fit as stack items. All three
are active on DePIN-Test testnet.

| | Legacy | PQ |
|---|---|---|
| Cancel sig scheme | ECDSA secp256k1 | ML-DSA-44 (~2421 B sig, ~1313 B pubkey) |
| Cancel verifier | `OP_DUP OP_HASH160 <PKH> OP_EQUALVERIFY OP_CHECKSIG` | `OP_DUP OP_SHA256 <commitment> OP_EQUALVERIFY <selector> OP_TXHASH OP_SWAP OP_CHECKSIGFROMSTACK` |
| What Alice signs | tx sighash (standard) | `SHA256(OP_TXHASH(selector))` — CSFS single-SHA256s the message |
| Payment destination | P2PKH only | P2PKH **or** AuthScript bech32m (scriptPubKey bytes hardcoded) |

```ts
import {
  buildPartialFillScriptPQHex,
  buildCancelScriptSigPQHex,
  parsePartialFillScriptPQ,
  isPartialFillScriptPQ,
  DEFAULT_PQ_TXHASH_SELECTOR
} from '@neuraiproject/neurai-scripts';

const scriptPubKeyHex = buildPartialFillScriptPQHex({
  network: 'xna-test',
  paymentAddress: 'tnq1...',               // AuthScript bech32m, or legacy "t..." P2PKH
  pubKeyCommitment: sha256(alicePQPubKey), // 32 bytes
  tokenId: 'CAT',
  unitPriceSats: 100_000_000n,
  txHashSelector: DEFAULT_PQ_TXHASH_SELECTOR  // 0xff = all eight tx fields
});

const cancelScriptSigHex = buildCancelScriptSigPQHex(mlDsa44SigWithSighash, alicePQPubKey);

// Indexers can tell variants apart:
if (isPartialFillScriptPQ(utxo.scriptPubKeyHex)) {
  const order = parsePartialFillScriptPQ(utxo.scriptPubKeyHex);
}
```

#### PQ cancel-branch layout

```
OP_IF                                // scriptSig pushed <sig> <pubKey> OP_1
  OP_DUP OP_SHA256
  <pubKeyCommitment 32B>
  OP_EQUALVERIFY
  <txHashSelector 1B>
  OP_TXHASH                          // msg = dSHA256(selected_tx_fields)
  OP_SWAP
  OP_CHECKSIGFROMSTACK               // verifies sig over SHA256(msg) for pubKey
OP_ELSE
  ... partial-fill branch (identical to legacy) ...
OP_ENDIF
```

---

## Network handling

Builders take address strings (whose prefix already encodes the network:
`t.../N...` for P2PKH, `tnq1.../nq1...` for AuthScript bech32m) and
validate them via `decodeAddress` from `neurai-create-transaction`. No
builder accepts a separate `network` parameter — it would be redundant
with the address and invite silent mismatches.

Parsers, on the other hand, do take a `network` argument (default
`'xna-test'`). The covenant *script bytes themselves do not encode
network*: a legacy covenant is opcodes plus a 20-byte PKH, a PQ covenant
is opcodes plus a 32-byte commitment and raw payment-scriptPubKey bytes,
and neither payload differs between mainnet and testnet. The parser
receives `network` purely so the caller can later base58-encode
`sellerPubKeyHash` against the right version byte, or interpret
`paymentScriptPubKey` in the correct bech32m/base58 context.

Keep this split intact when adding new covenants: builders reject a
`network` field, parsers echo it through.

---

## Consensus / policy notes

- **DePIN-Test opcodes are consensus-gated.** Each one is behind an
  individual flag (`nCTVEnabled`, `nCSFSEnabled`, `nTXHASHEnabled`,
  `nTXFIELDEnabled`, `nOUTPUTVALUEEnabled`, `nOUTPUTSCRIPTEnabled`,
  `nOUTPUTASSETFIELDEnabled`, `nINPUTASSETFIELDEnabled`,
  `nINPUTOUTPUTCOUNTEnabled`, `nREFINPUTSEnabled`, `nCATEnabled`,
  `nSPLITEnabled`, `nREVERSEBYTESEnabled`, `n64BitIntegersEnabled`,
  `nTXLOCKTIMEEnabled`, `nPQWitnessEnabled`). All are **true** on testnet
  and regtest, **false** on mainnet until each NIP's fork process lands.
- **NIP-18 per-element cap (3072 B) is also a mempool-policy win.**
  Neurai's `MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE` equals the consensus
  cap whenever CSFS is active, so PQ witness items are standard on the
  testnet today — no `-acceptnonstdtxn=1` required. The legacy 80 B cap
  only applies when CSFS is off.
- **Commitment choice (PQ).** The PQ covenant commits to
  `SHA256(pubKey)`, not the witness-v1 bech32m program. That keeps the
  covenant decoupled from AuthScript address derivation and lets the
  caller use any PQ key whose SHA256 they can compute.

---

## Adding new scripts to this library

The layout under `src/standard/` and `src/covenants/` is designed for
expansion. When adding a new primitive:

- **Standard scripts** (P2*, OP_RETURN, new address formats, …) go under
  `src/standard/`. Keep one file per scheme and export from
  `src/standard/index.ts`.
- **Covenants** (batch-fill, shared-claim, HTLC, vaults, AMM, …) go under
  `src/covenants/<name>/` with the same `script.ts` / `spend.ts` /
  `parse.ts` split the partial-fill module uses. Re-export from
  `src/covenants/index.ts`.
- **Reference-script carriers / NIP-015 helpers** will land in a future
  `src/reference-scripts/` directory when the NIP activates.

The top-level `src/index.ts` barrel should re-export everything publicly
consumable; callers import directly from the package root.

---

## License

MIT — same terms as the rest of the `@neuraiproject/*` libraries.
