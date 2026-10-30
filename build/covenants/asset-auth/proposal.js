/**
 * NIP-054 proposal hash H, the message a vote carries.
 *
 *   H = TaggedHash("NeuraiAssetAuthProposal", m)
 *   m = chainId (u8) || nVersion (i32) || nLockTime (u32) || T (u32)
 *       || compact(c) || compact(a) || compact(b)
 *       || (outpoint, nSequence) of inputs 0..c-1
 *       || outputs 0..a-1 || the last b outputs
 *       || compact(#refs) || reference inputs (version 3 only)
 *
 * Inputs from index c on and the outputs between the prefix and the suffix
 * (approvals, returns, fees, change) are left to the executor, so a skeleton
 * transaction with only the proposal inputs and outputs gives the same H as
 * the execution. Votes carry H as is, as the 32-byte (64-hex) message of
 * their owner-token transfer: `bytesToHex(hash)`.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { parseTransaction, serializeOutput } from '@neuraiproject/neurai-create-transaction';
import { concatBytes, hexToBytes } from '../../core/bytes.js';
/** The chain identifier the node commits to (OP_CHAINCONTEXT selector 0x03). */
export const ASSETAUTH_CHAIN_IDS = Object.freeze({
    mainnet: 0,
    testnet: 1,
    regtest: 2
});
const PROPOSAL_TAG = new TextEncoder().encode('NeuraiAssetAuthProposal');
function u32(value) {
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value >>> 0, true);
    return out;
}
function compactSize(value) {
    if (value < 0xfd)
        return Uint8Array.of(value);
    if (value <= 0xffff)
        return Uint8Array.of(0xfd, value & 0xff, value >> 8);
    return concatBytes(Uint8Array.of(0xfe), u32(value));
}
/** A display-order txid and vout as the node serializes a COutPoint. */
function outpoint(txid, vout) {
    return concatBytes(hexToBytes(txid).reverse(), u32(vout));
}
export function buildAssetAuthProposalMessage(proposal) {
    const { c, a, b, T } = proposal;
    const chainId = ASSETAUTH_CHAIN_IDS[proposal.chain];
    if (chainId === undefined) {
        throw new Error(`unknown chain ${JSON.stringify(proposal.chain)}`);
    }
    for (const [name, value] of Object.entries({ c, a, b, T })) {
        if (!Number.isInteger(value) || value < 0 || value > 0x7fffffff) {
            throw new Error(`${name} must be an integer from 0 to ${0x7fffffff}`);
        }
    }
    const tx = parseTransaction(proposal.rawTx);
    if (c > tx.inputs.length) {
        throw new Error(`c (${c}) exceeds the ${tx.inputs.length} inputs of the transaction`);
    }
    if (a + b > tx.outputs.length) {
        throw new Error(`a + b (${a + b}) exceeds the ${tx.outputs.length} outputs of the transaction`);
    }
    const version = new Uint8Array(4);
    new DataView(version.buffer).setInt32(0, tx.version, true);
    const parts = [Uint8Array.of(chainId), version, u32(tx.locktime), u32(T), compactSize(c), compactSize(a), compactSize(b)];
    for (const input of tx.inputs.slice(0, c)) {
        parts.push(outpoint(input.txid, input.vout), u32(input.sequence));
    }
    for (const output of [...tx.outputs.slice(0, a), ...tx.outputs.slice(tx.outputs.length - b)]) {
        parts.push(serializeOutput(output));
    }
    const refs = tx.version === 3 ? tx.vrefin : [];
    parts.push(compactSize(refs.length));
    for (const ref of refs)
        parts.push(outpoint(ref.txid, ref.vout));
    return concatBytes(...parts);
}
/** H: 32 bytes, in the order a vote carries it. */
export function assetAuthProposalHash(proposal) {
    const tag = sha256(PROPOSAL_TAG);
    return sha256(concatBytes(tag, tag, buildAssetAuthProposalMessage(proposal)));
}
