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
import type { AssetAuthArgs } from './policy.js';
export type AssetAuthChain = 'mainnet' | 'testnet' | 'regtest';
/** The chain identifier the node commits to (OP_CHAINCONTEXT selector 0x03). */
export declare const ASSETAUTH_CHAIN_IDS: Readonly<Record<AssetAuthChain, number>>;
export interface AssetAuthProposal extends AssetAuthArgs {
    /** The execution, or a skeleton with its proposal inputs and outputs (hex). */
    rawTx: string;
    chain: AssetAuthChain;
}
export declare function buildAssetAuthProposalMessage(proposal: AssetAuthProposal): Uint8Array;
/** H: 32 bytes, in the order a vote carries it. */
export declare function assetAuthProposalHash(proposal: AssetAuthProposal): Uint8Array;
