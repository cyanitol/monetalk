# 11-Day Chain Truncation

## Constants

```
SLOTS_PER_EPOCH   = 3,927           (12 hours at 11 seconds/slot)
EPOCHS_PER_CYCLE  = 22
CYCLE_DURATION    = 22 * 12h = 264h = 11 days
SNAPSHOT_PHASE    = last 100 slots of final epoch (~1,100 seconds)
```

## Trigger

Deterministic: based on slot number, not timestamps.

```
cycle_boundary(n) = n * SLOTS_PER_EPOCH * EPOCHS_PER_CYCLE
```

## Early Truncation (Supply-Based)

In addition to the deterministic slot-based trigger, early truncation fires when the circulating supply (sum of all spendable balances) drops below the early truncation threshold at any epoch boundary.

```
circulating_supply = sum(all_spendable_balances)
if circulating_supply < early_truncation_threshold * INITIAL_SUPPLY:
    trigger early truncation → enter SNAPSHOT PHASE
```

- Checked at every epoch boundary (first slot of each epoch)
- Initial threshold: 15% of INITIAL_SUPPLY (1.65B MTK)
- Threshold range: [5%, 25%], adjusted by adaptive controller
- When triggered: enter snapshot phase immediately, same as normal truncation
- Minimum cycle duration: 1 epoch (12 hours) — early truncation cannot fire in the first epoch

## Snapshot Phase (last 100 slots of cycle, ~1,100 seconds)

- No new chat transactions accepted
- Nodes compute terminal snapshot:
  - Validator set (Merkle root)
  - Reset balance ledger (Merkle root) -- wallets reset to reward-derived amounts
  - Identity/key registry (Merkle root)
  - Chain accumulated hash (rolling hash of all block hashes in epoch)
- Validators sign snapshot (Ed25519, require 2/3+ by stake weight)

### Merkle Tree Structure

Binary balanced SHA-256 Merkle tree.

```
Leaves = sorted(validator_set ++ balance_entries ++ key_registry_entries)
         by key hash ascending (SHA-256 of entry key).
Odd leaf promoted to next level (no duplication).
Interior node = SHA-256(left_child || right_child).
Root embedded in epoch genesis block.
```

### Accumulated Hash

```
accumulated_hash(0) = SHA-256(genesis_block_hash)
accumulated_hash(n) = SHA-256(accumulated_hash(n-1) || block_hash(n))
```

Sequential by construction; not parallelizable. Each block's hash depends on the entire prior chain.

### Attestation Format

Each validator produces an individual Ed25519 signature over the snapshot digest:

```
attestation_i = sign_ed25519(
    validator_privkey_i,
    SHA-256(epoch_number || accumulated_hash || merkle_root)
)
```

- Individual Ed25519 signatures, not aggregated.
- Stored as array in epoch genesis block.
- Size: 64 bytes * validator_count.

## Epoch Genesis Block

First block of new cycle embeds:
- Prior cycle's terminal snapshot + attestation signatures
- Initial validator set, balance ledger, key registry
- Accumulated hash binding to entire prior epoch
- Adaptive parameters for the new cycle
- Early truncation flag (whether this cycle ended via early truncation)
- Actual duration of the prior cycle in epochs (for verification)

**Chain split protection**: The accumulated hash creates an irreversible binding. Forging an alternative requires controlling 2/3+ stake.

## What Survives Truncation

| Data | Survives? |
|------|-----------|
| Wallet balances | Transformed (reset to rewards) |
| Staked balances | Yes (persist across epochs) |
| Validator set | Yes |
| Key registry | Yes (carried in genesis block) |
| Message content | **No** (deliberately destroyed) |
| Ratchet state | N/A (local only, never on-chain) |
| Signal sessions | Survive (local state, independent of chain) |
| Burned tokens | Restored to pool (burned_total resets to 0) |
| Adaptive parameters | Recomputed at cycle boundary |

## Signal Sessions and Truncation

Signal Double Ratchet sessions are **local state only** — they are never stored on-chain and are therefore unaffected by chain truncation. Sessions survive across epoch boundaries without re-establishment. The epoch_nonce is included in **blockchain transaction signatures** (the on-chain envelope), not in Signal session keys. This means:

- Open conversations continue seamlessly across truncation boundaries
- Signal ratchet counters, chain keys, and skipped message keys persist in local encrypted storage
- Only KEY_EXCHANGE and KEY_REPLENISH transactions (for establishing NEW sessions) require chain access
- If a user is offline for >11 days, their existing sessions survive but any pending on-chain key exchange messages are lost; new session establishment requires the peer to re-publish prekeys

## Key Registry Truncation

The full key registry (not just a Merkle root) is carried in the epoch genesis block. Contents per user entry:

- Identity key (Ed25519 public key, 32 bytes)
- Current signed prekey (X25519, 32 bytes + Ed25519 signature, 64 bytes)
- OPK count and latest KEY_REPLENISH reference (8 bytes)
- Total: ~136 bytes per user

At 500K users: ~68 MB in genesis block. New nodes download the full genesis block and validate via 2/3+ attestation signatures. SPKs that expired during the cycle are carried forward unchanged; validators should publish KEY_ROTATE in the first epoch of the new cycle.

## Balance Reset at Truncation

At truncation, all spendable balances are set to 0. Each account's new balance is then set to their calculated reward + earned rebate. Unspent tokens return to the pool. Staked balances persist unchanged. The Merkle root in the new genesis block reflects these post-reward balances.

At cycle boundary, the pool is fully restored: `pool(N+1) = INITIAL_SUPPLY - sum(staked_balances) - onboarding_reserve - treasury`. All tokens burned during the cycle are effectively returned to the pool. The `burned_total` counter resets to 0. The adaptive controller then computes parameters for the next cycle based on the current cycle's metrics (see doc/06-economics.md).

## New Node Bootstrapping

New node needs only: current epoch's genesis block + all blocks since. Verify genesis block via 2/3+ validator signatures. No historical chain required.

## State Transition Diagram

```
EPOCH N (normal operation)
    |
    v
[Slot reaches epoch_end_slot(N)]
    |
    v
SNAPSHOT PHASE (last ~100 slots)
    |  - Nodes compute terminal snapshot
    |  - Validators sign snapshot via Ed25519
    |  - Signatures aggregated in last ~100 slots
    |
    v
TRANSITION GATE
    |  - Verify: 2/3+ attestation on snapshot?
    |  - If yes: proceed to truncation
    |  - If no: keep waiting, request missing attestations
    |
    v
TRUNCATION EXECUTION
    |  - Write Epoch Genesis Block for epoch N+1
    |  - Delete all blocks from epoch N
    |  - Replace chain state with reset balances
    |  - Restore supply: pool = INITIAL_SUPPLY - staked - reserve - treasury
    |  - Reset burned_total = 0
    |  - Run adaptive controller → compute params for next cycle
    |
    v
EPOCH N+1 (normal operation begins with adjusted parameters)
```

### Early Truncation Path

```
EPOCH K (mid-cycle, epoch boundary)
    |
    v
[Check: circulating_supply < threshold?]
    |-- No: continue normal operation
    |-- Yes:
        |
        v
EARLY TRUNCATION TRIGGERED
    |  - Log early truncation event
    |  - Same flow as normal SNAPSHOT PHASE
    |
    v
SNAPSHOT PHASE (same as normal)
    ...
TRUNCATION EXECUTION
    |  - Write Epoch Genesis Block
    |  - Delete prior blocks
    |  - Restore supply: pool = INITIAL_SUPPLY - staked - reserve - treasury
    |  - Reset burned_total = 0
    |  - Run adaptive controller → compute params for next cycle
    |
    v
NEW CYCLE (normal operation begins with adjusted parameters)
```

## Crash Recovery (WAL-Based)

Write-Ahead Log for truncation. WAL entries are written with fsync before any state mutation. Incomplete WAL entries (detected by missing terminator byte 0xFF) are discarded on recovery. WAL is compacted after successful truncation checkpoint.

```
1. WAL_ENTRY: "truncation_begin" (epoch N, genesis hash) → fsync
2. Write epoch genesis block for N+1 → fsync
3. WAL_ENTRY: "genesis_written" → fsync
4. Delete epoch N block files
5. WAL_ENTRY: "blocks_deleted" → fsync
6. Update state DB with reset balances
7. WAL_ENTRY: "state_updated" → fsync
7.5. WAL_ENTRY: "supply_restored" → fsync (pool restored, burned_total reset, adaptive params computed)
8. WAL_ENTRY: "truncation_complete" → fsync
9. Compact WAL (remove entries for completed truncation)
```

On recovery:
- Read last WAL entry
- Discard any entry missing terminator byte 0xFF (incomplete write)
- If "truncation_begin": rollback, retry from snapshot
- If "genesis_written": resume deletion
- If "blocks_deleted": resume state update
- If "state_updated": resume supply restoration (pool restore, burned_total reset, adaptive params)
- If "supply_restored" or "truncation_complete": done

## Cross-Epoch Replay Prevention

- Each epoch has a unique epoch_nonce derived from prior VRF outputs
- Transaction validity includes epoch_nonce in the signed data
- Transactions from epoch N are cryptographically invalid in epoch N+1 (different nonce)
- Signal ratchet state prevents message-level replay (monotonic counters)

## Offline User Handling

- Users offline >11 days: messages from prior epoch are irrecoverably lost (by design)
- On reconnect: node downloads current epoch genesis block, validates via 2/3+ signatures
- Signal session state preserved locally (ratchet continues from last known state)
- Recommendation: client UI should warn users about 11-day message expiry

### Offline-During-Snapshot Recovery

If a node was offline during the snapshot phase and rejoins mid-cycle:

1. Request the epoch genesis block from 3+ peers.
2. Validate via 2/3+ attestation signatures on the genesis block.
3. If signatures match the known validator set from the prior epoch: accept genesis block and sync forward.
4. If signatures do not match the known validator set from the prior epoch: node enters **safe mode** and requests full state from bootstrap peers (hardcoded bootstrap list).
5. Safe mode persists until the node has verified state from a bootstrap peer and caught up to the current slot.

## Attestation Failure Handling

- If <2/3 attestation within 200 slots: extend snapshot phase by 100 slots
- If still <2/3: carry forward prior epoch unchanged, next epoch retries
- Sybil attacker withholding <33% cannot prevent truncation (only delay)
