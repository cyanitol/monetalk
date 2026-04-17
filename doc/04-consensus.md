# Consensus Mechanism (Simplified Ouroboros Praos)

## References

- Ouroboros Praos: David et al., "Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain", Eurocrypt 2018
- VRF: RFC 9381 (ECVRF-ED25519-SHA512-ELL2)
- FLP impossibility: Fischer, Lynch, Paterson, "Impossibility of Distributed Consensus with One Faulty Process", 1985

## Formal State Definition

```haskell
data ConsensusState = ConsensusState
  { chain          :: [Block]                -- ordered list of committed blocks
  , ledger         :: Map PubKey Account     -- current account states
  , mempool        :: Set Tx                 -- pending unconfirmed transactions
  , epoch_nonce    :: ByteString             -- 32 bytes, current epoch randomness
  , slot           :: Word64                 -- current slot number
  , stake_snapshot :: Map PubKey Coin        -- 2-epoch delayed stake distribution
  , circulating_supply :: Word64          -- sum of all spendable balances, monitored for early truncation
  , cycle_burned       :: Word64          -- tokens burned this cycle (resets at boundary)
  , adaptive_params    :: AdaptiveParams  -- current cycle's tunable parameters
  }

data Account = Account
  { balance         :: Word64       -- spendable token balance
  , nonce           :: Word64       -- monotonically increasing per-account tx counter
  , stake_weight    :: Word64       -- composite effective stake
  , punitive_factor :: Rational     -- [0/1, 1/1], multiplicative penalty
  }

data AdaptiveParams = AdaptiveParams
  { ap_burn_rate             :: Rational    -- [1/5, 4/5], adaptive burn percentage
  , ap_fee_floor             :: Word64      -- [5, 100] MTK
  , ap_fee_ceiling           :: Word64      -- [5000, 50000] MTK
  , ap_target_msgs_per_epoch :: Word64      -- [1000, 100000000]
  , ap_early_trunc_threshold :: Rational    -- [1/20, 1/4], fraction of INITIAL_SUPPLY
  }
```

The `stake_snapshot` is always taken from 2 epochs prior to the current epoch. This delay prevents stake grinding attacks where a leader could manipulate their own stake to influence future elections.

## Time Structure

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Slot duration | 11 seconds | 11-theme alignment, propagation headroom |
| Slots per epoch | 3,927 | 12-hour epochs (43,200s / 11s) |
| Epochs per cycle | 22 | 11-day truncation cycle |
| Active slot coefficient (f) | 0.20 | ~1 block per 55 seconds avg |
| Security parameter (k) | 11 (message tier) / 22 (value tier) | Two-tier settlement: ~10 min messages, ~20 min value transfers |

Cycles target 11 days but may be shorter if early truncation is triggered due to supply depletion. The adaptive controller adjusts parameters to maintain the 11-day target over time. Minimum cycle duration: 1 epoch (12 hours).

## Slot Leader Election (VRF)

Each node independently evaluates whether it leads a slot:

```
VRF_input = epoch_nonce || slot_number
(proof, output) = VRF_prove(node_secret_key, VRF_input)
threshold = 1 - (1 - f)^sigma_j   -- sigma_j = node's relative stake

if VRF_output_normalized < threshold:
    this node is slot leader, produce a block
```

No multi-party computation or communication is needed for leader selection.

### VRF Fixed-Point Arithmetic

VRF output is 64 bytes (SHA-512, per RFC 9381 ECVRF-ED25519-SHA512-ELL2). Normalization and threshold comparison use the following procedure:

```
-- Step 1: Normalize VRF output to [0, 1)
vrf_uint64    = big_endian_to_uint64(vrf_output[0..7])   -- first 8 bytes
VRF_normalized = vrf_uint64 / 2^64                        -- value in [0, 1)

-- Step 2: Compute threshold using 128-bit fixed-point (64.64 format)
--   All intermediate values stored as 128-bit integers where the lower
--   64 bits represent the fractional part.
one_fp        = 1 << 64                                   -- 1.0 in 64.64
f_fp          = floor(f * 2^64)                           -- active slot coefficient
sigma_j_fp    = floor(sigma_j * 2^64)                     -- node's relative stake
threshold_fp  = one_fp - fixed_pow(one_fp - f_fp, sigma_j_fp)
threshold     = threshold_fp / 2^64                       -- back to [0, 1)

-- Step 3: Compare
if VRF_normalized < threshold:
    node is slot leader
```

All nodes must use identical 128-bit fixed-point (64.64 format) arithmetic to ensure deterministic leader election across the network.

## Block Structure

```haskell
data Block = Block
  { bHeader :: BlockHeader
  , bBody   :: [ChatTx]
  }

data BlockHeader = BlockHeader
  { bhSlotNo      :: !Word64
  , bhBlockNo     :: !Word64
  , bhPrevHash    :: !ByteString    -- 32 bytes, SHA-256
  , bhBodyHash    :: !ByteString    -- 32 bytes
  , bhIssuerVK    :: !Ed25519PubKey
  , bhVRFProof    :: !ByteString
  , bhVRFOutput   :: !ByteString
  , bhSignature   :: !Ed25519Sig
  , bhHeartbeat   :: !(Maybe HeartbeatChallenge)  -- present if slot leader issues challenge
  }
```

## Stake Determination (Composite)

Stake is NOT just token balance. It is a composite score:

```
StakeMultiplier = 0.5 + 0.3 * UptimeRatio
EffectiveStake  = TokenBalance * StakeMultiplier * PunitiveFactor
```

- **StakeMultiplier range**: [0.5, 0.8] — minimum 0.5 (offline), maximum 0.8 (full uptime)
- 0.5 base: ensures staked tokens always contribute at least half their weight
- +0.3 * UptimeRatio: uptime bonus [0, 0.3], verified via heartbeat challenges
- * PunitiveFactor: penalty multiplier [0.0, 1.0]

**Active validator**: a validator who produced at least 1 block OR responded to at least 1 heartbeat challenge in the current cycle. Validators who are staked but completely unresponsive have UptimeRatio = 0, yielding StakeMultiplier = 0.5.

Snapshots taken with 2-epoch delay to prevent grinding.

## Fork Choice

Longest chain rule with density-based comparison for forks within k blocks of the tip.

### Formal Density Rule

```
density(chain, slot_range) = count(blocks in slot_range) / length(slot_range)
```

For competing forks within k blocks of the tip:

1. Compute density over the divergence range (from fork point to current slot).
2. Prefer the fork with higher density.
3. Ties broken by lower VRF output hash (lexicographic byte comparison of the VRF output in the first diverging block).

This density rule ensures that a chain with more consistent block production is preferred over one with the same length but concentrated production (which may indicate adversarial behavior).

## Finality

- **Optimistic confirmation**: Message visible at mempool inclusion (~11-55 seconds)
- **Message tier settlement**: k=11 blocks deep (~10 minutes). Encrypted messages where reordering has low impact. Reversal probability ~1 in 2,048.
- **Value tier settlement**: k=22 blocks deep (~20 minutes). Token transfers, stake operations, validator registration. Reversal probability ~1 in 4.2 million. Comparable to Bitcoin 6-conf.
- **Implementation**: Block validation marks each transaction with its tier based on transaction type. Nodes track two confirmation counters per block. Wallet UI shows "delivered" (k=11) vs. "settled" (k=22). Validators cannot spend block rewards until k=22 depth. Fee burns are immediate (burned tokens cannot be "un-burned").
- **Finality definition**: A block at depth >= k (inclusive) is considered final. k=11 for message-tier transactions; k=22 for value-tier transactions. A block with k or more blocks built on top of it is irreversible for its respective tier. By the FLP impossibility result, deterministic finality is impossible in an asynchronous network with even one faulty process; Ouroboros Praos provides probabilistic finality where the reversal probability decreases exponentially with depth.

## Formal BFT Proof Requirement (DO-178C DAL A, DO-333)

- Consensus safety and liveness must be formally verified via TLA+ model.
- **Safety**: No two honest nodes disagree on finalized blocks (blocks at depth >= k=11 (message tier) and k=22 (value tier)).
- **Liveness**: All valid transactions are eventually included (assuming <1/3 Byzantine stake).
- **Deliverable**: TLA+ specification + model checking results for 10^6 reachable states.
- Fork choice rule must be proven deterministic: same inputs produce the same output across all nodes.

## Clock Synchronization

```
Clock source priority:
  1. System NTP (if available, ±50ms accuracy)
  2. Peer median timestamp (median of last 10 received block timestamps)

Node local clock tolerance: ±1 second from NTP source.
  If local clock drifts beyond ±1s from NTP, node triggers immediate resync.

Block rejection rule: reject any block whose timestamp deviates >11 seconds
  from expected_slot_time (= genesis_time + slot_number * 11000 ms).
  The 11-second block tolerance accounts for the ±1s local clock tolerance
  on both the block producer side and the validating node side.

Slot assignment: floor(unix_timestamp_ms / 11000)
```

## Heartbeat Challenge Protocol

Heartbeat challenges verify validator liveness and contribute to the uptime ratio used in stake determination.

```
Parameters:
  HEARTBEAT_FREQUENCY = 1 challenge per 100 slots (~18.3 minutes at 11s slots)
  HEARTBEAT_RESPONSE_WINDOW = 10 slots (110 seconds)

Protocol:
  1. Slot leader includes HEARTBEAT_CHALLENGE in block header:
       challenge = random 32-byte nonce (from VRF output of leader)

  2. Each active validator must respond within 10 slots:
       response = sign(challenge || validator_pubkey, validator_secret_key)

  3. Response inclusion: any subsequent block producer may include
     heartbeat responses in their block body.

  4. Non-response penalty:
       uptime_score -= 1 / total_challenges_in_epoch
     (i.e., missing one challenge out of ~39 challenges per epoch
      decrements uptime by ~2.56%)

  5. Uptime ratio at epoch boundary:
       UptimeRatio = 1.0 - (missed_challenges / total_challenges_in_epoch)
```

## Mempool and Double-Spend Prevention

```
Max mempool size: 50,000 transactions (~50 MB)
Eviction: lowest-fee-first (FIFO within same fee tier)
Reject: new TX if mempool full AND new TX fee <= minimum fee in pool
Priority ordering: fee descending, then arrival time ascending
```

### Per-Account Nonce Ordering

The mempool enforces strict per-account nonce ordering to prevent double spends:

```
- Transaction with nonce N is only valid if the account's current
  confirmed nonce is N-1.
- Duplicate nonces are rejected at mempool admission.
- Transactions with future nonces (gaps) are held in a pending queue
  but not considered valid for block inclusion until the gap is filled.

Fork resolution and double-spend handling:
  - Fork choice selects one canonical chain.
  - Transactions from the losing (orphaned) chain are returned to the
    mempool if their nonces are still valid against the winning chain's
    ledger state.
  - Transactions whose nonces conflict with the winning chain are dropped.
```

## Validator Exit Protocol

Validators may withdraw their stake via the `STAKE_WITHDRAW` transaction:

```
STAKE_WITHDRAW lifecycle:
  1. Validator submits STAKE_WITHDRAW transaction (included in block).
  2. Cooldown period: 2 full epochs from the epoch in which the
     transaction is confirmed.
  3. During cooldown: validator continues to participate in consensus
     (leader election, block validation, heartbeat responses).
     This prevents sudden drops in active stake that could affect
     security assumptions.
  4. After cooldown: stake is returned to the validator's spendable
     balance. Validator is removed from the active validator set.

Early exit (before cooldown completes):
  - Validator may force-exit by submitting STAKE_WITHDRAW_IMMEDIATE.
  - Penalty: 10% of staked amount is burned (sent to unspendable address).
  - Remaining 90% returned immediately.
  - This discourages validators from rapidly entering and exiting to
    game epoch boundaries.
```

## VRF Epoch Nonce Derivation

```
epoch_nonce(N) = SHA-256(epoch_nonce(N-1) || last_block_VRF_output(epoch N-1))
epoch_nonce(0) = SHA-256("UmbraVox_genesis_nonce_v1")
```

### Epoch Genesis Block

Each epoch begins with a genesis block that bootstraps the epoch's state. This block includes a **chain revision number**:

```
data EpochGenesis = EpochGenesis
  { egChainRevision    :: !Word32       -- monotonically increasing revision
  , egEpochNo          :: !Word64
  , egStakeSnapshot    :: Map PubKey Coin
  , egEpochNonce       :: !ByteString   -- 32 bytes
  , egAdaptiveParams   :: AdaptiveParams
  , egPrevEpochHash    :: !ByteString   -- 32 bytes, hash of prior epoch's final block
  }
```

**Chain revision** tracks protocol-level changes (consensus rules, block format, transaction semantics). Software must support the current revision plus the 3 immediately prior revisions, allowing nodes a grace period to upgrade. Blocks produced under an unsupported revision (older than current - 3) are rejected.

- Nonce evolves deterministically from prior epoch's VRF outputs.
- Prevents grinding: attacker cannot predict nonce without knowing all VRF outputs.
- Early truncation produces a valid epoch boundary nonce using the same derivation formula (last block's VRF output from the shortened cycle).

### Edge Case: Empty Epoch

```
If epoch N-1 produced 0 blocks:
  epoch_nonce(N) = SHA-256(epoch_nonce(N-1) || 0x00*32)
```

This is a known degenerate case. The system continues with reduced entropy but no deadlock. An epoch with zero blocks indicates either extreme network partition or near-total validator failure. The deterministic fallback ensures all surviving nodes converge on the same nonce and can resume block production.

## Truncation Failure Handling

```
Failure mode 1: <2/3 attestation within 200 slots
  -> Extend snapshot phase by 100 slots, retry attestation collection

Failure mode 2: Still <2/3 after extension
  -> Emergency: carry forward prior epoch state unchanged, alert all validators
  -> Next epoch attempts truncation again (cumulative 2-epoch window)

Failure mode 3: Crash during truncation execution
  -> On restart: detect incomplete truncation via WAL marker
  -> Resume from last committed WAL entry
  -> Verify genesis block integrity before accepting new blocks

Failure mode 4: Early truncation triggered but <2/3 attestation
  -> Same handling as normal truncation failure (extend snapshot, then carry forward)
  -> Adaptive controller receives "failed_early_truncation" signal, raises threshold for next attempt
```

## Network Partition Recovery

- If partition occurs: each partition produces blocks independently.
- On heal: longest chain rule applies; shorter partition's blocks are orphaned.
- If both partitions have >1/3 stake: neither achieves 2/3+ attestation at epoch boundary.
- Truncation stalls until partition heals (designed failure mode).
- Recovery: partition with majority stake wins; minority partition nodes reorg to majority chain.
