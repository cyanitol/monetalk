# Hardening Spec: 11-Day Truncation Cycle Security

**Cross-references:** `doc/05-truncation.md`, `doc/04-consensus.md`, `doc/06-economics.md`, `doc/15-economic-model-v3.md`, `doc/10-security.md`, `doc/proof-04-token-conservation.md`

---

## 1. Truncation Boundary Atomicity

### Requirement

The 5-step cycle boundary process (snapshot, reset, restore, adjust, credit) must be atomic with respect to transaction processing. No transaction may observe an intermediate state between steps.

### Specification

```
ATOMIC_BOUNDARY_INVARIANT:
  For any transaction T and cycle boundary B occurring at slot s_B:
    T observes either the complete pre-boundary state S(N) or the
    complete post-boundary state S(N+1). No transaction T may
    observe a state where some but not all of the 5 steps have executed.
```

### Mechanism

1. **Transaction gate.** At the start of the snapshot phase (last 100 slots of the final epoch), the mempool gate closes: no new chat transactions are accepted for block inclusion. Only heartbeat responses and attestation messages are processed.

2. **Exclusive lock.** The cycle boundary executes under an exclusive state lock. The lock is acquired before step 1 (snapshot) and released after step 5 (credit). Block production is suspended for the duration.

3. **WAL ordering.** The write-ahead log (doc/05-truncation.md lines 200-224) enforces a strict ordering. Each WAL entry is fsynced before the next step begins. On crash recovery, the WAL guarantees exactly-once execution of each step.

4. **No interleaving proof.** Define the boundary transition function:

```
B : S(N) -> S(N+1)

B = credit . adjust . restore . reset . snapshot

For any transaction T and states S, S':
  if T is processed before B:  T sees S(N)
  if T is processed after B:   T sees S(N+1) = B(S(N))
  T cannot see snapshot(S(N)) or reset(snapshot(S(N))) etc.
```

The transaction gate guarantees the precondition: no T is concurrent with B. The WAL guarantees crash-atomic completion. Together these ensure full atomicity.

### Formal Proof (Atomicity)

**Theorem (Boundary Atomicity).** No transaction observes a partial boundary state.

**Proof.** By contradiction. Suppose transaction T observes intermediate state S_k where S_k is the result of applying steps 1..k but not step k+1..5.

- Case 1: T is a chat transaction. The transaction gate closes at snapshot phase entry (slot s_B - 100). T cannot be included in any block during slots [s_B - 100, s_B]. After B completes at slot s_B, the gate reopens with state S(N+1). Contradiction: T cannot be concurrent with B.

- Case 2: T is an attestation/heartbeat. These transactions do not read or modify economic state (balances, pool, burned_total). They operate on the consensus layer only. Therefore even if processed during B, they observe no economic intermediate state. The economic state visible to any subsequent transaction is S(N+1).

- Case 3: Crash during B. The WAL ensures that on recovery, B resumes from the last committed step. No blocks are produced until B completes (the node does not accept connections until WAL recovery finishes). Therefore no T can observe the intermediate crash state.

In all cases, T observes either S(N) or S(N+1). []

---

## 2. Cross-Truncation Chain Integrity

### Requirement

The accumulated hash chain must link consecutive cycles such that the history of all prior cycles is irrevocably committed, even though the block data from prior cycles is deleted.

### Mechanism

```
accumulated_hash(0) = SHA-256(genesis_block_hash)
accumulated_hash(n) = SHA-256(accumulated_hash(n-1) || block_hash(n))
```

At each cycle boundary, the accumulated hash of the entire cycle is embedded in the epoch genesis block of the next cycle. The genesis block also contains:

- The epoch number (monotonically increasing across cycles)
- The epoch nonce (derived from prior VRF outputs)
- 2/3+ validator attestations over:
  `SHA-256(epoch_number || accumulated_hash || merkle_root)`

### Formal Proof (History Integrity)

**Theorem (Unforgeable History).** An adversary controlling < 1/3 of total stake cannot produce an alternative accumulated hash that is accepted by honest nodes.

**Proof.**

1. **Hash chain binding.** The accumulated hash at the end of cycle C is:

```
H_C = SHA-256(H_{C-1}' || h_last)
```

where H_{C-1}' is the accumulated hash through the penultimate block and h_last is the final block's hash. By the collision resistance of SHA-256 (2^128 security), finding H_C' != H_C that maps to the same digest is infeasible.

2. **Attestation binding.** The epoch genesis block requires attestations from validators controlling >= 2/3 of total stake. Each attestation signs:

```
digest = SHA-256(epoch_number || accumulated_hash || merkle_root)
```

An adversary controlling < 1/3 of stake cannot produce 2/3 attestation weight. Therefore the adversary cannot substitute an alternative accumulated_hash in the genesis block.

3. **Inductive argument.** Base case: the genesis block hash H_0 is a protocol constant known to all nodes. Inductive step: assume H_{C-1} is correct and committed in a genesis block with 2/3+ attestation. Then H_C is uniquely determined by the block hashes of cycle C (hash chain property) and committed via 2/3+ attestation in the genesis block of cycle C+1. By induction, the entire history chain H_0, H_1, ..., H_C is unforgeable.

4. **Post-deletion integrity.** After truncation deletes blocks from cycle C, the accumulated hash H_C in the genesis block of cycle C+1 serves as a binding commitment to those deleted blocks. Any claim about the content of a deleted block can be verified against H_C (if the claimant provides the block and its position in the hash chain).

**Corollary.** Even an archival adversary who retains all historical blocks cannot produce a valid alternative history without forging 2/3+ attestations. []

---

## 3. State Consistency at Boundary

### Requirement

All 12 economic invariants (doc/proof-04-token-conservation.md) must hold immediately before, during, and immediately after the truncation boundary.

### Verification

For each invariant, we verify preservation across the CycleBoundary transition:

**Invariant 1 (Conservation):** Proven in proof-04. The CycleBoundary function computes `pool' = INITIAL_SUPPLY - staked' - reserve' - treasury'` and sets `burned' = 0`. Then `total' = sum(balances') + pool' + staked' + reserve' + treasury' + 0 = INITIAL_SUPPLY` by the same algebraic argument as proof-04 Section "Proof for CycleBoundary."

**Invariant 2 (Intra-cycle burn monotonic):** Trivially preserved. The new cycle starts with `burned = 0`. The first transaction in the new cycle sets `burned = to_burn >= 0`, satisfying monotonicity from the new baseline.

**Invariant 3 (Cycle boundary reset):** Holds by construction: `burned' = 0` is a direct assignment in CycleBoundary.

**Invariant 4 (Supply restoration):** Holds by construction: `pool'` is computed from the restoration formula.

**Invariant 5 (Reward floor):** The credit step (step 5) computes rewards. If `pool_allocation / active_validators >= MIN_REWARD`, proportional distribution applies with floor enforcement. If not, the validator cap mechanism activates. In both cases, every active validator receives >= 5,000 MTK. This is verified in proof-04 Invariant 5.

**Invariant 6 (Fee bounds):** The adjust step (step 4) computes new adaptive parameters via `clamp`. By definition of clamp, bounds are preserved. The new cycle's first fee computation uses these bounded parameters.

**Invariant 7 (Quadratic bonding):** Validator registrations processed in the new cycle use the same bonding formula. No boundary interaction.

**Invariant 8 (Rebate cap):** Rebates are computed and distributed at boundary (step 5). The cap is enforced during computation. The new cycle starts with zero accumulated rebates.

**Invariant 9 (Punitive recovery monotonic):** P_carryover persists across boundaries. No boundary operation increases P_carryover without a new violation. Recovery formula applied at boundary: `P_carry(t+1) = P_floor + (1 - P_floor) * P_carry(t)`, which is strictly increasing for P_floor > 0 (proven in proof-04 Invariant 9).

**Invariant 10 (Onboarding bonus cap):** Bonuses computed at boundary are explicitly capped at 50% of treasury allocation. Cap enforced by proportional scaling.

**Invariant 11 (Adaptive bounds):** All parameter adjustments go through `clamp` (proven in proof-04 Invariant 11).

**Invariant 12 (Minimum cycle duration):** The early truncation guard `current_epoch >= cycle_start_epoch + 1` ensures >= 1 epoch. Normal cycles run 22 epochs. Both satisfy >= 3,927 slots.

### Formal Statement

```
Theorem (Cross-Boundary Invariant Preservation):
  Let I(s) = conjunction of invariants 1-12 evaluated on state s.
  If I(S(N)) holds at the end of cycle N, then I(S(N+1)) holds at the
  start of cycle N+1, where S(N+1) = CycleBoundary(S(N)).

Proof: By case analysis on each of the 12 invariants as shown above.
  Each invariant is either:
  (a) preserved by construction (invariants 1, 3, 4, 6, 11, 12),
  (b) vacuously true at cycle start (invariants 2, 8),
  (c) preserved by the reward/penalty computation (invariants 5, 9, 10), or
  (d) independent of the boundary (invariant 7).  []
```

---

## 4. Early Truncation Security

### Threat

An adversary burns tokens rapidly (by sending a high volume of messages) to force early truncation, disrupting the network's 11-day cycle target.

### Cost Analysis

Early truncation fires when `circulating_supply < early_truncation_threshold * INITIAL_SUPPLY` at an epoch boundary.

```
Parameters (defaults):
  INITIAL_SUPPLY           = 11,000,000,000 MTK
  early_truncation_threshold = 0.15
  burn_rate                = 0.65
  fee_floor                = 10 MTK

Trigger condition:
  circulating_supply < 0.15 * 11B = 1,650,000,000 MTK

Required burn:
  An attacker must cause enough burn to reduce circulating supply
  from its current level to below the threshold.
```

**Worst-case cost (single attacker, no other activity):**

Assume the attacker holds all circulating supply at cycle start. Let C_0 be the initial circulating supply. The attacker must burn enough to reduce C_0 below 1.65B.

```
To burn X tokens via messaging:
  fees_paid = X / burn_rate = X / 0.65
  messages_required = fees_paid / fee_floor = (X / 0.65) / 10

Example: to burn from C_0 = 5B to 1.65B (burn 3.35B):
  fees_paid = 3.35B / 0.65 = 5.15B MTK
  messages = 5.15B / 10 = 515,000,000 messages
```

But the attacker must pay the fees from their own balance, and fees escalate via EMA when volume exceeds 1.5x target:

```
After sustained spam:
  base_fee = base_fee * 1.1^k (for k epochs of congestion)
  At k=20: base_fee = 10 * 1.1^20 = 67.3 MTK
  At k=40: base_fee = 10 * 1.1^40 = 452.6 MTK
```

**EMA escalation makes the cost superlinear.** The attacker cannot sustain spam at the initial fee rate. Realistic cost to trigger early truncation exceeds the total circulating supply in fees.

### Controller Response

When early truncation occurs:

```
duration_ratio = actual_cycle_slots / target_cycle_slots  (<< 1.0)

Next cycle adjustments (with 50% damping):
  burn_rate decreases    (less burn -> slower supply depletion)
  fee_floor increases    (higher minimum cost per message)
  fee_ceiling increases  (higher maximum cost)
  target_msgs decreases  (lower congestion threshold)
  early_truncation_threshold may decrease (range [0.05, 0.25])
```

The adaptive controller makes repeat attacks progressively harder. A second forced early truncation in the next cycle would face higher fees and lower burn rates.

### Impact Assessment

Early truncation is **graceful degradation**, not failure:

- Supply is fully restored via the Universe Cycle model
- All validator stakes persist
- All Signal sessions persist
- The only effect is a shortened cycle (minimum 1 epoch / 12 hours)
- The adaptive controller self-corrects within 2-3 cycles

**Verdict:** Cost exceeds benefit. The attacker spends more MTK than they can recover. Network impact is limited to one shortened cycle.

---

## 5. Truncation Denial

### Threat

An adversary attempts to prevent truncation from occurring, keeping the network in a depleting cycle indefinitely.

### Analysis

Truncation is **time-based**, not supply-based:

```
Normal truncation trigger:
  slot_number >= cycle_start_slot + EPOCHS_PER_CYCLE * SLOTS_PER_EPOCH

This is a deterministic function of slot number.
No economic variable, supply metric, or validator action can delay it.
```

The epoch boundary occurs at a fixed slot number. When that slot arrives, the snapshot phase begins automatically. The adversary cannot manipulate the slot counter (it is derived from wall-clock time via NTP with +-1 second tolerance and 11-second slots).

Early truncation is an **optional acceleration**, not a requirement. The 22-epoch cycle completes regardless of supply metrics. Therefore:

```
Theorem (Truncation Liveness):
  For any adversary A controlling < 1/3 of total stake:
    Every cycle terminates within at most 22 epochs + 300 slots
    (normal cycle + extended attestation window).

Proof:
  1. The slot counter is monotonically increasing (clock-based).
  2. After 22 * 3,927 = 86,394 slots, the snapshot phase begins.
  3. The snapshot phase lasts 100 slots (normal) + up to 200 slots
     (extended attestation collection if < 2/3 attestation).
  4. A controls < 1/3 stake, so honest validators control > 2/3 stake.
     Honest validators produce attestations within the response window.
  5. Therefore 2/3+ attestation is achieved within 300 slots of
     the snapshot phase start.
  6. Total cycle duration <= 86,394 + 300 = 86,694 slots.  []
```

### Edge Case: Attestation Withholding

If an adversary controlling exactly 1/3 of stake withholds attestations:

- Honest validators hold 2/3 of stake and can produce 2/3 attestation weight without the adversary.
- The adversary cannot prevent truncation; they can only decline to attest.
- Their non-attestation is a protocol violation subject to uptime penalties (UptimeRatio decreases, reducing their stake multiplier and future rewards).

### Edge Case: Clock Manipulation

- Nodes reject blocks with timestamps deviating > 11 seconds from expected slot time.
- A node with a manipulated clock produces invalid blocks that are rejected by honest nodes.
- The adversary cannot advance or retard the global slot counter.

---

## 6. Data Availability Across Truncation

### Pending Transactions

```
At snapshot phase entry (slot s_B - 100):
  - Transaction gate closes: no new chat transactions admitted to blocks.
  - Transactions already in the mempool but not yet included in a block
    are DROPPED. They cannot be included in the new cycle because:
    (a) they reference the old epoch_nonce (invalid in new cycle), and
    (b) sender balances are reset (the fee source may no longer exist).
  - Clients must resubmit transactions in the new cycle.
```

### In-Flight Messages (Signal Layer)

```
Signal messages that are encrypted but whose blockchain transaction has
not yet been confirmed:
  - The encrypted payload is in the sender's outbox (local state).
  - The sender's client retries submission in the new cycle.
  - Signal ratchet state is local and unaffected by truncation.
  - The recipient's ratchet will process the message normally when
    the new transaction is confirmed in the next cycle.
  - No message loss occurs at the Signal layer; only the blockchain
    delivery is delayed.
```

### Unfinalized Blocks

```
Blocks at depth < k (not yet final) at snapshot phase entry:
  - Included in the accumulated hash computation.
  - The snapshot uses the longest chain at slot s_B - 100.
  - Blocks in forks that are not part of the longest chain are
    abandoned (same as normal fork resolution).
  - Transactions in abandoned forks are returned to mempool, then
    dropped at gate close (see above).

Blocks produced during the snapshot phase (slots s_B - 100 to s_B):
  - Only contain attestation and heartbeat transactions.
  - These blocks ARE included in the accumulated hash.
  - They are deleted after truncation along with all other blocks.
```

### Data Availability Guarantee

```
Theorem (No Silent Data Loss):
  At truncation boundary, every transaction T falls into exactly one
  of the following categories:
    (a) T is in a finalized block (depth >= k): T's effects are
        reflected in the snapshot state.
    (b) T is in a non-finalized block on the longest chain: T's effects
        are reflected in the snapshot state (the snapshot reads the
        longest chain, not just finalized blocks).
    (c) T is in a fork or mempool: T is explicitly dropped. The sender
        can detect this via the absence of confirmation and resubmit.
    (d) T is a Signal-layer message not yet submitted: T remains in
        the sender's local outbox for retry.

  No transaction is silently lost without the sender's ability to
  detect and recover.  []
```

---

## 7. Validator Set Stability

### Threat

An adversary manipulates the validator set at truncation boundaries via:
- Stake grinding: choosing when to enter/exit to influence future elections
- Last-moment stake changes: altering stake just before the snapshot to gain disproportionate influence in the next cycle

### Mitigations

**2-epoch delayed stake snapshot:**

```
The stake_snapshot used for leader election in epoch E is taken from
epoch E-2 (doc/04-consensus.md line 40). This means:
  - Stake changes in the last 2 epochs of a cycle do not affect
    leader election until 2 epochs into the next cycle.
  - An adversary cannot change their election probability at the
    boundary by last-minute staking.
```

**Validator exit cooldown:**

```
STAKE_WITHDRAW requires a 2-epoch cooldown (doc/04-consensus.md
lines 239-261). During cooldown, the validator continues participating
in consensus. This prevents:
  - Flash exits to reduce honest stake at boundary
  - Rapid enter-exit cycles to game epoch boundaries
  - STAKE_WITHDRAW_IMMEDIATE incurs 10% slash, making gaming expensive
```

**Snapshot timing at boundary:**

```
The truncation snapshot captures the validator set as of the snapshot
phase start (slot s_B - 100). This validator set is embedded in the
epoch genesis block of the new cycle. Any STAKE_WITHDRAW or new
validator registration submitted during the snapshot phase is rejected
(transaction gate is closed for all non-attestation transactions).
```

### Formal Proof (No Stake Grinding Across Boundaries)

```
Theorem (Boundary Stake Stability):
  The validator set V(N+1) used for leader election in the first
  2 epochs of cycle N+1 is determined by stake_snapshot from
  epoch (boundary_epoch - 2). An adversary cannot influence V(N+1)
  by actions taken in the last 2 epochs of cycle N.

Proof:
  Let E_B be the boundary epoch. Leader election in epochs E_B+1 and
  E_B+2 uses stake_snapshot from epochs E_B-1 and E_B respectively.

  1. stake_snapshot(E_B-1) was computed at the start of epoch E_B-1,
     reflecting stake as of epoch E_B-3.
  2. Any stake change in epoch E_B-1 or E_B does not affect the
     snapshot until epoch E_B+1 at earliest, which uses the snapshot
     from E_B-1 (already frozen).
  3. The 2-epoch delay means the adversary must commit stake changes
     at least 2 epochs (24 hours) before the boundary to influence
     the next cycle's elections.
  4. During that 24-hour window, the adversary's stake is locked
     and earning proportional rewards/penalties, making grinding
     economically costly.  []
```

---

## 8. Ratchet Session Persistence

### Requirement

Signal Double Ratchet and PQ wrapper sessions must be completely independent of chain state and must survive truncation without re-establishment or data loss.

### Analysis

Signal sessions are **local state only** (doc/05-truncation.md lines 110-115):

```
Session state (stored in local encrypted database):
  - Root key (32 bytes)
  - Chain keys (sending and receiving, 32 bytes each)
  - Message keys (skipped keys for out-of-order delivery)
  - Ratchet public keys (DH and PQ)
  - Message counters (monotonic per chain)
  - PQ encapsulated shared secret

Chain state relevant to Signal:
  - NONE. Signal session keys are derived from the X3DH handshake
    and subsequent DH ratchet steps, not from any on-chain data.
```

### Independence Verification

```
Claim: Signal session state S_signal and chain state S_chain are
independent random variables.

Evidence:
  1. Signal root key is derived from X3DH: IK_A, EK_A, SPK_B, OPK_B.
     None of these keys are derived from or dependent on epoch_nonce,
     accumulated_hash, or any chain state variable.

  2. The epoch_nonce is used only in blockchain transaction signatures:
     sign(SHA-256(encrypted_blob || epoch_nonce), sender_key).
     It is NOT mixed into Signal key material.

  3. Signal ratchet steps use DH(ratchet_key_A, ratchet_key_B) and
     KDF(root_key, dh_output). No chain state enters the KDF.

  4. PQ wrapper uses ML-KEM-768 encapsulation, independent of chain.

  5. Message counters are local monotonic integers, not related to
     slot numbers or epoch numbers.

Therefore: truncation (which modifies S_chain) has no effect on
S_signal. Sessions persist across boundaries without interaction.
```

### Edge Cases

```
1. KEY_EXCHANGE during snapshot phase:
   - Rejected (transaction gate closed).
   - The initiator retries in the new cycle with a fresh transaction
     referencing the new epoch_nonce.
   - The X3DH handshake itself is unaffected (key material is
     independent of epoch_nonce).

2. KEY_REPLENISH during snapshot phase:
   - Also rejected. Validators should publish KEY_REPLENISH and
     KEY_ROTATE in the first epoch of the new cycle.
   - Existing sessions are unaffected (they don't need new prekeys).

3. Offline > 11 days:
   - Signal sessions survive (local state).
   - Pending KEY_EXCHANGE transactions from the old cycle are lost.
   - New session establishment requires the peer to re-publish prekeys.
   - Existing sessions resume from the last ratchet state.
```

---

## 9. New Node Synchronization

### Fast Sync Protocol

A node joining after truncation needs only:

```
Required data:
  1. Current cycle's epoch genesis block (~68 MB at 500K users)
     - Contains: validator set, balance ledger, key registry,
       accumulated hash, adaptive parameters, 2/3+ attestations
  2. All blocks from genesis block to current slot
     (at most 22 epochs * 3,927 slots/epoch * 0.20 blocks/slot
      = ~17,279 blocks per cycle)

NOT required:
  - Any block from any prior cycle
  - Any historical accumulated hash chain (beyond what's in the
    genesis block)
  - Any prior cycle's state
```

### Verification Procedure

```
1. Download epoch genesis block from 3+ peers.
2. Verify 2/3+ attestation signatures:
   for each attestation_i in genesis.attestations:
     verify_ed25519(
       validator_pubkey_i,
       attestation_i,
       SHA-256(epoch_number || accumulated_hash || merkle_root)
     )
   Compute total attesting stake weight. Require >= 2/3 of total.

3. Verify Merkle root against embedded state:
   Reconstruct Merkle tree from validator set, balances, key registry.
   Assert root == genesis.merkle_root.

4. Verify accumulated hash:
   The new node cannot independently verify the accumulated hash
   (it doesn't have prior blocks). It trusts the 2/3+ attestation
   as proof of correctness. This is the same trust assumption as
   the underlying Ouroboros Praos consensus.

5. Sync forward: download and validate all blocks from genesis
   to current slot, verifying:
   - VRF proofs for each slot leader
   - Block signatures
   - Transaction validity (nonces, balances, fee computation)
   - Accumulated hash chain (within the current cycle)
```

### Security Argument

```
Theorem (Fast Sync Safety):
  A new node that accepts a genesis block with valid 2/3+ attestation
  and syncs forward from it achieves the same state as a node that
  has been online since network inception.

Proof:
  1. The genesis block's state (balances, validator set, keys) is
     the canonical output of the CycleBoundary function applied to
     the prior cycle's final state.
  2. 2/3+ attestation guarantees that this state was agreed upon by
     the honest majority (under < 1/3 Byzantine stake assumption).
  3. By Theorem (Unforgeable History) from Section 2, the accumulated
     hash binds this genesis block to all prior history.
  4. Forward sync from the genesis block applies the same block
     validation rules as any online node.
  5. By the determinism of the consensus protocol (same inputs
     produce the same state), the new node converges to the same
     state as existing honest nodes.  []
```

### Bandwidth Requirements

```
Genesis block size: ~136 bytes/user * user_count + attestation overhead
  At 500K users: ~68 MB + 64 bytes * validator_count
  At 100K users: ~13.6 MB

Block sync (worst case, full 22-epoch cycle):
  ~17,279 blocks * ~100 KB avg compact block size = ~1.7 GB
  (full blocks: ~17,279 * ~4.44 MB = ~76.7 GB; compact block relay used for sync)

Total sync: ~1.8 GB for a full cycle catchup at 500K users (compact blocks + genesis).
```

---

## 10. Truncation Replay Attack

### Threat

An adversary replays a previous cycle's boundary state (genesis block, accumulated hash, attestations) to trick nodes into accepting a stale or forged cycle.

### Prevention Mechanisms

**Epoch nonce chaining:**

```
epoch_nonce(N) = SHA-256(epoch_nonce(N-1) || last_block_VRF_output(N-1))
epoch_nonce(0) = SHA-256("UmbraVox_genesis_nonce_v1")
```

Each epoch nonce depends on the VRF outputs of the prior epoch, which are unpredictable (VRF security) and unique to each execution. A replayed genesis block from cycle C contains `epoch_nonce(C)`, which differs from the current expected nonce.

**Monotonic epoch counter:**

```
The epoch_number in each genesis block is monotonically increasing.
Nodes reject any genesis block with epoch_number <= their last
accepted epoch_number.

Specifically:
  if genesis.epoch_number <= node.current_epoch:
      REJECT "stale epoch genesis block"
```

**Attestation freshness:**

```
Attestations sign: SHA-256(epoch_number || accumulated_hash || merkle_root)

A replayed attestation from cycle C has epoch_number = E_C.
For the current cycle C' > C, honest nodes expect epoch_number = E_{C'}.
The replayed attestation does not match the expected epoch number and
is rejected.
```

### Formal Proof (Replay Resistance)

```
Theorem (No Truncation Replay):
  An adversary cannot cause an honest node to accept a genesis block
  from cycle C in place of the expected genesis block for cycle C'
  (where C' > C).

Proof:
  1. The honest node maintains current_epoch as monotonically
     increasing state. At the boundary of cycle C', the node expects
     a genesis block with epoch_number = E_{C'}.

  2. A replayed genesis block from cycle C has epoch_number = E_C
     where E_C < E_{C'}. The monotonic epoch check rejects it.

  3. Even if the adversary modifies the epoch_number field to E_{C'},
     the attestation signatures were computed over the original
     (E_C, accumulated_hash_C, merkle_root_C). The modified genesis
     block fails attestation verification:
       verify_ed25519(pubkey_i, attestation_i,
         SHA-256(E_{C'} || accumulated_hash_C || merkle_root_C))
     This check fails because the attestation was signed over E_C,
     not E_{C'}.

  4. To forge new attestations, the adversary needs >= 2/3 stake
     weight, which contradicts the < 1/3 assumption.  []
```

### Variant: Replay Within Same Cycle

An adversary cannot replay an earlier epoch's genesis block within the same cycle because:

- Epoch numbers within a cycle are sequential.
- The node tracks the current epoch and rejects any genesis block with a non-incrementing epoch number.
- The accumulated hash covers all blocks since the last genesis, which differs between epochs.

---

## 11. Formal Safety Proof

### Theorem (Truncation Preserves Consensus Safety)

No two honest nodes finalize conflicting blocks across a truncation boundary.

### Setup

```
Let:
  k_msg = 11, k_val = 22 (two-tier security parameter)
  S_N = consensus state at end of cycle N
  S_{N+1} = consensus state at start of cycle N+1
  B = CycleBoundary transition
  chain_i = chain maintained by honest node i
```

### Proof

We must show that if blocks B1 and B2 are both finalized (at depth >= k) by honest nodes i and j respectively, then B1 and B2 are not conflicting (i.e., they are on the same chain or one is an ancestor of the other).

**Case 1: B1 and B2 are both in cycle N.**

Standard Ouroboros Praos safety applies. Under < 1/3 Byzantine stake, the probability of two honest nodes finalizing conflicting blocks at depth k decreases exponentially with k. At k=11 (messages), reversal probability is < 1/2,048; at k=22 (value), reversal probability is < 1/4,194,304.

**Case 2: B1 is in cycle N, B2 is in cycle N+1.**

```
B1 is finalized in cycle N at depth >= k.
  => B1 is included in the accumulated hash H_N.
  => H_N is committed in the genesis block G_{N+1} of cycle N+1.
  => G_{N+1} has 2/3+ attestation.

B2 is finalized in cycle N+1 at depth >= k.
  => B2's chain extends from G_{N+1}.
  => B2's chain includes B1 (transitively, via H_N in G_{N+1}).

Therefore B1 and B2 are on the same chain (B1 is an ancestor of
G_{N+1} which is an ancestor of B2). No conflict.
```

**Case 3: B1 is in cycle N, B2 is in cycle N+2 or later.**

By induction on the number of boundaries crossed:

```
B1 is committed in H_N, which is in G_{N+1}.
G_{N+1} is committed in H_{N+1}, which is in G_{N+2}.
...
G_{N+m-1} is committed in H_{N+m-1}, which is in G_{N+m}.
B2 extends G_{N+m}.

The accumulated hash chain H_N -> H_{N+1} -> ... -> H_{N+m}
ensures B1 is an ancestor of B2's chain (transitively).
No conflict.
```

**Case 4: Competing genesis blocks.**

```
Suppose adversary produces G'_{N+1} != G_{N+1} with a different
accumulated hash H'_N.

G'_{N+1} requires 2/3+ attestation over (E_{N+1}, H'_N, merkle_root').
Since honest validators (> 2/3 stake) only attest to the correct H_N,
G'_{N+1} cannot achieve 2/3+ attestation.

Therefore there is a unique genesis block per cycle boundary,
and all honest nodes agree on it.
```

**Conclusion.** Truncation boundaries do not introduce new opportunities for conflicting finalization. The accumulated hash chain and 2/3+ attestation requirement ensure that the post-truncation chain is a consistent extension of the pre-truncation chain. Consensus safety is preserved across all boundaries. []

### Liveness Across Boundaries

```
Theorem (Truncation Preserves Liveness):
  Under < 1/3 Byzantine stake, all valid transactions submitted
  after a truncation boundary are eventually included in a
  finalized block.

Proof:
  1. The truncation boundary produces a valid genesis block
     (guaranteed by Theorem (Truncation Liveness) from Section 5).
  2. The genesis block establishes a valid initial state for the
     new cycle (validator set, balances, nonce).
  3. Ouroboros Praos liveness holds for the new cycle: under < 1/3
     Byzantine stake, honest slot leaders are elected with
     probability >= f * (2/3) per slot, and they include valid
     transactions from the mempool.
  4. The transaction gate reopens after boundary completion,
     admitting new transactions to the mempool.
  5. By Ouroboros Praos liveness, these transactions are included
     within O(1/f) slots in expectation.  []
```

---

## Summary of Security Properties

| Property | Mechanism | Proven |
|----------|-----------|--------|
| Boundary atomicity | Transaction gate + WAL + exclusive lock | Section 1 |
| History integrity | Accumulated hash chain + 2/3+ attestation | Section 2 |
| Invariant preservation | Case analysis on all 12 invariants (cross-ref proof-04) | Section 3 |
| Early truncation cost | Superlinear fee escalation + adaptive controller | Section 4 |
| Truncation liveness | Time-based trigger (slot counter) | Section 5 |
| No silent data loss | Explicit categorization of all transaction states | Section 6 |
| Stake stability | 2-epoch delayed snapshots + exit cooldown | Section 7 |
| Ratchet independence | Signal state is local-only, no chain state dependency | Section 8 |
| Fast sync safety | 2/3+ attestation on genesis block | Section 9 |
| Replay resistance | Epoch nonce chaining + monotonic counter | Section 10 |
| Consensus safety | Accumulated hash chain extends Ouroboros Praos safety | Section 11 |

### Open Items for Implementation

1. **Transaction gate timing.** The 100-slot snapshot phase must be long enough for 2/3+ attestation collection under realistic network latency. If attestation collection regularly requires the extended 200-slot window, consider increasing the base snapshot phase.

2. **Genesis block size at scale.** At 1M+ users, the genesis block exceeds 136 MB. Consider Merkle proof compression or state diff encoding for bandwidth-constrained nodes.

3. **WAL corruption.** The WAL assumes a crash-safe filesystem (fsync guarantees). On filesystems without true fsync semantics (some network-attached storage), additional checksumming of WAL entries is required.

4. **Clock drift during snapshot.** If NTP becomes unavailable during the snapshot phase, nodes fall back to peer-median timestamps. Verify that peer-median convergence is fast enough to keep all honest nodes within the 11-second slot tolerance during the critical attestation window.
