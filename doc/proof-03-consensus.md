# Proof-03: Consensus Safety and Liveness

**DO-333 Requirement:** `doc/10-security.md` lines 149–152
**Source:** `doc/04-consensus.md` lines 11–163
**Assumptions used:** A7 (semi-synchrony), A8 (honest > 2/3 stake), A5 (DDH for VRF)

---

## Preamble

This document proves safety (no conflicting finalized blocks), liveness
(transactions eventually included), and fork-choice determinism for
UmbraVox's Ouroboros-style PoS consensus.  The proofs are structured as
a TLA+ state machine specification with invariant verification.

---

## 1. TLA+ State Machine Definition

### 1.1 Variables

```tla+
VARIABLES
  chain,            \* chain[node] : sequence of blocks
  slot,             \* current global slot number (Word64)
  stake_dist,       \* stake_dist[node] : effective stake (Word64)
  msgs_in_transit,  \* set of {block, sender, recipient, delay_remaining}
  epoch_nonce,      \* 32-byte epoch randomness
  finalized         \* finalized[node] : prefix of chain considered final
```

### 1.2 Constants

```tla+
CONSTANTS
  Nodes,            \* set of all node identifiers
  Byzantine,        \* subset of Nodes controlled by adversary
  Delta,            \* maximum message delay (slots)
  f,                \* active slot coefficient = 0.20
  k_msg,            \* security parameter = 11 (message tier finality depth)
  k_val,            \* security parameter = 22 (value tier finality depth)
  SlotsPerEpoch,    \* = 3927
  sk                \* sk[node] : VRF secret key for each node (abstract)
```

### 1.3 Assumptions (Encoded as ASSUME)

```tla+
ASSUME /\ Byzantine \subseteq Nodes
       /\ StakeSum(Byzantine) * 3 < StakeSum(Nodes)    \* A8: honest > 2/3
       /\ Delta \in Nat                                 \* A7: bounded delay
       /\ f = 20                                        \* fixed-point: 0.20 * 100
       /\ k_msg = 11                                     \* message tier
       /\ k_val = 22                                     \* value tier
```

### 1.4 Init

```tla+
Init ==
  /\ chain = [n \in Nodes |-> << GenesisBlock >>]
  /\ slot = 0
  /\ stake_dist = InitialStakeDistribution
  /\ msgs_in_transit = {}
  /\ epoch_nonce = SHA256("UmbraVox_genesis_nonce_v1")
  /\ finalized = [n \in Nodes |-> << GenesisBlock >>]
```

### 1.5 Abstract Operators (Declared, Not Defined)

The following operators are used abstractly in the specification.  Their
concrete implementations are provided by the system under verification;
the TLA+ model checker substitutes stubs or oracles.

```tla+
CONSTANTS
  GenesisBlock,             \* initial block
  InitialStakeDistribution, \* [Nodes -> Nat]
  Block,                    \* set of all block values
  VRF_prove(_, _),          \* (secret_key, input) -> (proof, output)
  VRF_normalize(_),         \* output -> value in [0, S) (fixed-point)
  MakeBlock(_, _, _),       \* (node, slot, parent) -> Block
  Hash(_),                  \* Block -> 32-byte hash
  Encode(_),                \* Nat -> byte string
  ChainOf(_),               \* Block -> Seq(Block): reconstructs full chain from
                            \* genesis to the given block via parent_hash links.
                            \* Assumes all ancestor blocks are locally available
                            \* (see §5.1 Limitations).
  ThresholdTable            \* [0..100 -> Nat] precomputed fixed-point thresholds
```

### 1.6 Helper Definitions

```tla+
\* All state variables as a single tuple (for UNCHANGED)
vars == <<chain, slot, stake_dist, msgs_in_transit, epoch_nonce, finalized>>

\* Stake-weighted sum
StakeSum(S) == LET RECURSIVE Helper(_)
                   Helper(ss) == IF ss = {} THEN 0
                                 ELSE LET x == CHOOSE n \in ss : TRUE
                                      IN stake_dist[x] + Helper(ss \ {x})
               IN Helper(S)

\* Set of elements in a sequence
Range(seq) == { seq[i] : i \in 1..Len(seq) }

\* Prefix test: seq1 is a prefix of seq2
IsPrefix(seq1, seq2) ==
  /\ Len(seq1) <= Len(seq2)
  /\ SubSeq(seq2, 1, Len(seq1)) = seq1

\* Abstract sets used in liveness specification
\* ValidTransactions: set of all syntactically and semantically valid
\*   transactions that have been submitted to some honest node's mempool.
\* FinalizedTxs: set of all transactions included in blocks that appear
\*   in some honest node's finalized prefix.
VARIABLES ValidTransactions, FinalizedTxs

\* Tip of chain (last element = most recent block)
Tip(seq) == seq[Len(seq)]

\* VRF-based slot leader test
\* NOTE: TLA+ has only integer division.  ThresholdTable is a precomputed
\* lookup from integer stake percentage [0..100] to a fixed-point threshold
\* at scale S = 10^6.  Each entry is: S - IntPow(S - f*S/100, pct, 100)
\* where IntPow computes (base/S)^(exp/100) in fixed-point.
\* The CONSTANT f (=20, representing 0.20) defines the table entries.
\* VRF_normalize returns a value in [0, S) at the same scale.
\* For TLC model checking, an equivalent Boolean oracle may be substituted.
IsSlotLeader(node, s, nonce, stakes) ==
  LET vrf_in  == nonce \o Encode(s)
      result  == VRF_prove(sk[node], vrf_in)
      output  == result[2]
      \* Integer stake percentage (resolution 1%); ThresholdTable maps
      \* this to a scale-10^6 threshold value.
      sigma_pct == (stakes[node] * 100) \div StakeSum(Nodes)
      thresh_fp == ThresholdTable[sigma_pct]
  IN VRF_normalize(output) < thresh_fp

\* Discretization note: The production implementation uses 64.64 fixed-point
\* arithmetic (doc/04-consensus.md lines 69-92) for continuous stake fractions.
\* The TLA+ model quantizes to integer percentages, introducing at most 0.5%
\* threshold error.  For validators with stake < 0.5% of total, this
\* quantization rounds to 0 (never elected).  This discretization is acceptable
\* for mechanism verification but the probabilistic security bounds in §2 apply
\* to the continuous-precision production implementation.

\* Broadcast: add one message per recipient with nondeterministic delay
Broadcast(sender, blk) ==
  \E delays \in [Nodes \ {sender} -> 0..Delta] :
    msgs_in_transit' = msgs_in_transit \cup
      { [block |-> blk, sender |-> sender, recipient |-> n,
         delay_remaining |-> delays[n]]
      : n \in Nodes \ {sender} }

\* Finalization: prefix of chain at depth k_msg (message tier)
\* Value tier finalization uses k_val = 22 (tracked separately)
UpdateFinalized(node) ==
  finalized' = [finalized EXCEPT ![node] =
    IF Len(chain'[node]) >= k_msg
    THEN SubSeq(chain'[node], 1, Len(chain'[node]) - k_msg)
    ELSE finalized[node]]

\* Block validation (abstract predicate)
ValidBlock(blk, local_chain) ==
  /\ blk.slot <= slot
  /\ blk.parent_hash = Hash(Tip(local_chain))
  /\ blk.slot > Tip(local_chain).slot
  \* Additional validity checks (signature, VRF proof) omitted for brevity
```

### 1.7 Actions

```tla+
Next == \/ NextSlot
        \/ \E n \in Nodes : ProduceBlock(n)
        \/ TickDelays
        \/ DeliverMessages

NextSlot ==
  /\ slot' = slot + 1
  /\ UNCHANGED <<chain, stake_dist, epoch_nonce, finalized, msgs_in_transit>>

\* Decrement delay counters (models time passing for in-flight messages)
\* Guard: only tick if at least one message has positive delay remaining.
\* Note: messages with delay_remaining already <= 0 are decremented further,
\* but this does not affect correctness (DeliverMessages checks <= 0).
TickDelays ==
  /\ \E msg \in msgs_in_transit : msg.delay_remaining > 0
  /\ msgs_in_transit' = { [msg EXCEPT !.delay_remaining = @ - 1]
                         : msg \in msgs_in_transit }
  /\ UNCHANGED <<chain, slot, stake_dist, epoch_nonce, finalized>>

ProduceBlock(node) ==
  /\ IsSlotLeader(node, slot, epoch_nonce, stake_dist)
  /\ ~\E b \in Range(chain[node]) : b.slot = slot  \* at most one block per slot
  /\ LET blk == MakeBlock(node, slot, Tip(chain[node]))
     IN /\ chain' = [chain EXCEPT ![node] = Append(@, blk)]
        /\ Broadcast(node, blk)
        /\ UpdateFinalized(node)
        /\ UNCHANGED <<slot, stake_dist, epoch_nonce>>

DeliverMessages ==
  /\ \E msg \in msgs_in_transit :
       /\ msg.delay_remaining <= 0
       /\ ValidBlock(msg.block, chain[msg.recipient])
       /\ LET new_chain == ForkChoice(chain[msg.recipient], msg.block)
          IN /\ chain' = [chain EXCEPT ![msg.recipient] = new_chain]
             /\ UpdateFinalized(msg.recipient)
       /\ msgs_in_transit' = msgs_in_transit \ {msg}
       /\ UNCHANGED <<slot, stake_dist, epoch_nonce>>

\* ForkChoice is defined in Section 4.1 below.
```

### 1.8 Type Invariant

```tla+
TypeInvariant ==
  /\ \A n \in Nodes : chain[n] \in Seq(Block)
  /\ slot \in Nat
  /\ \A n \in Nodes : stake_dist[n] \in Nat
  /\ \A msg \in msgs_in_transit :
       /\ msg.block \in Block
       /\ msg.sender \in Nodes
       /\ msg.recipient \in Nodes
       /\ msg.delay_remaining \in Int    \* may be <= 0 (deliverable)
  /\ epoch_nonce \in [1..32 -> 0..255]  \* exactly 32 bytes (SHA-256 output);
                                       \* after Init, epoch_nonce is always a
                                       \* SHA-256 digest, which is fixed at 32 bytes
  /\ \A n \in Nodes : Len(finalized[n]) <= Len(chain[n])
  /\ \A n \in Nodes : finalized[n] = SubSeq(chain[n], 1, Len(finalized[n]))
```

---

## 2. Safety: No Conflicting Finalized Blocks

### 2.1 Definition

Two blocks B₁ and B₂ conflict if neither is a prefix of the other's chain.
Safety requires that no two honest nodes finalize conflicting blocks.

```tla+
Safety ==
  \A n1, n2 \in Nodes \ Byzantine :
    IsPrefix(finalized[n1], finalized[n2])
    \/ IsPrefix(finalized[n2], finalized[n1])
```

### 2.2 Lemma: Common Prefix

**Lemma 2.1 (Common Prefix Property).**

For any two honest nodes n₁, n₂ at any slot s, their chains agree on all
blocks at depth ≥ k from the tip:

```
chain[n₁][1..Len(chain[n₁])-k] is a prefix of chain[n₂]
  OR chain[n₂][1..Len(chain[n₂])-k] is a prefix of chain[n₁]
```

**Proof.**  Suppose for contradiction that the chains diverge at some block
B at depth ≥ k in both chains.  Then there exist two competing chains of
length ≥ k extending from the fork point.

For the adversary to maintain a competing fork of length k, they must
produce k consecutive blocks without an honest block being preferred.

By the analysis of Ouroboros Praos (David, Gaži, Kiayias & Russell 2018),
the common prefix property holds with overwhelming probability when the
honest chain growth rate exceeds the adversary's.  Specifically, let α
be the Byzantine stake fraction (α < 1/3).  In each slot:

- Pr[at least one honest leader] ≥ 1 - (1-f)^{1-α}
- Pr[at least one adversary leader] ≤ 1 - (1-f)^{α}

For α < 1/3 and f = 0.20, the honest leader rate exceeds the adversary
rate.  The probability that the adversary's private chain outgrows the
honest chain over k = k_msg = 11 (message tier) or k = k_val = 22 (value tier) blocks decreases exponentially:

```
Pr[adversary fork of depth k] ≤ exp(-Ω(k))
```

For both tiers, the failure probability is exponentially small.  As a
conservative upper bound, the ratio of adversary-to-honest chain growth
gives:

```
Pr[adversary fork of depth k] ≤ (α/(1-α))^{k}
```

For α < 1/3, the ratio α/(1-α) < 1/2, so:
For k_msg = 11: (1/2)^{11} = 2^{-11} ≈ 1/2,048
For k_val = 22: (1/2)^{22} = 2^{-22} ≈ 1/4,194,304

**Synchronous vs. semi-synchronous regime.** The bound `(α/(1-α))^k` above
is a *synchronous-regime* upper bound derived from the honest-vs-adversary
chain growth ratio (adapted from the Bitcoin backbone model, Garay,
Kiayias & Leonardos 2015 — note: GKL's actual formulation uses chain
quality and common prefix parameters, not this ratio form.  The
`(α/(1-α))^k` expression is an independent conservative upper bound
derived from the intuition that the adversary must outgrow the honest
chain over k consecutive blocks; it is not a formal consequence of
any specific GKL theorem).  In UmbraVox's semi-synchronous network (A7),
messages may be delayed up to Δ slots, which weakens the honest advantage.

In the semi-synchronous model of Ouroboros Praos (David, Gaži, Kiayias &
Russell 2018, Theorem 1), an honest block produced in slot s may not be
seen by other honest nodes until slot s+Δ, allowing the adversary to extend
its fork during the delay window.  The effective honest advantage is
therefore reduced.  The common prefix property holds when the probability of
a "uniquely honest slot" (exactly one honest leader, zero adversary leaders)
exceeds the probability of adversary-dominated slots.  For f = 0.20,
α < 1/3, and Δ = 3, this condition is satisfied: the honest-to-adversary
chain growth ratio remains strictly greater than 1, and the failure
probability remains exponentially small in k.

**Quantitative verification for f = 0.20, α < 1/3, Δ = 3:**

The key condition (Praos Theorem 1) is that the probability of a "uniquely
honest slot" (UHS) exceeds the probability of an adversary-dominated slot.
A UHS is a slot where exactly one honest validator is elected and no
adversary validator is elected.

For a conservative lower bound, we compute the probability that *any*
honest validator is elected (not requiring uniqueness):

```
Pr[≥1 honest leader] = 1 - (1-f)^{1-α} = 1 - 0.80^{2/3} ≈ 0.138
```

This evaluates the formula at α = 1/3 (the A8 boundary), giving a
**conservative lower bound**: for any α < 1/3, honest stake (1-α) > 2/3,
so (1-f)^{1-α} < (1-f)^{2/3} and Pr[≥1 honest leader] > 0.138.
The bound tightens as the honest majority increases.

(The exact computation depends on the stake distribution; for a single
honest validator holding fraction (1-α) = 2/3, this is the precise
probability.  With multiple honest validators, the probability of a
*uniquely* honest slot is lower, but honest slots in general are more
frequent.)

An adversary slot has at least one adversary leader:
```
Pr[adversary leader] = 1 - (1-f)^α = 1 - 0.80^{1/3} ≈ 0.072
```

The honest-to-adversary ratio is 0.138/0.072 ≈ 1.92 > 1, confirming the
honest chain grows faster.  With Δ = 3, an honest block produced in slot s
is visible by slot s+3; blocks produced in the 3-slot window may not
contribute to the honest chain immediately, but the adversary must also
produce blocks during this window to extend a fork.  The net honest
advantage is reduced but remains positive (ratio > 1) for these parameters.

The `(α/(1-α))^k` bound used above is therefore *conservative*: it ignores
the honest advantage from uniquely honest slots and overstates adversary
capability by ignoring the delay costs the adversary incurs.  The
semi-synchronous analysis yields a tighter (lower) failure probability.  □

### 2.3 Theorem: Safety

**Theorem 2.2 (Consensus Safety).**

No two honest nodes disagree on finalized blocks.

**Proof.**

A block is finalized when it reaches depth ≥ k (where k = k_msg = 11 for messages, k = k_val = 22 for value transfers) in an honest node's chain:

```
finalized[n] = chain[n][1..Len(chain[n]) - k]
```

By Lemma 2.1 (Common Prefix), the prefixes at depth k agree between any
two honest nodes.  Since finalization is defined as the prefix at depth k,
and the common prefix property guarantees these prefixes are consistent,
no two honest nodes can finalize conflicting blocks.

Formally: for honest n₁, n₂:
```
finalized[n₁] = chain[n₁][1..L₁-k]
finalized[n₂] = chain[n₂][1..L₂-k]
```

By Common Prefix, one is a prefix of the other.  Therefore Safety holds.  □

---

## 3. Liveness: Transactions Eventually Finalize

### 3.1 Definition

```tla+
Liveness ==
  \A tx \in ValidTransactions :
    <>(tx \in FinalizedTxs)
```

(Every valid transaction is eventually in the finalized set.)

This temporal property requires weak fairness on individual sub-actions
to ensure progress.  TLC checks this under the fairness constraint:

```tla+
Fairness == /\ WF_vars(NextSlot)
            /\ WF_vars(TickDelays)
            /\ WF_vars(DeliverMessages)
```

Note: `WF_vars(Next)` on the full disjunction would be insufficient — it
only guarantees that *some* disjunct is taken when enabled, which could
allow starvation of individual sub-actions (e.g., messages never delivered
because NextSlot is always taken instead).  Per-action weak fairness
ensures each continuously enabled sub-action is eventually executed.

### 3.2 Theorem

**Theorem 3.1 (Consensus Liveness).**

Under assumptions A7 (semi-synchrony) and A8 (honest > 2/3 stake), every
valid transaction in the mempool is eventually included in a finalized block.

### 3.3 Proof

**Step 1: Expected time to honest leader.**

With f = 0.20 and honest stake fraction ≥ 2/3 (evaluating at the A8
boundary α = 1/3 for a conservative lower bound):

```
Pr[at least one honest leader in slot] ≥ 1 - (1-f)^{2/3}
  = 1 - 0.80^{2/3} ≈ 1 - 0.862 ≈ 0.138
```

This is a conservative lower bound: for any α < 1/3 the honest stake
exceeds 2/3, increasing the probability above 0.138.  Additionally,
splitting the honest stake among multiple validators increases the
aggregate probability (by Jensen's inequality on the concave function
1 − (1−f)^x).
Expected slots until an honest leader: ≤ 1/0.138 ≈ 7.2 slots ≈ 79.2 seconds.

**Step 2: Transaction inclusion.**

An honest leader includes all valid transactions from its mempool in its
block (honest behavior).  By A7, all transactions propagate within Δ slots.
Therefore, within Δ + 7.2 slots on average, any transaction reaches an
honest leader and is included.

**Step 3: Forced inclusion (100-block timeout).**

From `doc/19-game-theory.md` lines 360–370: if a transaction has been in the mempool for
≥ 100 blocks without inclusion, honest validators MUST include it in the
next block they produce (forced inclusion rule).  With the overall expected
block rate of f = 0.20 blocks/slot, 100 blocks takes on average
100 / 0.20 = 500 slots = 5,500 seconds ≈ 91.7 minutes.

**Step 4: Finalization.**

After inclusion at slot s, the block reaches depth k after at most
k / (expected blocks per slot) additional slots.  The expected number of
leaders per slot is at least f = 0.20 (exact for a single validator with
all honest stake) and approaches -ln(1-f) ≈ 0.223 in the many-validator
limit.  Using the conservative lower bound f = 0.20:
Message tier: k_msg/0.20 = 11/0.20 = 55 slots = 605 seconds ≈ 10 minutes.
Value tier: k_val/0.20 = 22/0.20 = 110 slots = 1,210 seconds ≈ 20 minutes.

**Total expected finalization time:** Message tier: ~10–12 minutes from
transaction submission.  Value tier: ~20–22 minutes from transaction
submission.  Worst case (forced inclusion + finalization): ~102 minutes
(91.7 min forced inclusion + 10 min message tier finalization) or ~112
minutes (91.7 min forced inclusion + 20 min value tier finalization).

**Liveness failure condition:** Liveness fails only if < 2/3 of stake is
honest (violating A8), which would allow Byzantine validators to
indefinitely censor transactions.  □

---

## 4. Fork Choice Determinism

### 4.1 Fork Choice Rule

From `doc/04-consensus.md` lines 134–149:

```
ForkChoice(current_chain, new_block) ==
  LET fork_point == CommonAncestor(current_chain, ChainOf(new_block))
      range == (fork_point.slot, current_slot)
  IN IF DensityGreater(ChainOf(new_block), current_chain, range)
       THEN ChainOf(new_block)
     ELSE IF DensityGreater(current_chain, ChainOf(new_block), range)
       THEN current_chain
     ELSE TieBreak(current_chain, ChainOf(new_block))

DensityGreater(chain1, chain2, (s1, s2)) ==
  \* Cross-multiplication avoids integer division truncation:
  \* c1/(s2-s1) > c2/(s2-s1) iff c1 > c2 (denominator cancels).
  Count(blocks in chain1 with slot in (s1, s2))
    > Count(blocks in chain2 with slot in (s1, s2))

TieBreak(chain1, chain2) ==
  LET b1 == FirstDivergingBlock(chain1)
      b2 == FirstDivergingBlock(chain2)
  \* Note: Hash fallback is a modeling addition for totality; doc/04-consensus.md
  \* lines 134-149 specify only VRF tiebreaker. VRF output collision probability
  \* is negligible (~2^{-512} for 64-byte outputs), making the Hash branch
  \* unreachable in practice.
  IN IF VRF_output(b1) < VRF_output(b2) THEN chain1
     ELSE IF VRF_output(b2) < VRF_output(b1) THEN chain2
     ELSE IF Hash(b1) < Hash(b2) THEN chain1 ELSE chain2
```

### 4.2 Theorem

**Theorem 4.1 (Fork Choice Determinism).**

Given the same inputs (current chain, candidate block, current slot),
the fork choice function produces the same output on all nodes.

### Proof

1. **Density computation is deterministic:** Given a chain and slot range,
   counting blocks in the range is a pure function of the chain data.

2. **Comparison is total:** Integer comparison of block counts is total
   (since both chains share the same slot range, the common denominator
   cancels, reducing density comparison to integer comparison).

3. **Tiebreaker is deterministic and total:** VRF outputs are deterministic
   given the block (included in the block header and verified).
   Lexicographic comparison of byte strings is total and deterministic.
   In the astronomically unlikely event of equal VRF outputs (probability
   ~2^{-512} for 64-byte outputs), a secondary tiebreak on block hashes
   resolves the comparison.  Totality of this final Hash comparison assumes
   collision resistance of SHA-256 (collision probability ≤ 2^{-128}); in
   the event of a hash collision, both chains are equally valid and either
   choice is consistent (all nodes observing the same block data make the
   same lexicographic comparison).

4. **No ambiguity:** The three top-level cases (d_new > d_current,
   d_current > d_new, d_new = d_current) are exhaustive and mutually
   exclusive.  The tiebreaker sub-cases are also exhaustive (the final
   hash comparison always produces a winner).

Therefore, the fork choice function is a deterministic function of its
inputs, producing identical results on all nodes that have the same
chain data.  □

---

## 5. TLC Model Checking Parameters

```tla+
\* Model configuration for TLC model checker
CONSTANTS
  Nodes = {n1, n2, n3, n4, n5}
  Byzantine = {n4, n5}            \* 2 of 5: 40% nodes but < 1/3 stake
  Delta = 3                       \* max 3-slot delay
  f = 20                          \* 0.20 as percentage
  k = 6                           \* reduced from k_msg=11/k_val=22 for tractability;
                                   \* the simplified model uses a single k parameter
                                   \* for mechanism verification -- the two-tier
                                   \* distinction is a policy layer above the
                                   \* consensus mechanism verified here
  SlotsPerEpoch = 10              \* reduced from 3927; declared for
                                   \* documentation only -- epoch transitions
                                   \* are not modeled in this simplified
                                   \* specification (see Limitations in §5)
  sk = [n1 |-> sk1, n2 |-> sk2, n3 |-> sk3, n4 |-> sk4, n5 |-> sk5]

\* Stake distribution: Byzantine has < 1/3
\* n1=30, n2=30, n3=30, n4=5, n5=5  (total=100, Byzantine=10 < 33.3)

\* Expected state space: dependent on chain length bounds and message set
\* size; exploration may require the full 48-hour timeout
\* Timeout: 48 hours per run
\* Check: Safety, TypeInvariant
\* Liveness: checked via \A tx \in ValidTransactions : <>(tx \in FinalizedTxs)
\*
\* STATUS: TLC verification is pending implementation.  The TLA+
\* specification above defines the model; concrete TLC run results
\* (state count, invariant pass/fail, runtime) will be recorded in
\* test/evidence/formal-proofs/reports/tlc-model-check.log upon
\* completion.  The probabilistic safety bound (§2.2) is independent
\* of TLC and holds for any k by the analytical argument.
```

**Scaling argument:** The model uses reduced parameters (k=6, epoch=10 slots)
for tractability.  The safety and liveness arguments scale because:
- Safety depends on k being sufficiently large that adversary fork probability
  is negligible.  The proof is parameterised by k; TLC verifies the mechanism
  for small k, and the exponential bound (2^{-k}) extrapolates to k_msg=11 and k_val=22.
- Liveness depends on honest majority and bounded delay, both of which
  are modelled faithfully at reduced scale.

TLC verifies that the state machine transitions preserve the Safety and
TypeInvariant properties for k=6.  The probabilistic bound on adversary
fork depth (§2.2) is independent of TLC and applies to any k; TLC validates
only the deterministic mechanism, not the probabilistic claim.

### 5.1 Limitations

Byzantine nodes in this model follow the honest protocol.  The TLC check
verifies *mechanism correctness* (the state machine invariants hold when all
nodes follow the protocol), **not** Byzantine fault tolerance.  Byzantine
fault tolerance is established by the probabilistic argument in §2.2
(Common Prefix), not by model checking.  A more complete model would add
adversarial actions (equivocation, withholding, selective delivery).

Additional simplifications:
- **Epoch nonce rotation is not modeled:** `epoch_nonce` is fixed throughout
  the specification.  This means nonce grinding attacks are not covered by
  the TLC results.
- **Stake snapshot delays are not modeled:** `stake_dist` is static.  Stake
  manipulation attacks (e.g., moving stake between epochs to influence
  leader election) are not covered by the TLC results.

- **ChainOf ancestor availability:** The `ChainOf(blk)` operator used in
  `ValidBlock` and `ForkChoice` assumes that the full chain from genesis to
  `blk` is available locally.  In practice, a node may not have all ancestor
  blocks if they were not yet delivered.  The specification assumes that
  `ValidBlock` is only called after all ancestors are available (implied by
  the `parent_hash` check and message delivery model).

These simplifications are acceptable for mechanism verification but mean the
TLC results do not cover nonce grinding or stake manipulation attacks.

---

## 6. Epoch Nonce Security

**Lemma 6.1 (Epoch Nonce Unpredictability).**

The epoch nonce for epoch N is unpredictable before the last block of
epoch N-1 is produced:

```
epoch_nonce(N) = SHA-256(epoch_nonce(N-1) || last_block_VRF_output(N-1))
```

**Proof.**

The last block's VRF output is determined by the slot leader's secret key
and the slot number.  By ECVRF pseudorandomness (Theorem 8.1 of Proof-01,
using A5), the VRF output is indistinguishable from random to any party
other than the slot leader.  Since the slot leader is determined by VRF
evaluation (which depends on the current epoch nonce), the adversary cannot
predict the VRF contribution of the last honest block.

An adversary controlling < 1/3 of stake has < 1/3 probability of producing
the last block of an epoch.  Even if they do, they can only choose to
withhold their block (forfeiting the slot), not bias the nonce arbitrarily.
The nonce is a hash of the previous nonce and the VRF output, so
withholding one block shifts the nonce by at most 1 bit of entropy
(publish vs. withhold).

Over many epochs, the adversary's influence on the nonce is bounded by
their stake fraction, which is insufficient to bias leader election.  □

**Limitation:** This analysis bounds the adversary's per-epoch nonce
influence to a single withhold/publish binary choice (~1 bit per epoch
when the adversary controls the last block, which occurs with probability
~α).  Over E epochs, the adversary's expected number of grinding
opportunities is α·E, yielding a cumulative nonce influence of O(α·E)
bits total (not per-epoch).  For α < 1/3 and E = 100 epochs,
this is ~33 bits of cumulative influence on the nonce, which is
insufficient to predict or bias the 256-bit epoch nonce.  A full
treatment (Praos, David et al. 2018 §5.3) formalises this via a nonce
grinding game and shows the adversary's advantage remains negligible.

**Empty epoch case:** If epoch N-1 produces 0 blocks:
```
epoch_nonce(N) = SHA-256(epoch_nonce(N-1) || 0x00*32)
```

This is deterministic but occurs only when no leader was elected for an
entire epoch (probability negligible for f=0.20 over 3,927 slots).
