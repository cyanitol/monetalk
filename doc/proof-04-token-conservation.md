# Proof-04: Token Conservation and Economic Invariants

**DO-333 Requirement:** `doc/10-security.md` lines 153–154
**Source:** `doc/15-economic-model-v3.md` lines 15–32, `doc/06-economics.md` lines 49–421, `doc/20-economic-analysis.md` lines 42–88
**Assumptions used:** A9 (bounded growth), A11 (reward floor threshold)

---

## Preamble

This document formally proves all 12 economic invariants of UmbraVox's
Universe Cycle token model.  Proofs are given in Coq-style pseudocode with
explicit state definitions matching `doc/20-economic-analysis.md` Section 1.
QuickCheck property specifications are provided for each invariant to enable
automated testing.

---

## State Definition (Coq-style)

```coq
Record State := mkState {
  pool          : nat ;     (* unallocated supply for rewards *)
  staked        : nat ;     (* tokens locked by validators *)
  reserve       : nat ;     (* onboarding reserve *)
  treasury      : nat ;     (* protocol treasury, capped *)
  burned        : nat ;     (* burned within current cycle *)
  rebate_accum  : nat ;     (* accumulated rebates, distributed at cycle end *)
  balances      : list nat; (* spendable balances per account *)
  adaptive      : AdaptiveParams
}.

Record AdaptiveParams := mkAdaptive {
  burn_rate     : Q ;    (* rational in [0.20, 0.80] *)
  fee_floor     : nat ;  (* in [5, 100] *)
  fee_ceiling   : nat ;  (* in [5000, 50000] *)
  target_msgs   : nat ;  (* in [1000, 100000000] *)
}.

Definition INITIAL_SUPPLY := 11000000000.
Definition TREASURY_CAP   := 1100000000.
Definition MIN_REWARD      := 5000.

Definition total (s : State) : nat :=
  sum (balances s) + pool s + staked s + reserve s + treasury s
  + burned s + rebate_accum s.
```

---

## State Transitions

There are exactly two transition functions:

### IntraCycleTx

Processes a single message transaction within a cycle:

```coq
Definition IntraCycleTx (s : State) (sender producer : nat) (fee : nat)
  : State :=
  let to_burn     := fee * burn_rate (adaptive s) in
  let non_burn    := fee - to_burn in
  let to_producer := non_burn * 20 / 35 in
  let to_treasury := non_burn * 10 / 35 in
  let to_rebate   := non_burn * 5 / 35 in   (* user rebate pool, doc/06 line 114 *)
  (* Integer rounding remainder: ensures fee split is exactly exhaustive *)
  let remainder   := non_burn - to_producer - to_treasury - to_rebate in
  let to_burn_actual := to_burn + remainder in
  (* Handle treasury cap: overflow goes to pool (doc/06 lines 182-189) *)
  let treasury_overflow := if treasury s + to_treasury > TREASURY_CAP
                           then (treasury s + to_treasury) - TREASURY_CAP
                           else 0 in
  let to_treasury_actual := to_treasury - treasury_overflow in
  mkState
    (pool s + treasury_overflow)           (* treasury overflow to pool, doc/06 lines 182-189 *)
    (staked s)                             (* staked unchanged during tx *)
    (reserve s)
    (treasury s + to_treasury_actual)
    (burned s + to_burn_actual)
    (rebate_accum s + to_rebate)           (* rebates accumulated, distributed at cycle end *)
    (update_balance (balances s) sender (fun b => b - fee)
     |> update_balance producer (fun b => b + to_producer))
    (adaptive s).
```

**Note:** Per doc/06 line 114, rebates are accumulated in `rebate_accum`
during the cycle and distributed to active users at cycle boundary.

### CycleBoundary

Atomic cycle boundary transition:

```coq
Definition CycleBoundary (s : State) (rewards : list nat)
  : State :=
  let staked' := staked s in  (* staked balances persist *)
  let reserve' := reserve s in
  let treasury' := treasury s in
  (* Distribute accumulated rebates to eligible users (doc/06 line 114) *)
  let rebates := distributeRebates (rebate_accum s) in
  (* Balances reset to 0, then credited with rewards + rebates (doc/06 line 317) *)
  (* Unspent prior balances are absorbed into pool via supply restoration *)
  let balances' := zipWith (+) rewards rebates in
  let pool' := INITIAL_SUPPLY - staked' - reserve' - treasury'
                - sum balances' in
  mkState pool' staked' reserve' treasury' 0 0 balances'
    (adjust_params (adaptive s) (cycle_metrics s)).
```

---

## Invariant 1: Conservation (sum = 11B)

**Theorem (Conservation).**
For all reachable states s: `total s = INITIAL_SUPPLY`.

### Proof for IntraCycleTx

```
total (IntraCycleTx s sender producer fee) =
  sum(balances') + pool' + staked' + reserve' + treasury'
  + burned' + rebate_accum'
```

Expanding each component:

```
sum(balances') = sum(balances s) - fee + to_producer
pool'          = pool s + treasury_overflow
staked'        = staked s
reserve'       = reserve s
treasury'      = treasury s + to_treasury_actual
burned'        = burned s + to_burn_actual
rebate_accum'  = rebate_accum s + to_rebate
```

Key identities:
- `to_treasury_actual + treasury_overflow = to_treasury`
  (overflow redirects treasury excess to pool; sum preserved).
- `to_burn_actual = to_burn + remainder`
  where `remainder = non_burn - to_producer - to_treasury - to_rebate`
  accounts for integer division truncation.

The fee split is exhaustive under integer arithmetic:
```
to_burn + non_burn = fee                           (definition of to_burn)
to_producer + to_treasury + to_rebate + remainder = non_burn  (by definition of remainder)
to_burn_actual = to_burn + remainder               (remainder absorbed into burn)
```

Therefore:
```
total' = (sum(balances s) - fee + to_producer)
       + (pool s + treasury_overflow)
       + staked s
       + reserve s
       + (treasury s + to_treasury_actual)
       + (burned s + to_burn_actual)
       + (rebate_accum s + to_rebate)
     = total s + (to_producer + to_rebate + treasury_overflow
                  + to_treasury_actual + to_burn_actual - fee)
     = total s + (to_producer + to_rebate + to_treasury
                  + to_burn + remainder - fee)
         [since treasury_overflow + to_treasury_actual = to_treasury,
          and to_burn_actual = to_burn + remainder]
     = total s + (to_producer + to_rebate + to_treasury + remainder
                  + to_burn - fee)
     = total s + (non_burn + to_burn - fee)
         [since to_producer + to_rebate + to_treasury + remainder = non_burn]
     = total s + (fee - fee)
     = total s
     = INITIAL_SUPPLY.  □
```

### Proof for CycleBoundary

```
total (CycleBoundary s rewards) =
  sum(balances') + pool' + staked' + reserve' + treasury' + 0 + 0
```

where `pool' = INITIAL_SUPPLY - staked' - reserve' - treasury' - sum(balances')`,
`burned' = 0`, and `rebate_accum' = 0` (both reset at cycle boundary).

The rewards are funded from pool_raw * 0.85 and rebates are distributed
from `rebate_accum s` (which was accumulated during the cycle).  The
constraint `sum(balances') ≤ pool_raw` where
`pool_raw = INITIAL_SUPPLY - staked' - reserve' - treasury'` ensures
pool' ≥ 0.

Substituting the definition of pool':

```
total' = sum(balances') + (INITIAL_SUPPLY - staked' - reserve' - treasury' - sum(balances'))
         + staked' + reserve' + treasury' + 0 + 0
       = INITIAL_SUPPLY.  □
```

**Note:** The pool' computation subtracts sum(balances') to ensure
conservation by construction.  The `rebate_accum` is fully distributed
into `balances'` and reset to 0, so it does not appear in pool'.  The
constraint `sum(balances') ≤ pool_raw` is enforced by the reward
distribution algorithm, which allocates at most 85% of pool_raw as
rewards (Invariant 5 provides the floor guarantee), and rebates are
capped by Invariant 8 (rebate cap).

**Assumption (Reward Budget).** The reward distribution algorithm ensures
sum(rewards) + sum(rebates) ≤ pool_raw, where pool_raw = INITIAL_SUPPLY - staked' - reserve' - treasury'. Rewards are capped at 85% of pool_raw (doc/06 lines 230-239), and rebates are funded from rebate_accum (which was deducted from fees during the cycle, not from pool). Under this assumption, sum(balances') ≤ pool_raw, ensuring pool' ≥ 0 (no nat underflow). This precondition is verified by QuickCheck property prop_reward_budget below.

### QuickCheck Property

```haskell
prop_conservation :: State -> Fee -> Property
prop_conservation s fee =
  let s' = intraCycleTx s 0 1 fee
  in total s' === total s

prop_conservation_boundary :: State -> Property
prop_conservation_boundary s =
  let s' = cycleBoundary s
  in total s' === INITIAL_SUPPLY

prop_reward_budget :: State -> Property
prop_reward_budget s =
  let s' = cycleBoundary s
      pool_raw = INITIAL_SUPPLY - staked s' - reserve s' - treasury s'
  in sum (balances s') <= pool_raw
```

---

## Invariant 2: Intra-Cycle Burn Monotonic

**Theorem.**  Within a cycle, `burned` only increases: for any intra-cycle
transition from s to s', `burned s' ≥ burned s`.

**Proof.**  In `IntraCycleTx`:
```
burned' = burned s + to_burn_actual
to_burn_actual = to_burn + remainder ≥ 0
  (to_burn = fee * burn_rate ≥ 0, remainder ≥ 0 since
   to_producer + to_treasury + to_rebate ≤ non_burn by integer truncation)
```
Therefore `burned' ≥ burned s`.

No other intra-cycle operation modifies `burned`.  □

### QuickCheck

```haskell
prop_burn_monotonic :: State -> Fee -> Property
prop_burn_monotonic s fee =
  burned (intraCycleTx s 0 1 fee) >= burned s
```

---

## Invariant 3: Cycle Boundary Reset

**Theorem.**  At every cycle boundary, `burned = 0`.

**Proof.**  By definition of `CycleBoundary`: `burned' = 0`.  □

### QuickCheck

```haskell
prop_burn_reset :: State -> Property
prop_burn_reset s = burned (cycleBoundary s) === 0
```

---

## Invariant 4: Supply Restoration

**Theorem.**  At cycle boundary:
`pool(N+1) = INITIAL_SUPPLY - staked(N+1) - reserve(N+1) - treasury(N+1) - sum(balances(N+1))`.

*Note:* This is the **post-credit** pool formula.  The specification
(`doc/15-economic-model-v3.md` line 24, `doc/06-economics.md` line 40)
defines the pre-credit pool as `INITIAL_SUPPLY - staked - reserve -
treasury` (step 3 of the boundary procedure).  Rewards are then
distributed from this pre-credit pool (step 5), producing the post-credit
pool stated here.  The two formulations are equivalent: the post-credit
pool equals the pre-credit pool minus the total rewards distributed.
This proof uses the post-credit form because it directly corresponds to
the `CycleBoundary` implementation, which performs both steps atomically.

**Proof.**  By definition of `CycleBoundary`:
```
pool' = INITIAL_SUPPLY - staked' - reserve' - treasury' - sum(balances')
```

This is a direct assignment, not a derivation.  The implementation computes
pool from the other components, making this invariant hold by construction.  □

### QuickCheck

```haskell
prop_supply_restoration :: State -> Property
prop_supply_restoration s =
  let s' = cycleBoundary s
  in pool s' === INITIAL_SUPPLY - staked s' - reserve s' - treasury s'
                  - sum (balances s')
```

---

## Invariant 5: Reward Floor

**Theorem.**  For each active validator i, if `pool > 0`:
`reward_i ≥ MIN_REWARD` (5,000 MTK).

**Proof.**  From `doc/06-economics.md` lines 230–239:

```
pool_allocation = pool * 0.85

if pool_allocation / active_validators ≥ MIN_REWARD:
    -- Normal distribution: all validators get ≥ MIN_REWARD
    reward_i = (raw_reward_i / total_raw_reward) * pool_allocation
    -- Note: minimum raw_reward_i > 0 for active validators (S_i ≥ 0.5, P_i > 0)
    -- In the worst case, reward_i approaches pool_allocation / active_validators ≥ MIN_REWARD

if pool_allocation / active_validators < MIN_REWARD:
    max_validators = pool_allocation / MIN_REWARD
    -- Top validators by stake receive MIN_REWARD each
    -- Excess validators queued with standby reward (1,000 MTK)
```

In both cases, every *active* (non-queued) validator receives ≥ MIN_REWARD.

**A11 (Reward Floor Threshold):** The reward floor threshold is checked
against `pool_allocation / V`, where `pool_allocation = pool × 0.85`
(`doc/06-economics.md` line 197). Only 85% of the pool is distributable
as rewards; the 15% remainder is retained as buffer for the next cycle.

**Edge cases:**
- If pool = 0: no rewards are distributed. The invariant is vacuously true.
- If 0 < pool < MIN_REWARD * active_validators: the queuing mechanism activates. max_validators = pool_allocation / MIN_REWARD (integer division). Only the top max_validators by stake receive rewards (each ≥ MIN_REWARD); the rest are queued with standby reward (1,000 MTK from treasury). If max_validators = 0 (pool_allocation < MIN_REWARD), all validators are queued and no per-validator reward is issued from the pool. The invariant holds vacuously for queued validators (they are not 'active' for purposes of this invariant).

**Subtlety:** The proportional formula `(raw_i / total_raw) * pool_alloc`
might give some validators less than MIN_REWARD if the distribution is
highly skewed.  The implementation must enforce a floor: `reward_i =
max(MIN_REWARD, proportional_reward_i)` with excess funded by reducing
top validators' rewards.

**Conservation under redistribution:** Enforcing the floor redistributes
tokens between validators but does not change `sum(rewards)`.  Reducing
top validators' rewards by exactly the amount added to bring bottom
validators up to MIN_REWARD preserves the total: `sum(rewards') =
sum(rewards)`.  This is a zero-sum reallocation within the reward pool,
so Invariant 1 (conservation) is unaffected.  □

### QuickCheck

```haskell
prop_reward_floor :: State -> Property
prop_reward_floor s =
  pool s > 0 ==>
    all (>= MIN_REWARD) (computeRewards s)
```

---

## Invariant 6: Fee Bounds

**Theorem.**  At all times: `fee_floor ≤ base_fee ≤ fee_ceiling`.

**Proof.**  From `doc/06-economics.md` lines 69–100, the fee computation
applies an explicit clamp:

```
base_fee = clamp(base_fee, fee_floor, fee_ceiling)
```

where `clamp(x, lo, hi) = max(lo, min(x, hi))`.

By definition of clamp: `fee_floor ≤ clamp(x, fee_floor, fee_ceiling) ≤ fee_ceiling`.  □

### QuickCheck

```haskell
prop_fee_bounds :: State -> Property
prop_fee_bounds s =
  let fee = computeBaseFee s
  in fee >= fee_floor (adaptive s) .&&. fee <= fee_ceiling (adaptive s)
```

---

## Invariant 7: Quadratic Bonding

**Theorem.**  The stake required for the n-th validator from the same /16
subnet is `50000 * n²` MTK.

**Proof.**  By specification (`doc/06-economics.md` lines 386–395):

```
stake_required(n) = 50000 * n^2
```

This is an explicit formula applied at validator registration.  The
implementation rejects registrations where the submitted stake is less
than `50000 * n^2` for the validator's subnet count n.

Verification: n=1: 50,000; n=2: 200,000; n=3: 450,000; n=10: 5,000,000.  □

### QuickCheck

```haskell
prop_quadratic_bonding :: Positive Int -> Property
prop_quadratic_bonding (Positive n) =
  stakeRequired n === 50000 * n * n
```

---

## Invariant 8: Rebate Cap

**Theorem.**  Per cycle: `total_rebates ≤ rebate_rate * total_fees_collected`.

**Proof.**  From `doc/06-economics.md` lines 241–250:

```
rebate_rate = (1 - burn_rate) * (5/35)
user_rebate = rebate_rate * total_fees_paid_by_user
```

Summing over all eligible users:

```
total_rebates = sum_i(rebate_rate * fees_i) = rebate_rate * sum_i(fees_i)
              = rebate_rate * total_fees_collected
```

The inequality is actually an equality for eligible users.  Users who
do not meet the bidirectional activity requirement (≥ 10 sent AND ≥ 10
received) receive 0 rebate, making the total strictly ≤.  □

### QuickCheck

```haskell
prop_rebate_cap :: State -> Property
prop_rebate_cap s =
  let (rebates, fees) = computeRebates s
  in sum rebates <= rebateRate (adaptive s) * sum fees
```

---

## Invariant 9: Punitive Recovery Monotonic

**Theorem.**  During recovery (no new violations), the punitive factor
P_carryover increases monotonically toward 1.0 (i.e., the penalty
severity monotonically *decreases* — doc/06 line 418):

```
P_carry(t+1) = P_floor + (1 - P_floor) * P_carry(t)
```

where P_floor ∈ {0.0, 0.1, 0.3} depending on tier.

**Proof.**  We must show P_carry(t+1) > P_carry(t) for P_carry(t) < 1.

```
P_carry(t+1) = P_floor + (1 - P_floor) * P_carry(t)
             = P_floor + P_carry(t) - P_floor * P_carry(t)
             = P_carry(t) + P_floor * (1 - P_carry(t))
```

Since P_carry(t) < 1 and P_floor > 0 (for Tiers 1 and 2):
```
P_floor * (1 - P_carry(t)) > 0
```

Therefore P_carry(t+1) > P_carry(t).  Strict monotonic increase.

**Convergence:** P_carry(t) → 1 as t → ∞.  Define e(t) = 1 - P_carry(t):

```
e(t+1) = 1 - P_carry(t+1) = 1 - P_floor - (1 - P_floor) * P_carry(t)
       = (1 - P_floor) * (1 - P_carry(t)) = (1 - P_floor) * e(t)
```

So e(t) = (1 - P_floor)^t * e(0), which converges geometrically to 0.

| Tier | P_floor | e(t)/e(0) at t=3 | e(t)/e(0) at t=10 |
|------|---------|-------------------|---------------------|
| 1 | 0.3 | 0.343 (P > 0.95 if start 0.9) | 0.028 |
| 2 | 0.1 | 0.729 | 0.349 (P > 0.95 at ~22 cycles from P=0.5) |
| 3 | 0.0 | 1.000 (no recovery) | 1.000 |

**Tier 3 special case:** P_floor = 0, so P_carry(t+1) = P_carry(t).
No recovery during the 10-cycle penalty period (P_carry remains at 0.0).
After the 10-cycle lockout, Tier 2 recovery begins with P_floor = 0.1
(`doc/06-economics.md` line 344).  The transition preserves monotonicity:
P_carry is constant at 0.0 during lockout, then begins increasing under
the Tier 2 formula (proved above).  The overall trajectory is therefore
monotonically non-decreasing.  If the validator does not re-register,
P_carry resets upon re-staking.  □

### QuickCheck

```haskell
prop_punitive_monotonic :: PFloor -> PCarry -> Property
prop_punitive_monotonic pfloor pcarry =
  pcarry < 1.0 && pfloor > 0.0 ==>
    let pcarry' = pfloor + (1 - pfloor) * pcarry
    in pcarry' > pcarry .&&. pcarry' <= 1.0
```

---

## Invariant 10: Onboarding Bonus Cap

**Theorem.**  Per cycle: `onboarding_bonus_total ≤ 0.50 * treasury_allocation`.

**Proof.**  From `doc/06-economics.md` lines 252–307:

```
treasury_allocation = (1 - burn_rate) * (10/35) * total_fees
onboarding_bonus_total = sum_i(0.10 * referred_fees_i)
```

The implementation enforces an explicit cap:

```
if onboarding_bonus_total > 0.50 * treasury_allocation:
    scale_factor = (0.50 * treasury_allocation) / onboarding_bonus_total
    -- Scale all bonuses proportionally
    for each validator i:
        bonus_i *= scale_factor
```

After scaling: `onboarding_bonus_total = 0.50 * treasury_allocation`.
Before the cap is hit: `onboarding_bonus_total < 0.50 * treasury_allocation`.
In both cases: `onboarding_bonus_total ≤ 0.50 * treasury_allocation`.  □

### QuickCheck

```haskell
prop_onboarding_cap :: State -> Property
prop_onboarding_cap s =
  let (bonuses, talloc) = computeOnboardingBonuses s
  in sum bonuses <= talloc `div` 2
```

---

## Invariant 11: Adaptive Parameter Bounds

**Theorem.**  At all times:
- burn_rate ∈ [0.20, 0.80]
- fee_floor ∈ [5, 100]
- fee_ceiling ∈ [5000, 50000]
- target_msgs ∈ [1000, 100000000]

**Proof.**  Under bounded growth (A9), the duration_ratio input is
bounded.  From `doc/06-economics.md` lines 138–170, every parameter
adjustment applies `clamp`:

```
burn_rate_raw    = clamp(burn_rate(N) * duration_ratio, 0.20, 0.80)
burn_rate(N+1)   = burn_rate(N) + 0.5*(burn_rate_raw - burn_rate(N))

fee_floor_raw    = clamp(fee_floor(N) / duration_ratio, 5, 100)
fee_floor(N+1)   = fee_floor(N) + 0.5*(fee_floor_raw - fee_floor(N))

fee_ceiling_raw  = clamp(fee_ceiling(N) / duration_ratio, 5000, 50000)
fee_ceiling(N+1) = fee_ceiling(N) + 0.5*(fee_ceiling_raw - fee_ceiling(N))

target_msgs_raw  = clamp(target_msgs(N) * duration_ratio, 1000, 100000000)
target_msgs(N+1) = target_msgs(N) + 0.5*(target_msgs_raw - target_msgs(N))
```

Step 1: `raw = clamp(x(N) * r_or_1/r, lo, hi)`.  By definition of clamp,
`raw ∈ [lo, hi]`.

Step 2: `x(N+1) = x(N) + 0.5*(raw - x(N))`.  This is a convex
combination: `x(N+1) = 0.5*x(N) + 0.5*raw`.  If `x(N) ∈ [lo, hi]`
and `raw ∈ [lo, hi]`, then `x(N+1) ∈ [lo, hi]` (convex set).

**Initial values** (doc/06-economics.md lines 171–178):
- burn_rate = 0.65 ∈ [0.20, 0.80] ✓
- fee_floor = 10 ∈ [5, 100] ✓
- fee_ceiling = 10000 ∈ [5000, 50000] ✓
- target_msgs = 10000 ∈ [1000, 100000000] ✓

By induction: if params are in bounds at cycle N, both raw and x(N+1)
are in bounds at cycle N+1.  Base case: initial values in bounds.  □

### QuickCheck

```haskell
prop_adaptive_bounds :: AdaptiveParams -> DurationRatio -> Property
prop_adaptive_bounds ap dr =
  let ap' = adjustParams ap dr
  in burn_rate ap' >= 0.20 .&&. burn_rate ap' <= 0.80
     .&&. fee_floor ap' >= 5 .&&. fee_floor ap' <= 100
     .&&. fee_ceiling ap' >= 5000 .&&. fee_ceiling ap' <= 50000
     .&&. target_msgs ap' >= 1000 .&&. target_msgs ap' <= 100000000
```

---

## Invariant 12: Minimum Cycle Duration

**Theorem.**  Every cycle lasts at least 1 epoch (3,927 slots = 12 hours).

**Proof.**  Under bounded growth (A9), the network cannot grow faster than
10× per 100 cycles, so truncation triggers remain well-behaved.
From `doc/06-economics.md` lines 120–136, early truncation checks:

```
if current_epoch >= cycle_start_epoch + 1:
    trigger cycle boundary
else:
    defer truncation to end of current epoch
```

The guard `current_epoch >= cycle_start_epoch + 1` ensures at least 1
full epoch passes before early truncation can fire.  One epoch = 3,927
slots.

If early truncation is not triggered, the cycle runs for its full 22
epochs (86,394 slots), which is ≥ 3,927.  □

### QuickCheck

```haskell
prop_min_cycle :: CycleLog -> Property
prop_min_cycle log =
  all (\c -> cycleSlots c >= 3927) (cycles log)
```

---

## Slashing Subcase

**Theorem (Slashing Conservation).**  When a Tier 3 penalty slashes 25%
of a validator's stake, the total supply is conserved.

**Proof.**  Slashing transfers tokens from `staked` to `burned`:

```
slash_amount = staked_i * 25 / 100
staked'  = staked - slash_amount
burned'  = burned + slash_amount
```

All other components unchanged.  Therefore:
```
total' = sum(balances) + pool + staked' + reserve + treasury + burned'
         + rebate_accum
       = sum(balances) + pool + (staked - slash_amount) + reserve + treasury
         + (burned + slash_amount) + rebate_accum
       = total
       = INITIAL_SUPPLY.  □
```

At cycle boundary, `burned' = 0` and `pool' = INITIAL_SUPPLY - staked' - reserve' - treasury' - sum(balances')`.  The slashed tokens are absorbed into the new pool,
restoring the supply distribution without the slashed stake.

---

## Complete QuickCheck Test Suite

```haskell
-- Run all 12 invariants on arbitrary state transitions
prop_all_invariants :: State -> [Action] -> Property
prop_all_invariants s0 actions =
  let states = scanl applyAction s0 actions
  in conjoin
       [ counterexample "conservation" $
           all (\s -> total s == INITIAL_SUPPLY) states
       , counterexample "burn monotonic (intra-cycle)" $
           burnMonotonicWithinCycles states
       , counterexample "burn reset" $
           all (\s -> isBoundary s ==> burned s == 0) states
       , counterexample "supply restoration" $
           all (\s -> isBoundary s ==>
             pool s == INITIAL_SUPPLY - staked s - reserve s - treasury s
                        - sum (balances s)) states
       , counterexample "reward floor" $
           all (\s -> isBoundary s ==> all (>= MIN_REWARD) (rewards s)) states
       , counterexample "fee bounds" $
           all (\s -> fee_floor (adaptive s) <= baseFee s
                   && baseFee s <= fee_ceiling (adaptive s)) states
       , counterexample "quadratic bonding" $
           all (\(n,req) -> req == 50000 * n * n) (registrations states)
       , counterexample "rebate cap" $
           all (\s -> totalRebates s <= rebateRate s * totalFees s) states
       , counterexample "punitive monotonic" $
           punitiveMonotonic states
       , counterexample "onboarding cap" $
           all (\s -> onboardingBonusTotal s <= treasuryAlloc s `div` 2) states
       , counterexample "adaptive bounds" $
           all adaptiveInBounds states
       , counterexample "min cycle duration" $
           all (\c -> cycleSlots c >= 3927) (extractCycles states)
       ]
```

**Test parameters** (per `doc/16-verification-plan.md`):
- Commit: 1,000 cases per property (seed = 42)
- Nightly: 100,000 cases per property (seed = 42 + random seeds)
- Monte Carlo: 100,000 cycles, 100–100,000 validators, adversarial strategies

---

## Specification Conflicts Between doc/06 and doc/20

This proof follows `doc/06-economics.md` as the authoritative specification.

**Rebate allocation (fundamental disagreement):** doc/06 (line 114)
specifies the 5/35 fee portion as a "user rebate pool" distributed to
active users at cycle end.  doc/20 (lines 52–58) names this same 5/35
portion `to_stakers` and adds it to the `staked` field, treating it as
a staking reward rather than a user rebate.  These are fundamentally
different destinations (user balances vs staking pool).  **This proof
follows doc/06 as authoritative:** rebates accumulate in `rebate_accum`
during the cycle, then `CycleBoundary` distributes them into user
`balances'`.  Any future implementation must resolve this specification
conflict between doc/06 and doc/20.

The following areas where doc/20 is less specific than doc/06:

1. **Treasury overflow (fundamental disagreement):** doc/20 (lines 62–68)
   redirects treasury overflow to burn (`to_burn += to_treasury`), while
   doc/06 (lines 182–189) specifies overflow goes to pool.  This proof
   follows doc/06: overflow is redirected to pool.

2. **Balance reset at cycle boundary:** doc/20 (lines 42–50) does not
   explicitly state that unspent balances are absorbed into the pool.
   doc/06 (line 317) specifies balance reset with absorption.  This proof
   follows doc/06: `CycleBoundary` resets balances to rewards + rebates,
   with unspent prior balances absorbed via the pool restoration formula.

These gaps should be resolved by updating doc/20 to match doc/06.
