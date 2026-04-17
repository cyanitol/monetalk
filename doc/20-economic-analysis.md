# 20. Economic Analysis: Universe Cycle Model

This document provides the quantitative economic foundation for the Universe Cycle
Model (v3). It formalizes the state machine, proves controller convergence, analyzes
steady-state behavior, and stress-tests the system against growth shocks and adversarial
scenarios. All numeric results assume the default parameter set from
[doc/06-economics.md](06-economics.md) unless stated otherwise.

---

## 1. Model Specification

### State Variables

The system state at any point within a cycle is:

```
S = (pool, staked, reserve, treasury, burned, balances[], adaptive_params)
```

| Variable          | Type       | Description                                       |
|-------------------|------------|---------------------------------------------------|
| `pool`            | uint64     | Unallocated supply available for rewards           |
| `staked`          | uint64     | Total tokens locked by validators                  |
| `reserve`         | uint64     | Onboarding reserve for new accounts                |
| `treasury`        | uint64     | Protocol fund (capped, managed via chain revisions) |
| `burned`          | uint64     | Tokens burned within the current cycle             |
| `balances[i]`     | uint64     | Spendable balance of account `i`                   |
| `adaptive_params` | struct     | `{burn_rate, fee_floor, fee_ceiling, target_msgs}` |

**Fixed constants:**

```
INITIAL_SUPPLY     = 11,000,000,000 MTK
TREASURY_CAP       = 1,100,000,000 MTK   (10% of supply)
RESERVE_INITIAL    = 1,100,000,000 MTK   (10% of supply)
MIN_REWARD         = 5,000 MTK
ONBOARDING_GRANT   = 10,000 MTK
CONTROLLER_DAMPING = 0.50
```

### Intra-Cycle Transition

Every message transaction transforms the state:

```
IntraCycleTx(S, msg) -> S'
  fee         = ema_fee(msg, S)          -- EMA-adjusted fee
  to_burn     = fee * S.adaptive_params.burn_rate
  to_producer = fee * (1 - S.adaptive_params.burn_rate) * (20/35)
  to_treasury = fee * (1 - S.adaptive_params.burn_rate) * (10/35)
  to_rebate   = fee * (1 - S.adaptive_params.burn_rate) * (5/35)

  S'.burned             = S.burned + to_burn
  S'.balances[sender]  -= fee
  S'.balances[producer]+= to_producer
  S'.treasury           = min(S.treasury + to_treasury, TREASURY_CAP)
  S'.pool              += to_rebate    (distributed to active users at cycle boundary)
  S'.pool               = S.pool       (unchanged intra-cycle)
```

When treasury is at cap, the treasury portion redirects to burn:

```
  if S.treasury >= TREASURY_CAP:
      to_burn += to_treasury
      to_treasury = 0
```

### Cycle Boundary Transition

At cycle boundary (triggered by slot count or early truncation):

```
CycleBoundary(S) -> S'
  -- Distribute rewards
  for each active validator i:
      S'.balances[i] = S.balances[i] + reward(i, S) + rebate(i, S)

  -- Reset burn counter
  S'.burned = 0

  -- Restore supply
  S'.pool = INITIAL_SUPPLY - sum(S'.staked) - S'.reserve - S'.treasury

  -- Adjust adaptive parameters
  S'.adaptive_params = adjust(S.adaptive_params, cycle_metrics(S))
```

Where `reward(i, S)` is the validator's share of the reward pool (proportional to
blocks produced and uptime), and `rebate(i, S)` returns a fraction of fees paid by
the validator's own messages during the cycle.

---

## 2. Steady-State Analysis

### Expected Burn Per Cycle

Given:
- N users
- M messages per cycle
- Average fee F (MTK)
- Burn rate B

```
expected_burn = M * F * B
```

At default parameters with full on-chain capacity (M = 76,787,520 msgs/cycle,
F ~ 100 MTK average, B = 0.65):

```
expected_burn = 76,787,520 * 100 * 0.65 = 4,991,188,800 MTK (~4.99B)
```

As a fraction of the 11B total supply: **~45.4% per cycle at full capacity**.

However, full capacity assumes all ~76.8M message slots per cycle are filled.
In practice, early-network usage will be orders of magnitude lower. At 10,000
msgs/cycle (a realistic early figure), the burn is only 650,000 MTK (~0.006%
of supply). The key insight is that early truncation transitions from unreachable
at low utilization to an **active safety mechanism** as the network approaches
capacity — this is by design.

### Pool Evolution

Since supply restores at each cycle boundary:

```
pool(N+1) = INITIAL_SUPPLY - sum(staked(N+1)) - reserve(N+1) - treasury(N+1)
```

As more tokens are staked over time, the pool shrinks. The binding constraint is:

```
pool_allocation = pool * 0.85
pool_allocation >= MIN_REWARD * active_validator_count = 5,000 * V
```

If a new stake would reduce the pool below this threshold, the staking transaction
is rejected. This guarantees every active validator receives at least MIN_REWARD.

### Treasury Trajectory

Treasury receives a fraction of fees each cycle, minus any spending authorized via chain revisions.

Per-message treasury income:

```
treasury_per_msg = F * (1 - B) * (10/35)
                 = 100 * 0.35 * 0.2857
                 ≈ 10.0 MTK
```

Per-cycle treasury income at full capacity:

```
treasury_per_cycle = 76,787,520 * 10.0 = 767,875,200 MTK (~767.9M)
```

Cycles to reach treasury cap at full capacity (ignoring spending):

```
1,100,000,000 / 767,875,200 ≈ 1.43 cycles
```

At full capacity, the treasury cap would be reached within 2 cycles. In practice,
early-network message volumes are far below capacity, so treasury filling is gradual.
At 10,000 msgs/cycle, treasury income is only 100,000 MTK per cycle, and the cap
would take ~11,000 cycles (~331 years). Treasury spending (authorized via chain
revisions) will further slow accumulation. The treasury cap becomes operationally
relevant only as the network scales toward capacity.

### Onboarding Reserve Depletion

At 10,000 MTK per new user, the reserve (1.1B MTK) supports **110,000 new accounts**.

Replenishment mechanisms:
- **Inactive reclamation**: accounts inactive for >5 cycles (55 days) with balance
  < 1,000 MTK are reclaimed
- **Validator-operated faucets**: supplement the reserve for faster onboarding

Expected steady-state with 100K active users:
- Annual inactive churn: ~7.5% (7,500 accounts)
- Average reclaimable balance: ~5,000 MTK
- Annual reclamation: 7,500 * 5,000 = **37.5M MTK/year**
- New users supportable by reclamation alone: **3,750/year**

For growth exceeding this rate, validator faucets and treasury-funded grants
(authorized via chain revisions) provide supplementary onboarding capacity.

---

## 3. Adaptive Controller Analysis

### Controller Definition

At each cycle boundary, the adaptive controller updates parameters:

```
param(N+1) = param(N) + DAMPING * (target(N) - param(N))
```

where:

```
target(N) = param(N) * duration_ratio
duration_ratio = actual_cycle_duration / target_cycle_duration
```

and `DAMPING = 0.50`.

### Convergence Proof Sketch

Define the error term:

```
error(N) = param(N) - param_equilibrium
```

After a step change in network activity (a one-time shift to a new steady state):

```
error(N+1) = param(N+1) - param_equilibrium
           = param(N) + 0.5 * (target(N) - param(N)) - param_equilibrium
```

At the new equilibrium, `target(N) = param_equilibrium`, so:

```
error(N+1) = param(N) + 0.5 * (param_equilibrium - param(N)) - param_equilibrium
           = param(N) - param_equilibrium - 0.5 * (param(N) - param_equilibrium)
           = 0.5 * error(N)
```

**Error halves each cycle.** This is a geometric series with ratio 0.5:

| Cycles elapsed | Residual error |
|----------------|----------------|
| 1              | 50.0%          |
| 2              | 25.0%          |
| 3              | 12.5%          |
| 5              | 3.125%         |
| 7              | 0.78%          |
| 10             | 0.098%         |

**Convergence rate**: geometric with ratio 0.5, unconditionally stable (ratio < 1).

### Stability Properties

The controller is purely proportional (no integral or derivative terms):

- **No windup**: there is no accumulated integral state that can saturate
- **No oscillation**: convergence is monotonic (error decreases every cycle)
- **No overshoot**: the damping factor of 0.5 guarantees each step moves at most
  halfway toward the target

**Limitation**: pure proportional control has steady-state error under continuous
growth. If the network is growing every cycle, the controller is always slightly
behind. This is acceptable because:

1. The target cycle duration (11 days) has a +-50% tolerance band
2. Cycles between 5.5 and 16.5 days are operationally acceptable
3. Continuous growth exceeding 100% per cycle would saturate any controller design

### Sensitivity Analysis

| Parameter    | Sensitivity to 10x activity growth | Response time |
|--------------|-----------------------------------|---------------|
| burn_rate    | High (primary lever)              | 3-5 cycles    |
| fee_floor    | Medium                            | 3-5 cycles    |
| fee_ceiling  | Low (only relevant during congestion) | 3-5 cycles |
| target_msgs  | Medium                            | 3-5 cycles    |

---

## 4. Monte Carlo Simulation Design

### Input Parameters

```
Simulation runs:      100,000 cycles
Validator count:      starts at 100, grows per LogNormal(mu=0.01, sigma=0.005)/cycle
User count:           starts at 1,000, grows per LogNormal(mu=0.02, sigma=0.01)/cycle
Message rate:         Poisson(lambda = user_count * 0.5 msgs/user/cycle)
Attacker present:     Bernoulli(p=0.05) -- 5% of cycles have a spam attacker
Attacker intensity:   Uniform(2x, 20x) normal volume when present
```

### Tracked Outputs Per Cycle

- Cycle duration (in slots)
- Whether early truncation fired (boolean)
- Adaptive parameters: burn_rate, fee_floor, fee_ceiling, target_msgs
- Pool size at cycle start
- Total burned within cycle
- Total fees collected
- Treasury balance
- Onboarding reserve balance
- Per-validator reward: min, median, max

### Success Metrics

| # | Metric                                                              | Threshold |
|---|---------------------------------------------------------------------|-----------|
| 1 | Cycle duration within [0.5, 1.5] * target                          | > 99%     |
| 2 | Early truncation fires under normal conditions                      | < 1%      |
| 3 | Adaptive parameters converge after any growth shock                 | <= 5 cycles |
| 4 | All 12 formal invariants hold                                       | 100%      |
| 5 | No cycle shorter than 1 epoch (minimum cycle duration)              | 100%      |
| 6 | Validator reward >= 5,000 MTK floor for all active validators       | 100%      |
| 7 | Treasury never exceeds cap (1.1B MTK)                               | 100%      |

---

## 5. Early Truncation Analysis

### Trigger Condition

Early truncation fires when:

```
sum(spendable_balances) < early_trunc_threshold * INITIAL_SUPPLY
```

evaluated at each epoch boundary. With `early_trunc_threshold = 0.15`:

```
trigger when sum(spendable_balances) < 0.15 * 11B = 1.65B MTK
```

### Under What Conditions Does This Fire?

1. Extremely high message volume (burn outpaces cycle duration)
2. Deliberate supply depletion attack
3. Burn rate stuck high from a previous cycle while activity spikes

### Expected Frequency Under Normal Operation

At default parameters (burn_rate = 0.65, avg fee 100 MTK) with varying utilization:

```
distributable_supply  ≈ 8,000,000,000 MTK
depletion_target       = 0.85 * 8B = 6,800,000,000 MTK

At full capacity (~76.8M msgs/cycle):
  total_burn_per_cycle = 76,787,520 * 100 * 0.65 = 4,991,188,800 MTK (~4.99B)
  cycles_to_deplete    = 6.8B / 4.99B ≈ 1.36 cycles
  → Early truncation fires WITHIN the first cycle at full capacity.

At moderate utilization (~1M msgs/cycle):
  total_burn_per_cycle = 1,000,000 * 100 * 0.65 = 65,000,000 MTK
  cycles_to_deplete    = 6.8B / 65M ≈ 105 cycles

At early-network utilization (~10K msgs/cycle):
  total_burn_per_cycle = 10,000 * 100 * 0.65 = 650,000 MTK
  cycles_to_deplete    = 6.8B / 650K ≈ 10,462 cycles
```

At low utilization, early truncation is effectively unreachable — the trigger
exists as a distant safety bound. As the network scales toward capacity, early
truncation transitions into an **active safety mechanism** that prevents
over-depletion during high-throughput cycles. The adaptive controller responds
by reducing burn_rate in subsequent cycles, naturally throttling depletion.

### Growth Threshold: What Activity Level Triggers Early Truncation?

```
supply_to_burn     = 0.85 * 8B = 6.8B MTK
max_msgs_per_cycle = 76,787,520 (chain capacity, ~76.8M)
fee_to_trigger     = 6.8B / (76,787,520 * 0.65) ≈ 136 MTK per message
```

This is only **~1.4x above the default average fee** (100 MTK). At full capacity
with even moderate fee levels, early truncation is reachable within a single cycle.
This means early truncation serves as a **practical safety mechanism at scale**,
not merely a theoretical bound.

At lower utilization, the effective fee threshold scales inversely with message
count. For example, at 1M msgs/cycle the fee to trigger is ~10,462 MTK (just
above the fee ceiling), making truncation unlikely but not impossible during
congestion spikes.

The secondary risk scenario remains off-chain: if validator staking increases
dramatically, reducing the pool and distributable supply. This is bounded by the
staking constraint (pool_allocation must cover MIN_REWARD * validator_count).

### Recovery After Early Truncation

1. Controller reduces burn_rate by ~50% of the observed shortfall
2. Next cycle: longer duration, lower burn pressure
3. Within 3-5 cycles: parameters stabilize at a new equilibrium
4. Supply restores fully at the very next cycle boundary (damage is never permanent)

---

## 6. Supply Depletion Attack Economics

### Cost to Force Early Truncation

See [doc/19-game-theory.md](19-game-theory.md) for the full analysis. Summary:

- Cost exceeds total circulating supply
- EMA fee escalation makes sustained spam exponentially expensive
- Attack achieves only one shortened cycle; the adaptive controller compensates
- Attacker permanently loses all fees paid (burned tokens are gone within the cycle)

### Comparison to v2 (Deflationary Model)

In v2, a spam attack caused **permanent** supply reduction. Every token burned was
gone forever. While still unprofitable for the attacker, the damage accumulated
across attacks.

In v3 (Universe Cycle), the same attack causes only **temporary** supply reduction
within one cycle. At the cycle boundary, supply restores. The attacker's damage is
strictly bounded to one cycle.

| Property                    | v2 (Deflationary) | v3 (Universe Cycle) |
|-----------------------------|-------------------|---------------------|
| Damage from single attack   | Permanent         | Bounded to one cycle |
| Cumulative damage           | Monotonic increase | Zero (resets)       |
| Attacker cost               | Same (fee + burn) | Same (fee + burn)   |
| Recovery mechanism          | None              | Automatic at boundary |

**v3 is strictly more resilient to supply depletion attacks than v2.**

---

## 7. Growth Accommodation

### 10x Growth Scenario

Starting state: 100 validators, 1K users, ~1K msgs/cycle.

After 10x growth: 1K validators, 10K users, ~10K msgs/cycle.

```
burn_per_cycle (before) = 1,000 * 100 * 0.65 = 65,000 MTK
burn_per_cycle (after)  = 10,000 * 100 * 0.65 = 650,000 MTK
fraction_of_supply      = 650,000 / 11B = 0.006%
```

The adaptive controller barely needs to adjust. Fee floor and EMA handle demand
fluctuations within each cycle. Cycle duration stretches slightly, and the controller
nudges burn_rate down by a small increment over 2-3 cycles.

### 100x Growth Scenario

Starting state: 100 validators, 1K users.

After 100x growth: 10K validators, 100K users, ~100K msgs/cycle.

At this scale, on-chain capacity (~76.8M msgs/cycle) is far from saturated,
but message volume and fee escalation become significant:

```
burn_per_cycle = 100,000 * 1,000 * 0.65 = 65,000,000 MTK
fraction_of_supply = 65M / 11B = 0.59%
```

At 100K msgs/cycle, the network is at ~0.13% of capacity. EMA-driven fee
escalation remains modest, and early truncation is distant (~105 cycles to
depletion at these parameters). The adaptive controller has ample room to
manage growth.

### Scaling Limit

The adaptive controller saturates when:

1. Burn rate hits its floor (0.20) -- no further reduction possible
2. Fee floor hits its ceiling (100 MTK) -- minimum spam cost maximized
3. On-chain capacity is fully utilized

At saturation with burn_rate = 0.20 and maximum throughput:

```
max_burn_per_cycle = 76,787,520 * 10,000 * 0.20 = 153,575,040,000 MTK (~153.6B)
fraction_of_supply = 153.6B / 11B = 1,396%
```

At full capacity with maximum fees and minimum burn rate, a single cycle would
burn **~14x the total supply** — early truncation fires almost immediately. This
confirms that early truncation is an essential and active safety mechanism at
scale, not a theoretical bound.

In practice, this extreme scenario is self-limiting: EMA fee escalation to the
10,000 MTK ceiling requires sustained congestion, and early truncation would fire
well before a full cycle completes, triggering the adaptive controller to reduce
burn_rate for subsequent cycles.

At more realistic saturation parameters (burn_rate = 0.20, avg fee = 100 MTK):

```
burn_per_cycle = 76,787,520 * 100 * 0.20 = 1,535,750,400 MTK (~1.54B)
fraction_of_supply = 1.54B / 11B = 13.96%
cycles_to_deplete_to_15% = 85% / 13.96% ≈ 6.1 cycles ≈ 67 days
```

Even with minimum burn rate and moderate fees, sustained full-capacity utilization
depletes the distributable supply within ~6 cycles. Beyond this throughput level,
the protocol needs structural scaling: higher block frequency `f`, larger blocks,
or sharding.

---

## 8. Equilibrium Analysis

### Validator Equilibrium

With full supply restoration, the pool starts each cycle at a predictable size:

```
pool = INITIAL_SUPPLY - staked - reserve - treasury
```

As validator count grows, staked tokens grow, and the pool shrinks. The equilibrium
condition is:

```
pool_allocation = pool * 0.85
pool_allocation / validator_count >= MIN_REWARD
max_validators = pool_allocation / MIN_REWARD
```

Example with 1B staked, 1.1B reserve, 0.55B treasury:

```
pool = 11B - 1B - 1.1B - 0.55B = 8.35B
distributable = 8.35B * 0.85 = 7.0975B  (keeping 15% as early-trunc buffer)
max_validators = 7.0975B / 5,000 = 1,419,500
```

The network can support over **1.4 million validators** before hitting the reward
floor. This is stable and predictable. Unlike v2, the pool does not shrink from
permanent burns.

### User Equilibrium

Users balance message value against fee cost. With adaptive fees:

- **Low activity** -> low fees -> messaging encouraged (positive feedback)
- **High activity** -> high fees -> marginal messages discouraged (negative feedback)
- **Equilibrium**: fee level where marginal message value equals marginal fee cost

This is a standard supply/demand equilibrium. The EMA fee mechanism acts as the
price discovery mechanism, and the adaptive controller ensures long-run stability.

### System-Level Attractor

The Universe Cycle Model creates a **steady-state attractor**:

1. Each cycle starts from the same initial conditions (modulo persistent state
   changes like staking and treasury balance)
2. The adaptive controller drives parameters toward the 11-day target duration
3. Predictable pool sizes enable predictable validator economics
4. No long-term deflation risk eliminates the "death of network" failure mode

The attractor is globally stable: regardless of initial conditions or perturbations,
the system converges to the same neighborhood of operating parameters within 5-10
cycles.

---

## 9. v2 vs v3 Comparison

| Aspect                        | v2 (Deflationary)                   | v3 (Universe Cycle)                    |
|-------------------------------|-------------------------------------|----------------------------------------|
| Long-term supply              | Shrinks permanently                 | Restores each cycle                    |
| Burn behavior                 | Permanent (monotonic)               | Cycle-scoped (resets at boundary)      |
| Validator reward predictability | Decreases over time (shrinking pool) | Stable per cycle (pool restores)      |
| Spam cost to attacker         | Permanent loss                      | Intra-cycle loss (attacker still loses)|
| Network growth accommodation  | Fixed parameters, no accommodation  | Adaptive controller self-tunes         |
| Early truncation              | Not supported                       | Supply-based trigger                   |
| Death spiral risk             | Yes (burns can exceed new activity) | No (pool restores each cycle)          |
| Parameter flexibility         | None                                | Burn rate, fee bounds, targets adaptive|
| Economic complexity           | Low                                 | Medium (controller adds complexity)    |
| Fee split                     | Fixed 65/20/10/5                    | Adaptive burn / proportional non-burn  |
| Treasury behavior             | Unbounded growth                    | Capped at 10% of supply               |
| Spam attack resilience        | Medium (permanent damage)           | High (damage bounded to one cycle)     |
| Formal verification needs     | Standard invariants                 | +Controller convergence proof          |

---

## 10. Parameter Sensitivity

### Initial Parameter Set (Recommended)

| Parameter              | Initial Value | Range           | Rationale                                          |
|------------------------|---------------|-----------------|----------------------------------------------------|
| burn_rate              | 0.65          | [0.20, 0.80]    | Strong anti-spam while leaving 35% for ecosystem   |
| fee_floor              | 10 MTK        | [5, 100]        | Low enough for casual use, high enough for spam    |
| fee_ceiling            | 10,000 MTK    | [5,000, 50,000] | Prevents prohibitive costs during demand spikes    |
| target_msgs_per_epoch  | 10,000        | [1K, 100M]      | Matches on-chain capacity at f=0.20                |
| early_trunc_threshold  | 0.15          | [0.05, 0.25]    | 15% provides ~2-3 day buffer at typical burn rates |
| controller_damping     | 0.50          | Fixed           | Prevents oscillation; guarantees convergence       |

### Sensitivity Rankings (Impact on Cycle Duration)

1. **burn_rate** (highest): directly controls depletion speed. A 10% change in
   burn rate changes effective cycle duration by ~15%.
2. **message_volume** (external, not controlled): primary driver of total burn.
   10x volume produces 10x burn.
3. **fee_floor** (medium): sets minimum cost; affects low-activity periods most.
4. **fee_ceiling** (low): only relevant during congestion; EMA usually keeps fees
   below ceiling.
5. **target_msgs** (low): affects EMA adjustment speed, not directly burn rate.
6. **early_trunc_threshold** (low): only matters when approaching depletion;
   normal operation stays well above.

### Tornado Diagram (Cycle Duration Sensitivity)

```
Parameter                    | -50% of initial | +50% of initial | Impact
-----------------------------|-----------------|-----------------|-------
burn_rate (0.325 - 0.80*)   | +77% duration   | -35% duration   | HIGH
message_volume (ext.)        | +100% duration  | -50% duration   | HIGH
fee_floor (5 - 15)          | +5% duration    | -3% duration    | LOW
fee_ceiling (5K - 15K)      | ~0%             | ~0%             | NONE
target_msgs (5K - 15K)      | +2%             | -2%             | LOW
early_trunc_pct (7.5%-22.5%)| ~0% (normal op) | ~0% (normal op) | NONE*
```

\* `early_trunc_threshold` only matters during depletion events.
\* `burn_rate` upper bound clamped to the canonical hard cap of 0.80 (see doc/06-economics.md).

### Key Insight

The system is dominated by two variables: **burn_rate** and **message_volume**. The
adaptive controller adjusts burn_rate in response to message_volume (via cycle
duration feedback), creating a self-correcting loop. All other parameters are
secondary tuning knobs that matter only at the margins.

This two-variable dominance is a desirable property: it means the system's behavior
is predictable and can be reasoned about without modeling all parameters
simultaneously.

---

## 11. Expert Cryptocurrency Economics Analysis

This section provides a critical economic evaluation of the Universe Cycle Model from the perspective of monetary economics, mechanism design, and comparative cryptocurrency analysis.

### 11.1 Monetary Classification

The Universe Cycle Model is **not a traditional cryptocurrency**. It defies standard
classification:

| Category | Bitcoin | Ethereum | Stablecoins | MTK |
|----------|---------|----------|-------------|-----|
| Supply model | Deflationary (halving) | Inflationary/deflationary (EIP-1559) | Pegged (stable) | **Cyclical (periodic reset)** |
| Token persistence | Permanent | Permanent | Permanent | Cycle-scoped (spendable) |
| Value proposition | Store of value | Utility + store of value | Medium of exchange | **Pure utility (messaging)** |
| Price discovery | External markets | External markets | Peg mechanism | Internal EMA (no external market needed) |

MTK is best understood as a **utility coupon with periodic renewal**. It has no
store-of-value proposition by design — spendable balances reset every 11 days. This
is intentional: MTK exists to meter access to a messaging network, not to be an
investment vehicle.

### 11.2 Velocity of Money Analysis

The equation of exchange (MV = PQ) provides useful framing:

```
M = money supply in circulation
V = velocity (turnover rate per cycle)
P = price level (fee per message in MTK)
Q = quantity of messages per cycle
```

In a traditional economy, increasing V (faster spending) drives inflation. In
UmbraVox's Universe Cycle:

- **M is reset each cycle** → no long-term monetary base erosion
- **V is bounded by on-chain capacity** (~76.8M msgs/cycle) and fee floor
- **P is adaptive** (EMA + adaptive controller)
- **Q is demand-driven** (users choose how many messages to send)

The key insight: **velocity cannot cause instability** because the cycle reset
absorbs any supply imbalance. High velocity within a cycle burns more tokens faster,
but the boundary reset restores everything. The adaptive controller then adjusts P
for the next cycle.

This is fundamentally different from fiat monetary policy, where velocity shocks
require central bank intervention. Here, the protocol's cycle boundary *is* the
automatic stabilizer.

### 11.3 Token Valuation Framework

Traditional token valuation models (discounted utility, network value) require
modification for cyclical tokens:

**Intrinsic value of 1 MTK**: the messaging utility it provides.

```
value(1 MTK) = messages_purchasable * value_per_message
             = (1 / base_fee) * user_willingness_to_pay_per_message
```

At base_fee = 100 MTK and user willing to pay $0.01/message:
```
value(1 MTK) = (1/100) * $0.01 = $0.0001
```

**Critical observation**: Because spendable MTK expires every 11 days, MTK has no
speculative premium from scarcity or future appreciation. Its value is purely the
present-cycle messaging utility. This is economically healthy for a utility token —
it prevents speculative hoarding that would starve the network of liquidity.

**Staked MTK** has a different valuation:
```
value(staked_MTK) = sum_over_cycles(expected_reward_per_cycle * discount_factor^cycle)
```

Staked balances persist, so they have time-value. Validators effectively earn a
yield on their stake through rewards, creating an interest-rate-like dynamic.

### 11.4 Incentive Compatibility Analysis

**Definition**: A mechanism is incentive-compatible if honest behavior maximizes
each participant's utility.

#### Validators
- **Honest action**: maintain uptime, produce blocks, participate in consensus
- **Reward**: `StakeMultiplier_i = 0.5 + 0.3 * U_i; RawReward_i = StakeMultiplier_i * P_i`, proportional share of pool
- **Deviation**: go offline (U drops), censor (P drops via penalty), Sybil (quadratic cost)
- **Result**: honest action strictly dominates at all parameter values

The stake multiplier formula `0.5 + 0.3*U` ensures that pure capital
(staking alone) captures only the baseline 50% of potential rewards (StakeMultiplier = 0.5). The remaining 30%
requires active uptime participation (at full uptime, StakeMultiplier = 0.8). This solves the "passive staker" problem seen in many PoS
networks.

#### Users
- **Honest action**: send legitimate messages, maintain bidirectional activity
- **Reward**: messaging utility + 5% rebate
- **Deviation**: spam (costs more than utility gained), rebate gaming (burn > rebate at all params)
- **Result**: honest action dominates

The adaptive burn rate (minimum 20%) always exceeds the maximum effective rebate
rate (~14.3% of fee at minimum burn), maintaining the anti-gaming inequality across
all controller states.

#### Onboarders
- **Honest action**: onboard real users who generate genuine activity
- **Reward**: 10% of referred user fees for 3 cycles
- **Deviation**: fake accounts (unprofitable due to burn), front-running (prevented by PoW)
- **Result**: honest action dominates when referred users generate fees > initial grant cost

The 3-cycle expiry prevents rent-seeking and forces continuous contribution.

### 11.5 Mechanism Design Critique

#### Strengths

1. **No reflexivity trap**: Traditional crypto assets suffer from reflexivity —
   price drops → miners/validators exit → security drops → price drops further. The
   Universe Cycle breaks this loop because the pool restores regardless of prior
   cycle conditions. Validator rewards are predictable cycle-to-cycle.

2. **Built-in fiscal policy**: The adaptive controller functions as an automated
   central bank that adjusts the "interest rate" (burn rate) based on economic
   activity. Unlike human-managed monetary policy, it is transparent, deterministic,
   and manipulation-resistant.

3. **Credible commitment to non-dilution**: The conservation invariant + cycle
   reset means no new tokens are ever created. Users can trust that the supply is
   exactly 11B — no chain revision can inflate it. This is stronger than Bitcoin's
   21M cap, which is a consensus rule that could theoretically be changed.

4. **Natural Gresham's Law prevention**: In traditional economics, "bad money
   drives out good." In UmbraVox, there is only one currency, and it expires. There
   is no incentive to hoard MTK (spendable balances reset), eliminating the
   velocity problem that plagues deflationary tokens.

#### Weaknesses and Risks

1. **No external price discovery mechanism**: MTK pricing is entirely internal
   (EMA-based). If an external market for MTK develops (likely once validators sell
   tokens via faucets), the internal price and external price could diverge. A high
   external MTK price (due to faucet scarcity) could make messaging prohibitively
   expensive in real terms even if the internal fee is low.

   **Mitigation**: The 11-day reset acts as a natural price anchor — nobody will pay
   more than 11 days of messaging utility for MTK that expires in 11 days. But
   staked MTK (which persists) could develop a separate, higher valuation.

2. **Cold start problem**: The network needs validators before users can message,
   and validators need users (fee revenue) to justify operating costs. The initial
   reward pool (9.35B) bootstraps validators, but the 11-day reset means early
   validators cannot accumulate wealth — they must find ongoing economic
   justification.

   **Mitigation**: The validator onboarding incentive (10% referral bonus) provides
   an additional revenue stream during the growth phase. Validators who successfully
   build user bases have a sustainable business model from day one.

3. **Staking centralization pressure**: Because staked balances persist and earn
   compound returns (rewards can be re-staked), there is a natural centralizing
   force. Large stakers earn more, can stake more, and capture an increasing share
   of rewards over time.

   **Mitigation**: The stake multiplier formula (50% baseline, 30% uptime)
   limits the pure capital advantage. A validator with 10x the stake earns at most
   ~5x the reward (not 10x) if they have the same uptime.
   The quadratic bonding cost for multiple identities in the same subnet further
   limits concentration.

4. **Adaptive controller gaming**: A sophisticated adversary could intentionally
   manipulate cycle durations across 10+ cycles to push parameters to favorable
   extremes. While expensive, this is theoretically possible.

   **Mitigation**: Hard parameter bounds prevent degenerate states. The 50% damping
   ensures any manipulation requires sustained effort. The cost scales linearly with
   the number of cycles targeted.

### 11.6 Comparative Crypto-Economic Analysis

#### vs Bitcoin (Deflationary Store of Value)
Bitcoin's 21M cap creates scarcity, driving speculative value but also hoarding
(low velocity) and security budget concerns as block rewards diminish. MTK's
cyclical reset solves both: no hoarding incentive (tokens expire), and the reward
pool restores each cycle (no security budget decline). Tradeoff: MTK has zero
store-of-value utility.

#### vs Ethereum (EIP-1559 Adaptive Fee + Burn)
Ethereum's base fee adjustment and partial burn (EIP-1559) is the closest analogue
to MTK's EMA + adaptive burn. Key difference: Ethereum's burn is permanent (net
deflationary when burn > issuance), while MTK's burn is cycle-scoped. Ethereum has
no cycle boundary — its economy is continuous. MTK's discrete cycles provide
cleaner economic resets but introduce the "cycle seam" problem (transactions
in-flight during truncation must be resubmitted).

#### vs Filecoin (Utility Token with Recurring Costs)
Filecoin requires FIL for storage deals — a recurring utility cost similar to MTK's
messaging fees. Both have the "cold start" challenge. Filecoin solved it with a
large ICO and vesting schedule. MTK rejects ICOs (no pre-mine), relying instead on
the onboarding faucet and validator incentives. MTK's model is more equitable but
slower to bootstrap.

#### vs Session/OXEN (Decentralized Messaging + Tokens)
Session is the most direct competitor. OXEN tokens incentivize Service Node
operation, similar to MTK incentivizing validators. Key economic differences:
- OXEN is permanent and tradeable; MTK spendable balances expire
- Session uses PoW for spam prevention; MTK uses fee-based burn
- Session has no cyclical reset; MTK's universe cycle is unique
- Session Service Nodes earn through block rewards; MTK validators earn through
  the pool + fee revenue + onboarding bonuses

### 11.7 Long-Term Economic Sustainability

The critical question: **Can this economy sustain itself indefinitely?**

**Revenue sources for validators (per cycle):**
1. Pool rewards (proportional share of 85% of pool)
2. Block producer fees (20% of non-burn fees)
3. Onboarding bonuses (10% of referred user fees)

**Cost structure for validators:**
- Hardware: ~$18/cycle ($50/month)
- Bandwidth: ~$5/cycle
- Opportunity cost of staked capital

**Break-even analysis:**
At minimum reward (5,000 MTK) and external MTK value of $0.0001:
```
revenue = 5,000 * $0.0001 = $0.50/cycle
cost ≈ $23/cycle
deficit = $22.50/cycle
```

At this valuation, minimum reward is insufficient. Validators need either:
- Higher MTK external value (~$0.005 per MTK for break-even)
- Onboarding bonus revenue
- Higher-than-minimum rewards (early network with few validators)

**With 100 validators sharing 8.35B * 0.85 pool:**
```
per_validator_reward = 7.0975B / 100 ≈ 71.0M MTK/cycle
at $0.0001/MTK = $7,100/cycle — very profitable
```

**At 10,000 validators:**
```
per_validator_reward = 7.0975B / 10,000 ≈ 710K MTK/cycle
at $0.0001/MTK = $71.00/cycle — marginally profitable
at $0.001/MTK = $710/cycle — solidly profitable
```

The network is economically sustainable as long as MTK maintains minimal external
value. The Universe Cycle model ensures the pool never depletes, providing a
permanent revenue base for validators.

### 11.8 Open Questions for Future Research

1. **Optimal damping factor**: Is 0.50 optimal? Lower damping (0.3) responds
   faster but risks oscillation. Higher damping (0.7) is more stable but slower to
   adapt. An empirical study on simulated growth curves would determine the optimal
   value.

2. **Cross-cycle MEV**: Can validators extract value by strategically timing
   transactions near cycle boundaries? The cycle seam (snapshot phase where no
   chat transactions are accepted) creates a blackout period. Validators who know
   the exact truncation timing could front-run the boundary.

3. **External market dynamics**: If MTK develops an external market, how does the
   external price interact with the internal EMA fee? A formal model of the
   two-price system (internal fee vs external market price) is needed.

4. **Optimal treasury cap**: Is 10% the right cap? Too low limits the protocol's
   capacity for funding development and onboarding. Too high concentrates supply.
   The optimal cap depends on expected treasury spending needs, which are
   unknowable at design time.

5. **Validator cartel formation**: At what validator count does cartel formation
   become economically rational? Game-theoretic analysis with repeated games (not
   just one-shot) could reveal cartel stability regions.

6. **Reserve currency effects**: If MTK becomes the dominant token in its niche,
   could it develop reserve-currency dynamics where external entities hold MTK for
   reasons beyond messaging utility? The 11-day expiry on spendable balances
   prevents this for casual holders, but staked MTK could develop this property.
