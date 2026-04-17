# Hardening 17: Supply Depletion Defense

**Cross-references:**
- `doc/06-economics.md` (fee model, adaptive controller, early truncation)
- `doc/15-economic-model-v3.md` (Universe Cycle model)
- `doc/20-economic-analysis.md` (steady-state analysis, supply depletion economics)
- `doc/proof-04-token-conservation.md` (conservation invariant)
- `doc/proof-06-controller-convergence.md` (geometric convergence, BIBO stability)

---

## 1. Attack Model

### Adversary Profile

An adversary with budget B MTK attempts to drain circulating supply by sending
maximum-fee messages at maximum volume, burning tokens as fast as possible. The
adversary's goal is to trigger early truncation (circulating supply < 15% of 11B
= 1.65B MTK), thereby shortening the cycle and disrupting network service.

### Assumptions

- The adversary controls sufficient accounts to send messages at the maximum
  per-epoch rate without being rate-limited by the EMA fee escalation on a
  single account.
- The adversary is willing to permanently lose all tokens spent on fees (burned
  portion is irrecoverable within the cycle; non-burn portion goes to producers,
  treasury, and rebate pool).
- The adversary's accounts are funded with budget B MTK at the start of the
  cycle.
- The adversary does not control a majority of validators (no consensus-level
  attack).

### Attack Procedure

1. Adversary acquires B MTK (via faucet, purchase from validators, or
   pre-existing balance).
2. Adversary sends messages at the fee ceiling rate, maximising burn per message.
3. Each message costs `fee_ceiling` MTK, of which `burn_rate * fee_ceiling` is
   burned and removed from circulating supply.
4. Adversary continues until either budget is exhausted or early truncation
   triggers.

### What the Adversary Achieves

- A shortened cycle (early truncation).
- Temporary disruption: the cycle boundary fires early, resetting all spendable
  balances.
- No permanent damage: supply restores at the next cycle boundary (Invariant 4,
  proof-04).

### What the Adversary Cannot Achieve

- Permanent supply reduction (Universe Cycle restores supply every boundary).
- Consensus disruption (fee burning does not affect validator set or block
  production).
- Data loss (messages already committed to the chain persist across cycles).

---

## 2. Cost Analysis at Each Burn Rate

### Definitions

```
INITIAL_SUPPLY           = 11,000,000,000 MTK
early_trunc_threshold    = 0.15  (initial)
trigger_supply           = 0.15 * 11B = 1,650,000,000 MTK

distributable_supply     = INITIAL_SUPPLY - staked - reserve - treasury
                         approx 11B - 1B - 1.1B - 0.55B = 8.35B  (reference scenario)

supply_to_burn           = distributable_supply - trigger_supply
                         = 8.35B - 1.65B = 6.70B MTK
```

The adversary must burn 6.70B MTK to trigger early truncation. However, the
adversary pays the full fee, not just the burn portion. The cost to the adversary
is the total fees paid; only `burn_rate` fraction contributes to supply depletion.

```
tokens_burned_per_message = fee * burn_rate
total_fee_per_message     = fee
adversary_cost            = messages_needed * fee
messages_needed           = supply_to_burn / (fee * burn_rate)
adversary_cost            = supply_to_burn / burn_rate
```

Note: the adversary's non-burned fee portion (going to producers, treasury,
rebates) does not leave circulation -- it enters other accounts. So only the
burned fraction depletes supply.

### Cost Table (fee_ceiling = 10,000 MTK, supply_to_burn = 6.70B)

| burn_rate | Burn per msg (MTK) | Messages needed    | Total cost (MTK)     | Cost as % of 11B |
|-----------|--------------------|--------------------|----------------------|-------------------|
| 0.20      | 2,000              | 3,350,000          | 33,500,000,000       | 304.5%            |
| 0.30      | 3,000              | 2,233,333          | 22,333,333,333       | 203.0%            |
| 0.40      | 4,000              | 1,675,000          | 16,750,000,000       | 152.3%            |
| 0.50      | 5,000              | 1,340,000          | 13,400,000,000       | 121.8%            |
| 0.60      | 6,000              | 1,116,667          | 11,166,666,667       | 101.5%            |
| 0.65      | 6,500              | 1,030,769          | 10,307,692,308       | 93.7%             |
| 0.70      | 7,000              | 957,143            | 9,571,428,571        | 87.0%             |
| 0.80      | 8,000              | 837,500            | 8,375,000,000        | 76.1%             |

### Cost Table (fee_ceiling = 50,000 MTK, supply_to_burn = 6.70B)

| burn_rate | Burn per msg (MTK) | Messages needed    | Total cost (MTK)     | Cost as % of 11B |
|-----------|--------------------|--------------------|----------------------|-------------------|
| 0.20      | 10,000             | 670,000            | 33,500,000,000       | 304.5%            |
| 0.40      | 20,000             | 335,000            | 16,750,000,000       | 152.3%            |
| 0.65      | 32,500             | 206,154            | 10,307,692,308       | 93.7%             |
| 0.80      | 40,000             | 167,500            | 8,375,000,000        | 76.1%             |

**Key result:** The adversary cost equals `supply_to_burn / burn_rate` regardless
of fee level. The fee ceiling only affects the number of messages required, not
the total cost. At every burn rate, the cost exceeds 76% of the total supply.

### Adversary Budget Constraint

The adversary must possess `supply_to_burn / burn_rate` MTK to execute the
attack. At burn_rate = 0.80, this is 8.375B MTK -- 76.1% of the total supply.
At burn_rate = 0.20, this is 33.5B MTK -- more than 3x the total supply. The
attack is infeasible at low burn rates and requires near-total supply capture at
high burn rates.

The non-burn portion of each fee (paid to producers, treasury, rebates)
re-enters circulation, partially replenishing the supply the adversary is trying
to deplete. This creates a self-defeating feedback loop: the harder the adversary
burns, the more tokens flow to other participants.

```
effective_burn_per_fee = fee * burn_rate
recirculated_per_fee   = fee * (1 - burn_rate)

Net depletion rate = burn_rate (only the burned fraction leaves circulation)
```

At burn_rate = 0.80: 80% of each fee is burned, 20% recirculates.
At burn_rate = 0.20: 20% of each fee is burned, 80% recirculates.

---

## 3. Maximum Burn Rate

### Worst-Case Parameters

At the most aggressive controller state (maximum burn, maximum fee ceiling):

```
burn_rate    = 0.80  (controller maximum)
fee_ceiling  = 50,000 MTK  (controller maximum)
```

### On-Chain Capacity

```
slots_per_epoch   = 3,927
block_frequency   = 0.20  (1 block per 5 slots on average)
blocks_per_epoch  = 3,927 * 0.20 = 785
msgs_per_block    = 4,444
max_msgs_per_epoch = 785 * 4,444 = 3,488,540
```

### Maximum Burn Per Epoch

```
max_burn_per_epoch = max_msgs_per_epoch * fee_ceiling * burn_rate
                   = 3,488,540 * 50,000 * 0.80
                   = 139,541,600,000 MTK per epoch (theoretical)
```

### Throughput vs Budget Constraint

```
Theoretical max burn per epoch (139.5B MTK) far exceeds the total supply (11B).
With 4,444 messages per block, throughput is NOT the limiting factor for
supply depletion. The adversary's budget is the binding constraint.

At fee_ceiling = 50,000 MTK and burn_rate = 0.80, the adversary needs only:
  messages_needed = 6,700,000,000 / (50,000 * 0.80) = 167,500 messages
  blocks_needed   = 167,500 / 4,444 = 37.7 blocks (~35 minutes of block production)

However, the adversary must HOLD 6.70B / 0.80 = 8.375B MTK (76.1% of total
supply) to pay the fees. This budget constraint — not throughput — is the
primary defense against supply depletion attacks.
```

The cost analysis in Section 2 remains the authoritative defense: at any burn
rate, triggering early truncation costs more MTK than any single entity can possess.

### With Default Parameters (burn_rate = 0.65, fee_ceiling = 10,000)

```
At default parameters, the adversary needs:
  messages_needed = 6,700,000,000 / (10,000 * 0.65) = 1,030,769 messages
  blocks_needed   = 1,030,769 / 4,444 = 232 blocks (~3.6 hours)
  adversary_budget = 6,700,000,000 / 0.65 = 10,307,692,308 MTK (93.7% of supply)
```

The throughput capacity can deliver these messages within hours, but the
adversary would need 93.7% of the total supply to fund the attack — an
impossibility for any single entity.

### Accounting for EMA Fee Escalation

The above analysis assumes the adversary pays a constant fee_ceiling. In
practice, the EMA fee mechanism escalates fees under congestion:

```
if ema_msgs > target * 1.5:  base_fee = base_fee * 1.1
```

This escalation increases the adversary's per-message cost. However, fees are
clamped at fee_ceiling, so escalation saturates. The saturation point is reached
when `base_fee` reaches `fee_ceiling`, after which the adversary pays a constant
rate. The tables above already assume this saturated state (worst case for the
network, best case for the adversary's burn efficiency).

---

## 4. Controller Response

### After Early Truncation

If early truncation fires at epoch E of a target-22-epoch cycle:

```
actual_cycle_slots = E * 3,927
target_cycle_slots = 86,394
duration_ratio     = actual_cycle_slots / 86,394
```

For truncation at the earliest possible point (E = 1, minimum cycle):

```
duration_ratio = 3,927 / 86,394 = 0.04545
```

### Parameter Adjustment (with 50% damping)

From proof-06, the controller applies:

```
x(N+1) = x(N) + 0.5 * (clamp(x(N) * duration_ratio, x_min, x_max) - x(N))
```

For burn_rate at duration_ratio = 0.04545 (extreme early truncation):

```
burn_rate_raw = clamp(0.65 * 0.04545, 0.20, 0.80) = clamp(0.02955, 0.20, 0.80) = 0.20
burn_rate(N+1) = 0.65 + 0.5 * (0.20 - 0.65) = 0.65 - 0.225 = 0.425
```

For fee_ceiling at duration_ratio = 0.04545:

```
fee_ceiling_raw = clamp(10,000 / 0.04545, 5000, 50000) = clamp(220,022, 5000, 50000) = 50,000
fee_ceiling(N+1) = 10,000 + 0.5 * (50,000 - 10,000) = 30,000
```

### Geometric Convergence to Stable State

Per proof-06, Theorem 2.1, the controller error halves each cycle:

```
|e(N+k)| = 0.5^k * |e(N)|
```

If early truncation was triggered by an attack (not organic growth), the
controller over-compensates: it reduces burn_rate and raises fee_ceiling,
making the next cycle more resilient to the same attack. This is the correct
response because the shortened cycle signals excessive burn pressure.

After the attack ends, the controller converges back to the natural equilibrium:

| Cycles after attack | burn_rate (from 0.425) | Residual error |
|---------------------|------------------------|----------------|
| 0                   | 0.425                  | 100%           |
| 1                   | 0.5375                 | 50%            |
| 2                   | 0.59375                | 25%            |
| 3                   | 0.62188                | 12.5%          |
| 5                   | 0.64297                | 3.1%           |
| 7                   | 0.64824                | 0.8%           |

The controller returns to within 1% of the natural burn_rate within 7 cycles
(77 days) after the attack ends. During recovery, the reduced burn_rate makes
repeated attacks more expensive (Section 5).

---

## 5. Multi-Cycle Attack

### Attack Across Consecutive Cycles

If the adversary attacks in cycle N and triggers early truncation, the
controller adjusts parameters for cycle N+1:

```
Cycle N:   burn_rate = 0.65   -> attack triggers early truncation
Cycle N+1: burn_rate = 0.425  -> controller reduces burn_rate
Cycle N+2: burn_rate = 0.3125 -> if attack repeats, further reduction (or recovery if attack stops)
```

### Cost Escalation Per Cycle

The adversary's cost to trigger early truncation is `supply_to_burn / burn_rate`.
As the controller reduces burn_rate, each successive attack becomes more
expensive:

| Cycle | burn_rate | Cost to trigger (MTK) | Cost as % of 11B | Relative to Cycle N |
|-------|-----------|-----------------------|-------------------|---------------------|
| N     | 0.65      | 10,307,692,308        | 93.7%             | 1.00x               |
| N+1   | 0.425     | 15,764,705,882        | 143.3%            | 1.53x               |
| N+2   | 0.3125    | 21,440,000,000        | 194.9%            | 2.08x               |
| N+3   | 0.25625   | 26,146,341,463        | 237.7%            | 2.54x               |
| N+4   | 0.228125  | 29,373,770,492        | 267.0%            | 2.85x               |
| N+5   | 0.214063  | 31,298,245,614        | 284.5%            | 3.04x               |

### Convergence to Floor

The burn_rate floor is 0.20 (Invariant 11). As burn_rate approaches 0.20, the
controller damping slows further reduction:

```
burn_rate approaches 0.20 asymptotically:
  0.65 -> 0.425 -> 0.3125 -> 0.25625 -> 0.228125 -> 0.214063 -> 0.207031 -> 0.203516
```

At burn_rate = 0.20 (floor), the cost to trigger early truncation is:

```
cost = 6,700,000,000 / 0.20 = 33,500,000,000 MTK = 304.5% of total supply
```

This is more than 3x the total supply. The attack is mathematically impossible
at the burn_rate floor because the adversary cannot possess more tokens than
exist.

### Total Multi-Cycle Attack Cost

If the adversary attacks every cycle until burn_rate reaches the floor:

```
Total cost = sum over cycles of (supply_to_burn / burn_rate(N))
           = 6.70B * (1/0.65 + 1/0.425 + 1/0.3125 + 1/0.25625 + ...)
           = 6.70B * (1.538 + 2.353 + 3.200 + 3.902 + 4.384 + 4.672 + ...)
```

The first 4 cycles alone cost:

```
6.70B * (1.538 + 2.353 + 3.200 + 3.902) = 6.70B * 10.993 = 73.65B MTK
```

This is 6.7x the total supply. A sustained multi-cycle attack is impossible.

---

## 6. Steady-State Attack Cost

### After Controller Adapts

Once the controller reaches the burn_rate floor (0.20) after repeated attacks,
the steady-state cost to trigger early truncation each cycle is:

```
steady_state_cost = 6,700,000,000 / 0.20 = 33,500,000,000 MTK per cycle
```

### Adversary Benefit Analysis

What does the adversary gain from triggering early truncation?

1. **Cycle shortened**: network continues operating; only the cycle boundary
   occurs early. All sessions, messages, and validator state persist.
2. **Spendable balances reset**: all users lose their remaining spendable
   balance for the cycle. But this happens every 11 days anyway.
3. **Validator rewards reduced**: validators receive rewards proportional to
   the shortened cycle. This is a minor inconvenience, not a service disruption.

The maximum damage from one early truncation is the loss of the remaining cycle
time (at most ~10.5 days, since minimum cycle is 1 epoch = 12 hours).

### Cost-Benefit Inequality

```
Adversary cost:    33.5B MTK (at floor burn_rate)
Adversary benefit: temporary inconvenience (cycle shortened by at most 10.5 days)
```

For any rational valuation of MTK:

```
cost_in_value = 33.5B * value_per_MTK
benefit_in_value = (disruption_value_to_adversary)

For the attack to be rational: benefit > cost
  -> disruption_value > 33.5B * value_per_MTK
```

At any non-trivial MTK valuation (e.g., $0.0001/MTK):

```
cost = 33.5B * $0.0001 = $3,350,000
benefit = temporary cycle shortening (no permanent damage)
```

No rational adversary would spend $3.35M for a temporary inconvenience that
resolves automatically at the next cycle boundary. The attack is strictly
dominated by non-attack strategies.

### Recirculation Effect

The non-burn portion of the adversary's fees (at burn_rate = 0.20, this is
80% of fees) goes to producers, treasury, and rebate pool. This means:

```
adversary_spent      = 33.5B MTK
actually_burned      = 33.5B * 0.20 = 6.70B MTK
recirculated         = 33.5B * 0.80 = 26.8B MTK
```

The adversary effectively pays 26.8B MTK to validators and the protocol
treasury. The attack is a massive wealth transfer from the adversary to the
network's participants.

---

## 7. Early Truncation Is Not Catastrophic

### What Happens When Early Truncation Fires

1. **Epoch boundary check detects** `circulating_supply < threshold * 11B`.
2. **Minimum cycle guard**: if fewer than 1 epoch has elapsed, truncation is
   deferred (Invariant 12). This prevents rapid-fire cycle resets.
3. **Cycle boundary executes** (atomic, per doc/15-economic-model-v3.md):
   a. Rewards calculated on pre-reset balances (end-of-cycle snapshot).
   b. All spendable balances reset to 0.
   c. Pool restored: `pool = 11B - staked - reserve - treasury`.
   d. `burned_total` reset to 0.
   e. Adaptive controller adjusts parameters for next cycle.
   f. Rewards and rebates credited from the new pool.
4. **New cycle begins** with fully restored supply.

### What Persists Across the Truncation

- Staked balances (validator stakes carry over unchanged).
- Treasury balance (subject to cap).
- Onboarding reserve.
- All committed messages on the chain.
- Validator set and consensus state.
- Adaptive parameters (adjusted by controller).
- Penalty carryover (punitive factors).
- Referral attribution (up to 3 cycles).

### What Is Temporarily Affected

- **Spendable balances**: reset to 0, then re-credited with rewards. Users
  who had unspent tokens lose them, but would have lost them at the normal
  cycle boundary anyway. The loss is at most 10.5 days early.
- **Cycle-scoped metrics**: burned_total resets, fee escrow clears. These
  reset at every boundary regardless.
- **Validator rewards**: proportional to the shortened cycle. Validators earn
  less than a full cycle, but the controller compensates in subsequent cycles.

### Service Continuity

The network never stops operating. Block production, message relay, and
consensus continue through and after early truncation. The cycle boundary is
a bookkeeping operation, not a service interruption.

---

## 8. Circuit Breaker Mechanisms

### Consecutive Early Truncation Detection

If early truncation fires in K consecutive cycles, additional defensive measures
activate.

### Tier 1: Two Consecutive Early Truncations (K = 2)

**Trigger**: Early truncation fires in cycles N and N+1.

**Response**:
- **Minimum burn rate floor raised**: `burn_rate_min` temporarily increases
  from 0.20 to 0.10 (inverted: the floor is lowered to 0.10 to reduce burn
  pressure further, since low burn rate = harder to deplete).

  Wait -- the floor should be *lowered* if the goal is to resist depletion.
  Correcting:

- **Burn rate floor enforced**: `burn_rate_min` held at the Invariant 11
  lower bound of 0.20 for the next cycle. At burn_rate = 0.20, the cost to
  trigger early truncation is `6.70B / 0.20 = 33.5B MTK` (304.5% of total
  supply). Mathematically impossible.
- **Fee ceiling frozen**: fee_ceiling locked at its current value for 1 cycle,
  preventing the controller from raising it (which would increase per-message
  burn).

```
if consecutive_early_truncations >= 2:
    burn_rate_min_override = 0.20  (Invariant 11 lower bound, 1 cycle)
    fee_ceiling_frozen = true      (temporary, 1 cycle)
    burn_rate(N+1) = clamp(controller_output, 0.20, 0.80)
```

### Tier 2: Three Consecutive Early Truncations (K = 3)

**Trigger**: Early truncation fires in cycles N, N+1, and N+2.

**Response** (all Tier 1 measures plus):
- **Temporary fee freeze**: base_fee locked at fee_floor for the next cycle.
  All messages cost fee_floor, minimising burn per message.
- **Burn rate forced to floor**: burn_rate set to 0.20 (Invariant 11 lower
  bound) for the next cycle, bypassing the controller.

```
if consecutive_early_truncations >= 3:
    burn_rate_override = 0.20      (Invariant 11 lower bound, forced, 1 cycle)
    base_fee_override = fee_floor  (forced, 1 cycle)
    fee_ceiling_frozen = true      (forced, 1 cycle)
```

At fee_floor = 5 MTK and burn_rate = 0.20:
```
burn_per_message = 5 * 0.20 = 1.0 MTK
max_burn_per_epoch = 3,488,540 * 1.0 = 3,488,540 MTK
epochs_to_deplete = 6,700,000,000 / 3,488,540 = 1,921 epochs = 960.5 days (~2.6 years)
```

The circuit breaker renders supply depletion attacks completely infeasible.

### Circuit Breaker Reset

When a cycle completes without early truncation, the consecutive counter resets
to 0 and all overrides are lifted. The controller resumes normal adaptive
operation.

```
if cycle completed without early truncation:
    consecutive_early_truncations = 0
    burn_rate_min_override = null
    fee_ceiling_frozen = false
    base_fee_override = null
    burn_rate_override = null
```

### Formal Properties

1. **Circuit breaker does not violate conservation** (Invariant 1): overrides
   only affect burn_rate and fee parameters, not the conservation equation.
2. **Circuit breaker preserves minimum cycle duration** (Invariant 12): the
   1-epoch minimum still applies.
3. **Circuit breaker is temporary**: all overrides lift after one clean cycle.
4. **Circuit breaker parameters are within normal adaptive bounds**:
   burn_rate = 0.20 is the Invariant 11 lower bound, ensuring the circuit
   breaker never violates the burn_rate invariant range [0.20, 0.80].

---

## 9. Game-Theoretic Analysis

### Players

- **Adversary (A)**: budget B MTK, goal is to disrupt the network.
- **Network (N)**: adaptive controller + validator set, goal is to maintain
  11-day cycles.

### Strategy Space

**Adversary strategies**:
- S1: Do nothing (no attack).
- S2: Single-cycle attack (spend B MTK in one cycle to trigger early truncation).
- S3: Multi-cycle sustained attack (attack every cycle).
- S4: Intermittent attack (attack every K cycles to prevent controller adaptation).

**Network responses** (automatic, not strategic):
- R1: Adaptive controller adjusts burn_rate downward after early truncation.
- R2: Circuit breaker activates after consecutive truncations.
- R3: Normal operation (no truncation).

### Payoff Matrix (Single Cycle)

Define adversary utility as:

```
U_A = benefit_from_disruption - cost_of_attack
U_N = network_utility - disruption_damage
```

| Adversary \ Network | Normal (R3)                | Controller (R1)            |
|---------------------|----------------------------|----------------------------|
| No attack (S1)      | U_A = 0, U_N = full        | N/A                        |
| Attack (S2)         | U_A = D - C, U_N = reduced | U_A = D - C, U_N = recovers|

Where:
- C = cost of attack = `supply_to_burn / burn_rate` (Section 2)
- D = disruption benefit (subjective value to adversary)

### Nash Equilibrium Analysis

**Claim**: S1 (no attack) is the dominant strategy for any rational adversary.

**Proof**:

For S2 to be rational: `D > C`, i.e., `D > supply_to_burn / burn_rate`.

At burn_rate = 0.65 (default): `C = 10.31B MTK` (93.7% of total supply).
At burn_rate = 0.20 (floor): `C = 33.5B MTK` (304.5% of total supply).

The disruption benefit D is bounded:
- Early truncation shortens one cycle by at most 10.5 days.
- The network recovers immediately at the next cycle boundary.
- No permanent damage occurs (supply restores, consensus continues).
- The adversary's tokens are permanently lost (within the cycle, and spendable
  balances reset at boundary anyway).

For D > 10.31B MTK to hold, the adversary must value a temporary cycle
shortening more than 93.7% of the total token supply. This requires:

```
marginal_value_of_disruption_per_day > 10.31B / 10.5 days
                                     = 981,904,762 MTK per day of disruption
```

This exceeds the total circulating supply that any single entity could hold.
No rational adversary values temporary disruption at this rate.

**Therefore**: U_A(S1) = 0 > U_A(S2) = D - C < 0 for all realistic D.
S1 strictly dominates S2. The Nash equilibrium is (S1, R3): no attack,
normal operation.

### Repeated Game Analysis (Multi-Cycle)

In the repeated game, the controller's adaptation makes each successive
attack more expensive (Section 5). The adversary faces a supergame where:

```
U_A(S3) = sum_{k=0}^{inf} (D_k - C_k) * delta^k
```

where delta < 1 is the discount factor, D_k is the disruption benefit in
cycle k, and C_k is the cost in cycle k.

Since C_k increases monotonically (burn_rate decreases toward 0.20) while
D_k remains constant (each disruption has the same bounded effect):

```
D_k - C_k < 0 for all k >= 0   (from single-cycle analysis)
```

The sum is strictly negative for all delta in (0, 1). S3 is strictly
dominated by S1 in the repeated game.

### Intermittent Attack (S4)

If the adversary attacks every K cycles, the controller partially recovers
between attacks. After K clean cycles, the burn_rate recovers:

```
burn_rate_recovered = burn_rate_eq - 0.5^K * (burn_rate_eq - burn_rate_post_attack)
```

At K = 5: 96.875% recovery. The adversary must pay nearly the full initial
cost each time. The total cost over T attacks:

```
Total_cost(S4) = T * (supply_to_burn / burn_rate_approx_eq) approx T * 10.31B
```

Each attack achieves only temporary disruption. The cumulative cost scales
linearly while cumulative benefit is bounded (each disruption affects only one
cycle). For any finite budget, S4 is strictly dominated by S1.

### Conclusion

No strategy profile exists where a rational adversary with finite budget
benefits from a supply depletion attack. The unique Nash equilibrium is
(no attack, normal operation).

---

## 10. Monitoring and Alerting

### Metrics for Detection

The following metrics should be computed at every epoch boundary and compared
against thresholds:

#### 10.1 Burn Rate Anomaly

```
burn_this_epoch       = sum of all tokens burned in the current epoch
expected_burn         = target_msgs * base_fee * burn_rate
burn_ratio            = burn_this_epoch / expected_burn

ALERT if burn_ratio > 3.0  (burn exceeding 3x expected)
WARN  if burn_ratio > 2.0
```

#### 10.2 Message Volume Spike

```
msgs_this_epoch       = count of messages in current epoch
ema_msgs              = EMA of messages per epoch (3-epoch window)
volume_ratio          = msgs_this_epoch / ema_msgs

ALERT if volume_ratio > 5.0  (5x normal volume)
WARN  if volume_ratio > 3.0
```

#### 10.3 Circulating Supply Trajectory

```
circulating           = sum(all_spendable_balances)
depletion_rate        = (circulating_prev_epoch - circulating) per epoch
epochs_to_threshold   = (circulating - trigger_supply) / depletion_rate

ALERT if epochs_to_threshold < 4  (less than 2 days)
WARN  if epochs_to_threshold < 8  (less than 4 days)
```

#### 10.4 Fee Ceiling Saturation

```
msgs_at_ceiling = count of messages where fee == fee_ceiling
ceiling_ratio   = msgs_at_ceiling / msgs_this_epoch

ALERT if ceiling_ratio > 0.50  (>50% of messages at fee ceiling)
WARN  if ceiling_ratio > 0.25
```

#### 10.5 Single-Source Concentration

```
For each account:
  account_burn = fees_paid * burn_rate
  account_share = account_burn / burn_this_epoch

ALERT if any account_share > 0.10  (single account causing >10% of burn)
WARN  if any account_share > 0.05
```

### Dashboard Summary

All metrics feed into a validator-local monitoring dashboard. No central
monitoring service is required. Each validator independently computes alerts
from on-chain data. Alert thresholds can be configured per-node.

---

## 11. Emergency Protocol

### Trigger: Extreme Supply Depletion

If circulating supply drops below 5% of INITIAL_SUPPLY (550M MTK), the
emergency protocol activates. This is well below the early truncation
threshold (15%) and represents an extraordinary event that should never
occur under normal conditions or standard attacks.

```
EMERGENCY_THRESHOLD = 0.05 * 11,000,000,000 = 550,000,000 MTK
```

### Emergency Measures

#### 11.1 Immediate Transaction Freeze

```
if circulating_supply < EMERGENCY_THRESHOLD:
    accept_only_essential_transactions = true
```

Essential transactions (still processed):
- Block production and consensus messages.
- Validator heartbeats and attestations.
- Cycle boundary transitions.

Non-essential transactions (frozen):
- User chat messages.
- Faucet claims.
- Staking and unstaking operations.
- Treasury disbursements.

The freeze persists until the next cycle boundary, at which point supply
restores and normal operation resumes.

#### 11.2 Forced Cycle Boundary

If the emergency threshold is reached and at least 1 epoch has elapsed
(Invariant 12), an immediate cycle boundary is triggered:

```
if circulating_supply < EMERGENCY_THRESHOLD
   AND current_epoch >= cycle_start_epoch + 1:
    trigger immediate cycle boundary
    -- This is equivalent to early truncation but at a lower threshold
```

This is a special case of early truncation with a more aggressive threshold.
The normal early truncation mechanism (at 15%) should fire first; the 5%
emergency is a backstop for scenarios where early truncation threshold has
been raised by the adaptive controller (threshold range is [0.05, 0.25]).

#### 11.3 Validator-Voted Emergency Parameter Adjustment

If the emergency protocol fires, validators can signal support for a one-time
parameter adjustment via a special transaction type:

```
EmergencyVote {
    validator_pubkey: [u8; 32],
    proposed_burn_rate: Q,        -- must be in [0.05, 0.20]
    proposed_fee_ceiling: nat,    -- must be in [1000, 5000]
    signature: [u8; 64],
}
```

**Threshold**: 67% of active validators (by stake weight) must submit
matching votes within the same epoch.

**Effect**: If threshold is met, the proposed parameters take effect at
the next cycle boundary, overriding the adaptive controller for one cycle.

**Constraints**:
- Emergency votes are only valid when the emergency protocol is active.
- Proposed parameters must be within emergency bounds (more restrictive
  than normal adaptive bounds).
- The override lasts exactly one cycle; the adaptive controller resumes
  afterward.
- Emergency votes are recorded on-chain for auditability.

#### 11.4 Post-Emergency Recovery

After the emergency cycle boundary:

1. Supply restores normally (Invariant 4).
2. Adaptive controller adjusts parameters based on the extreme duration_ratio.
3. Circuit breaker activates (consecutive early truncation counter increments).
4. Emergency parameter override (if voted) applies for one cycle.
5. All overrides lift after one clean cycle.

The system self-heals through the combination of supply restoration,
adaptive control, and circuit breakers. No manual intervention is required
beyond the optional emergency vote.

### Reachability Analysis

For the emergency threshold (5%) to be reached, the adversary must burn:

```
supply_to_emergency = distributable_supply - 0.05 * 11B
                    = 8.35B - 0.55B = 7.80B MTK
```

At any burn_rate:

```
cost = 7.80B / burn_rate
```

| burn_rate | Cost (MTK)         | % of total supply |
|-----------|--------------------|-------------------|
| 0.80      | 9,750,000,000      | 88.6%             |
| 0.65      | 12,000,000,000     | 109.1%            |
| 0.20      | 39,000,000,000     | 354.5%            |

The emergency threshold is unreachable at any burn_rate. Even at the maximum
burn_rate of 0.80, the cost (9.75B MTK) exceeds the distributable supply.
The adversary would run out of tokens before reaching the emergency level.

**The emergency protocol is a defense-in-depth measure that should never
activate under any plausible scenario.** Its existence provides a formal
guarantee that the protocol has defined behavior even under conditions that
exceed all analyzed attack budgets.

---

## 12. Summary of Attack Unprofitability

| Parameter combination     | Cost to trigger early truncation | Feasibility |
|---------------------------|----------------------------------|-------------|
| burn=0.65, ceil=10,000    | 10.31B MTK (93.7% of supply)     | Infeasible  |
| burn=0.80, ceil=50,000    | 8.38B MTK (76.1% of supply)      | Infeasible  |
| burn=0.20, ceil=5,000     | 33.5B MTK (304.5% of supply)     | Impossible  |
| burn=0.20 (floor, steady) | 33.5B MTK (304.5% of supply)     | Impossible  |
| Circuit breaker active    | 33.5B MTK (304.5% of supply)     | Impossible  |
| Multi-cycle (4 cycles)    | 73.65B MTK cumulative            | Impossible  |

At every parameter combination within the adaptive bounds, a supply depletion
attack costs more tokens than a single entity can possess. The attack is
economically irrational (cost exceeds any possible benefit), self-defeating
(non-burn fees recirculate to network participants), and self-correcting
(the adaptive controller increases attack cost after each attempt).

The Universe Cycle model ensures that even a successful early truncation
causes no permanent damage. Supply restores at the next boundary. The network
continues operating. The adversary loses their entire budget. No rational
actor pursues this strategy.
