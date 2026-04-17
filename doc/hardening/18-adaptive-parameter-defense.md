# 18. Hardening: Adaptive Parameter Defense

**Cross-references:**
- `doc/06-economics.md` lines 138--178 (Adaptive Parameter Controller)
- `doc/15-economic-model-v3.md` lines 70--85 (Controller definition)
- `doc/20-economic-analysis.md` sections 3, 6 (Controller analysis, supply depletion)
- `doc/proof-06-controller-convergence.md` (Convergence proof)

---

## 1. Attack Surface

The adaptive controller adjusts four economic parameters at each cycle
boundary using a single input signal:

```
duration_ratio = actual_cycle_slots / target_cycle_slots
```

where `target_cycle_slots = 86,394` (11 days).

The adversary's lever is `actual_cycle_slots`. This value is determined by
when the cycle ends, which occurs either at the 11-day mark or earlier via
the early truncation trigger:

```
if circulating_supply < early_truncation_threshold * INITIAL_SUPPLY:
    trigger cycle boundary
```

An adversary can influence `actual_cycle_slots` by:

1. **Flooding messages** to burn circulating supply faster, triggering early
   truncation and producing `duration_ratio < 1`.
2. **Withholding messages** (if the adversary controls a large fraction of
   network activity) to slow supply depletion, producing `duration_ratio > 1`
   (cycle runs to full 11-day length or beyond if no truncation fires).

In practice, withholding is only effective if the adversary represents a
significant fraction of legitimate traffic. Flooding is the primary attack
vector because any participant can unilaterally increase message volume.

### Attack Input Path

```
adversary sends spam messages
  -> fees burned (burn_rate fraction)
  -> circulating_supply decreases
  -> early truncation fires sooner
  -> actual_cycle_slots decreases
  -> duration_ratio < 1
  -> controller adjusts parameters for next cycle
```

---

## 2. Parameter Manipulation Goals

### 2.1 Drive burn_rate to Minimum (0.20)

**Goal:** Reduce the per-message cost of spam. At burn_rate = 0.20, only 20%
of each fee is destroyed (vs 65% at default). This means more of each fee
recirculates as producer rewards, treasury, and rebates, lowering the
effective cost of sustained spam.

**Mechanism:** Force early truncation repeatedly. Each shortened cycle
produces `duration_ratio < 1`, which causes:

```
burn_rate_raw(N+1) = burn_rate(N) * duration_ratio    (duration_ratio < 1)
```

The burn rate decreases each cycle.

### 2.2 Drive burn_rate to Maximum (0.80)

**Goal:** Disrupt network usability. At burn_rate = 0.80, users lose 80% of
every fee to burn. Messaging becomes expensive, discouraging legitimate use.

**Mechanism:** Ensure cycles run long (no early truncation, low activity).
This requires the adversary to suppress legitimate traffic or simply wait for
a low-activity period, producing `duration_ratio >= 1`. However, the
adversary cannot force `duration_ratio` significantly above 1 because cycles
have a fixed maximum length of 11 days (86,394 slots). The maximum possible
`duration_ratio` is 1.0 under normal conditions.

**Assessment:** Driving burn_rate to maximum is harder than driving it to
minimum. The adversary can only achieve `duration_ratio` slightly above 1 by
ensuring no early truncation fires; they cannot extend cycles beyond 11 days.
The upward drift is therefore slow and bounded.

### 2.3 Fee Floor / Fee Ceiling Manipulation

**Goal:** Drive `fee_floor` to minimum (5 MTK) to reduce spam cost, or to
maximum (100 MTK) to disrupt usability.

Fee floor adjusts inversely to duration_ratio:

```
fee_floor_raw(N+1) = fee_floor(N) / duration_ratio
```

Early truncation (`duration_ratio < 1`) drives fee_floor UP (protective).
Long cycles (`duration_ratio > 1`) drive fee_floor DOWN.

This means the adversary faces a dilemma: flooding to manipulate burn_rate
down simultaneously pushes fee_floor up, partially offsetting the benefit.

---

## 3. 50% Damping as Defense

### 3.1 Damping Mechanism

The controller applies 50% damping to every parameter adjustment:

```
x(N+1) = x(N) + 0.5 * (x_raw(N+1) - x(N))
```

where `x_raw(N+1) = clamp(x(N) * f(duration_ratio), x_min, x_max)` and the
effective step is halved.

### 3.2 Theorem: Per-Cycle Influence Bound

**Theorem 3.1.** The adversary's per-cycle influence on any parameter x is
at most 50% of the raw desired change.

**Proof.** Let `delta_raw = x_raw(N+1) - x(N)` be the raw change the
adversary achieves by manipulating `duration_ratio`. The actual change
applied is:

```
delta_actual = 0.5 * delta_raw
```

Therefore:

```
|delta_actual| = 0.5 * |delta_raw| <= 0.5 * |delta_raw|
```

The adversary achieves at most half of what an undamped controller would
yield. No matter how extreme the adversary makes `duration_ratio`, the
damping halves the effect.  []

### 3.3 Corollary: Minimum Cycles to Reach Extreme

**Corollary 3.2.** To move parameter x from initial value x_0 to bound
x_bound, the adversary requires at least:

```
k >= ceil(log(|x_bound - x_0| / |x_raw_step|) / log(2))
```

cycles, where `x_raw_step` is the maximum possible raw step per cycle. In
practice, damping forces the adversary to spend at least twice as many
cycles as an undamped system would require.

---

## 4. Hard Clamp Bounds

### 4.1 Unconditional Bounds

Every parameter is clamped after every update:

```
x(N+1) = clamp(x(N) + 0.5 * (x_raw(N+1) - x(N)), x_min, x_max)
```

| Parameter      | Min     | Max     |
|----------------|---------|---------|
| burn_rate      | 0.20    | 0.80    |
| fee_floor      | 5       | 100     |
| fee_ceiling    | 5,000   | 50,000  |
| target_msgs    | 1,000   | 100,000,000 |

### 4.2 Theorem: Absolute Manipulation Bound

**Theorem 4.1 (BIBO Safety).** Regardless of adversary budget, strategy, or
duration of attack, all parameters remain within their clamp bounds for all
time.

**Proof.** By Theorem 4.1 of proof-06-controller-convergence.md:

```
clamp(y, x_min, x_max) = max(x_min, min(y, x_max))
```

For any real y: `x_min <= clamp(y, x_min, x_max) <= x_max`.

Initial values are within bounds. The clamp is applied after every update
step. By induction, `x(N) in [x_min, x_max]` for all N >= 0.

This holds for arbitrary input sequences, including adversarial ones. The
bound does not depend on convergence, damping, or any behavioral assumption
about the adversary.  []

### 4.3 Sufficiency of Bounds for Network Operation

**Theorem 4.2.** The network operates correctly at every parameter
combination within the clamp bounds.

**Proof.** We verify each extreme combination:

**burn_rate = 0.20 (minimum):**
- Fee split: 20% burn, 45.7% producer, 22.9% treasury, 11.4% rebate.
- Anti-spam: 20% of fee is still irreversibly burned within the cycle. At
  fee_floor = 5 MTK, minimum spam cost = 1 MTK burned per message. With
  minimum cycle duration of 3,927 slots and ~889 messages/slot capacity (4,444 msgs/block × 0.20 blocks/slot), an
  adversary can send at most ~3,488,540 spam messages at a cost of 3,488,540 MTK
  burned. This provides meaningful spam resistance even at minimum burn rate.
- Rebate never exceeds burn: 11.4% rebate < 20% burn. The anti-gaming
  inequality holds.

**burn_rate = 0.80 (maximum):**
- Fee split: 80% burn, 11.4% producer, 5.7% treasury, 2.9% rebate.
- Usability: fees are expensive, but fee_floor bounds the minimum cost. Even
  at maximum burn rate and fee_ceiling = 50,000 MTK, users can still send
  messages. The EMA fee mechanism adjusts base_fee downward when volume drops,
  keeping fees near fee_floor during low-activity periods.

**fee_floor = 5 (minimum) with burn_rate = 0.20:**
- Minimum spam cost per message: 5 * 0.20 = 1 MTK burned.
- This is the weakest spam defense point. However, EMA congestion pricing
  raises fees under spam conditions (base_fee * 1.1 per epoch above 1.5x
  target), so sustained spam quickly drives fees above floor.

**fee_floor = 100 (maximum) with burn_rate = 0.80:**
- Per-message cost: minimum 100 MTK, with 80 MTK burned.
- Expensive for casual users, but the adaptive controller would only reach
  this state under extreme network conditions (very short cycles due to
  extreme activity). The controller corrects within 5 cycles once conditions
  normalize.

**fee_ceiling = 5,000 (minimum):**
- Congestion pricing capped at 5,000 MTK. Under extreme demand, this may
  not fully price out spam, but the EMA window (3 epochs) limits the rate
  at which congestion escalates.

**fee_ceiling = 50,000 (maximum):**
- During congestion, fees can reach 50,000 MTK per message (per 1KB). This
  is expensive but bounded. The cycle boundary resets the economy within at
  most 11 days.

**All combinations maintain the conservation invariant:**
```
sum(all_balances) + pool + reserve + treasury + burned == 11,000,000,000
```

The invariant holds at any parameter combination because it depends only on
the fee split accounting (which sums to 1.0 at any burn_rate) and the supply
restoration formula (which is independent of adaptive parameters).  []

---

## 5. Multi-Cycle Manipulation (Ratchet Attack)

### 5.1 Attack Description

The adversary attempts to ratchet a parameter to its extreme over many
cycles by repeatedly forcing early truncation.

### 5.2 Worst-Case: Driving burn_rate from 0.65 to 0.20

**Setup:** burn_rate starts at 0.65 (default). Adversary wants to reach 0.20.

**Per-cycle dynamics:** The adversary forces early truncation at the minimum
cycle duration (1 epoch = 3,927 slots). This gives:

```
duration_ratio = 3,927 / 86,394 = 0.04545
```

Raw target: `burn_rate_raw = 0.65 * 0.04545 = 0.02955`, clamped to 0.20.

After damping:
```
burn_rate(1) = 0.65 + 0.5 * (0.20 - 0.65) = 0.65 - 0.225 = 0.425
```

Second cycle (adversary forces minimum duration again):
```
burn_rate_raw(2) = 0.425 * 0.04545 = 0.01932, clamped to 0.20
burn_rate(2) = 0.425 + 0.5 * (0.20 - 0.425) = 0.425 - 0.1125 = 0.3125
```

Third cycle:
```
burn_rate_raw(3) = 0.3125 * 0.04545 = 0.01420, clamped to 0.20
burn_rate(3) = 0.3125 + 0.5 * (0.20 - 0.3125) = 0.3125 - 0.05625 = 0.25625
```

Fourth cycle:
```
burn_rate(4) = 0.25625 + 0.5 * (0.20 - 0.25625) = 0.25625 - 0.028125 = 0.228125
```

Fifth cycle:
```
burn_rate(5) = 0.228125 + 0.5 * (0.20 - 0.228125) = 0.228125 - 0.014063 = 0.214063
```

Sixth cycle:
```
burn_rate(6) = 0.214063 + 0.5 * (0.20 - 0.214063) = 0.214063 - 0.007031 = 0.207031
```

**Result:** The adversary reaches burn_rate near 0.20 in approximately 6
cycles (~66 days at 11 days/cycle, but the adversary is forcing minimum-
length cycles of 12 hours each, so real elapsed time is ~3 days).

### 5.3 Cost of the Ratchet Attack

To force early truncation, the adversary must burn enough circulating supply
to cross the threshold:

```
early_truncation when: circulating_supply < 0.15 * 11B = 1.65B MTK
```

Starting circulating supply (approximate, after staking and reserves):

```
distributable ~= 8B MTK
threshold = 1.65B
must_burn = 8B - 1.65B = 6.35B MTK
```

At burn_rate = 0.65 and minimum fee_floor = 10 MTK:

```
burn_per_message = 10 * 0.65 = 6.5 MTK
messages_needed = 6.35B / 6.5 = 976,923,077 messages
total_fee_cost = 976,923,077 * 10 = 9,769,230,770 MTK
```

**The adversary must spend approximately 9.77B MTK in fees in a single cycle
to trigger early truncation.** This exceeds the total distributable supply.
The adversary cannot acquire enough MTK to execute even a single forced
truncation without controlling nearly the entire supply.

Even with fees at EMA-adjusted levels (which rise under spam), the cost
increases further. The EMA multiplier compounds: base_fee * 1.1 per epoch
above 1.5x target. Over 1 epoch (3,927 slots), a spam flood would drive
fees to:

```
base_fee after k congested epochs = fee_floor * 1.1^k
```

At k = 10 epochs: `10 * 1.1^10 = 25.9 MTK`, doubling the spam cost.

### 5.4 Theorem: Multi-Cycle Cost Bound

**Theorem 5.1.** To drive burn_rate from x_0 to x_min over k cycles, the
adversary must spend at least:

```
C_total >= k * C_truncation
```

where `C_truncation` is the cost of forcing a single early truncation
(approximately 9.77B MTK at default parameters).

**Proof.** Each cycle boundary resets the supply via the restoration formula:

```
pool(N+1) = INITIAL_SUPPLY - staked - reserve - treasury
```

The adversary's burn from cycle N does not reduce the supply available in
cycle N+1. The adversary must re-spend in every cycle to force truncation
again. Costs are additive across cycles, not cumulative.

From section 5.2, reaching burn_rate ~= 0.20 requires approximately 6
forced truncations. Total cost:

```
C_total >= 6 * 9.77B = 58.6B MTK
```

This exceeds the total supply (11B) by a factor of 5.3. **The ratchet
attack is economically infeasible.**  []

### 5.5 Note on Partial Truncation

Even if the adversary cannot reach full early truncation, they could aim to
shorten cycles moderately. However, any shortening less than early truncation
produces `duration_ratio` close to 1.0, yielding negligible parameter
movement. The early truncation trigger is binary: either the cycle is
truncated (sharp ratio change) or it runs to full duration (ratio = 1.0).
There is no intermediate lever the adversary can exploit.

---

## 6. Feedback Loop Stability (Resonance Attack)

### 6.1 Attack Description

The adversary alternates between forcing short and long cycles to excite an
oscillatory mode in the controller, amplifying parameter swings beyond what
a monotonic attack could achieve.

### 6.2 Theorem: No Oscillatory Modes

**Theorem 6.1.** The adaptive controller has no oscillatory modes. Alternating
perturbations produce strictly smaller parameter deviations than sustained
perturbations in a single direction.

**Proof.** From proof-06-controller-convergence.md Theorem 3.1, the error
dynamics are:

```
e(N+1) = (1 - D) * e(N) = 0.5 * e(N)
```

The update factor `(1 - D) = 0.5` is real and positive. The eigenvalue of
the system is 0.5, which is:
- Real (no imaginary component, so no oscillatory mode)
- Positive (no sign alternation)
- Less than 1 in absolute value (contracting)

For a resonance attack to succeed, the system would need a complex eigenvalue
with magnitude near 1.0. The controller's eigenvalue is 0.5 (real), so no
forcing frequency can excite resonance.

**Alternating attack analysis:** Suppose the adversary forces `duration_ratio
= r_low` in odd cycles and `duration_ratio = r_high` in even cycles:

Cycle 1 (attack): `x(1) = x(0) + 0.5 * (x(0) * r_low - x(0))`
Cycle 2 (reverse): `x(2) = x(1) + 0.5 * (x(1) * r_high - x(1))`

Substituting:
```
x(1) = x(0) * (1 + 0.5*(r_low - 1))
x(2) = x(1) * (1 + 0.5*(r_high - 1))
     = x(0) * (1 + 0.5*(r_low - 1)) * (1 + 0.5*(r_high - 1))
```

If `r_low * r_high = 1` (adversary alternates symmetrically):
```
Let r_low = 1/a, r_high = a for some a > 1.

x(2) = x(0) * (1 + 0.5*(1/a - 1)) * (1 + 0.5*(a - 1))
     = x(0) * (1 - 0.5*(a-1)/a) * (1 + 0.5*(a-1))
     = x(0) * (1 - 0.5*delta/a) * (1 + 0.5*delta)

where delta = a - 1.

     = x(0) * (1 + 0.5*delta - 0.5*delta/a - 0.25*delta^2/a)
     = x(0) * (1 + 0.5*delta*(1 - 1/a) - 0.25*delta^2/a)
```

For any a > 1, the term `-0.25*delta^2/a` is negative, so the net two-cycle
effect is less than the effect of applying delta in one direction for two
cycles. Alternating perturbations partially cancel.

**Conclusion:** The controller is not susceptible to resonance attacks. The
purely real eigenvalue and 50% damping ensure monotonic convergence from any
perturbation sequence.  []

### 6.3 Corollary: Worst-Case Forcing is Monotonic

**Corollary 6.2.** The adversary's optimal strategy for moving a parameter
toward a bound is sustained monotonic forcing (same direction every cycle).
Any alternation wastes adversary budget.

This follows directly from the cancellation shown in the alternating analysis
above. The adversary gains nothing from oscillatory strategies.

---

## 7. Parameter Independence

### 7.1 Theorem: No Cascade Effect

**Theorem 7.1.** Manipulation of one adaptive parameter does not affect the
evolution of any other adaptive parameter.

**Proof.** The four parameter update equations are (from doc/06-economics.md
lines 153--162):

```
burn_rate(N+1)   = burn_rate(N)   + 0.5 * (clamp(burn_rate(N)   * r, 0.20, 0.80)    - burn_rate(N))
fee_floor(N+1)   = fee_floor(N)   + 0.5 * (clamp(fee_floor(N)   / r, 5, 100)        - fee_floor(N))
fee_ceiling(N+1) = fee_ceiling(N) + 0.5 * (clamp(fee_ceiling(N) / r, 5000, 50000)   - fee_ceiling(N))
target_msgs(N+1) = target_msgs(N) + 0.5 * (clamp(target_msgs(N) * r, 1000, 100000000) - target_msgs(N))
```

Each equation depends only on its own current value and the shared input `r`
(duration_ratio). There are no cross-terms: `burn_rate(N+1)` does not depend
on `fee_floor(N)`, `fee_ceiling(N)`, or `target_msgs(N)`, and vice versa.

The system Jacobian with respect to the parameter vector
`[burn_rate, fee_floor, fee_ceiling, target_msgs]` is diagonal:

```
J = diag(1 - D, 1 - D, 1 - D, 1 - D) = 0.5 * I_4
```

(proof-06-controller-convergence.md Theorem 8.1)

A diagonal Jacobian means the parameters are decoupled. Perturbation in one
dimension has zero effect on the others.

**Indirect coupling note:** While the parameters do not couple through the
controller equations, they do share the input `r`. An adversary who
manipulates `r` affects all four parameters simultaneously. However, the
adversary cannot selectively manipulate one parameter while leaving others
unchanged. This is a defense property: any attack on burn_rate also moves
fee_floor (in the protective direction, as shown in section 2.3).  []

---

## 8. Recovery After Manipulation

### 8.1 Theorem: Recovery to Equilibrium in ~5 Cycles

**Theorem 8.1.** Once the adversary ceases manipulation, all parameters
converge to within 5% of equilibrium within 5 cycles and to within 1% in 7
cycles.

**Proof.** This is a direct application of proof-06-controller-convergence.md
Theorem 2.1. When the adversary stops, `duration_ratio` returns to its
natural value (approximately 1.0 for a well-functioning network). The error
from equilibrium evolves as:

```
|e(N+k)| = 0.5^k * |e(N)|
```

At k = 5: residual error = 0.5^5 = 3.125% < 5%.
At k = 7: residual error = 0.5^7 = 0.78% < 1%.

**Worst case (parameter at bound):** If the adversary has driven burn_rate
to 0.20 and equilibrium is 0.65:

```
e(0) = 0.20 - 0.65 = -0.45

Cycle 1: burn_rate = 0.20 + 0.5 * (0.65 - 0.20) = 0.425
Cycle 2: burn_rate = 0.425 + 0.5 * (0.65 - 0.425) = 0.5375
Cycle 3: burn_rate = 0.5375 + 0.5 * (0.65 - 0.5375) = 0.59375
Cycle 4: burn_rate = 0.59375 + 0.5 * (0.65 - 0.59375) = 0.621875
Cycle 5: burn_rate = 0.621875 + 0.5 * (0.65 - 0.621875) = 0.6359375
```

After 5 cycles: burn_rate = 0.636, within 2.2% of equilibrium (0.65).

**Elapsed time:** 5 cycles * 11 days = 55 days. If cycles ran at the target
duration, recovery completes within ~55 days. If cycles were shortened during
the attack, recovery begins as soon as the adversary stops, and the first
post-attack cycle runs at or near normal duration.  []

### 8.2 No Persistent Damage

The Universe Cycle model guarantees that supply restores at every cycle
boundary:

```
pool(N+1) = INITIAL_SUPPLY - staked - reserve - treasury
```

The adversary's spending in prior cycles has no effect on future supply.
There is no hysteresis or permanent state change from controller
manipulation. The only persistent effect is the parameter values themselves,
which recover geometrically per Theorem 8.1.

---

## 9. Governance-Free Design

### 9.1 No Human Governance Surface

The adaptive controller operates algorithmically with no human governance
mechanism:

- No multisig controls parameter bounds.
- No voting mechanism selects parameter values.
- No DAO or committee can override the controller.
- No admin keys exist for parameter adjustment.

All parameter adjustments are computed deterministically from on-chain data
(`actual_cycle_slots`). Every node independently computes the same parameter
values. There is no off-chain input.

### 9.2 Social Engineering Resistance

Because no governance mechanism exists, the following social attacks are
impossible:

1. **Governance capture:** No governance body to capture.
2. **Bribery of voters:** No voters to bribe.
3. **Key compromise:** No admin keys to compromise.
4. **Social pressure on committee:** No committee exists.
5. **Proposal manipulation:** No proposal mechanism.

The controller's behavior is defined entirely by the protocol specification
and the clamp bounds. Changing the bounds or damping factor requires a chain
revision (section 10).

### 9.3 Tradeoff

The absence of governance means the protocol cannot quickly adapt to
unforeseen economic conditions that fall outside the clamp bounds. This is an
intentional design choice: predictability and manipulation resistance are
prioritized over flexibility. The chain revision mechanism (section 10)
provides an escape valve for truly exceptional circumstances.

---

## 10. Chain Revision as Override

### 10.1 Mechanism

In extreme cases where the adaptive controller cannot adequately respond
(e.g., network conditions require parameters outside the current clamp
bounds), a chain revision can modify:

- Clamp bounds (x_min, x_max for each parameter)
- Damping factor D
- Initial parameter values for the next cycle
- Early truncation threshold bounds

### 10.2 Activation Process

From doc/06-economics.md lines 399--404:

1. Developers release new node software containing the updated chain revision
   number and parameter definitions.
2. Validators upgrade their software to adopt the new revision.
3. Each genesis block carries a `chain_revision` integer.
4. Nodes must support the current revision plus 3 prior revisions.
5. Parameter changes take effect at the cycle boundary following activation.

### 10.3 Security Properties

- **No on-chain governance:** Chain revisions are software updates, not
  on-chain votes. There is no smart contract to exploit, no voting token to
  accumulate, no quorum to manipulate.
- **Voluntary adoption:** Each validator independently decides whether to
  upgrade. There is no forcing function. This is equivalent to Bitcoin's
  soft/hard fork model.
- **Backward compatibility window:** Support for 3 prior revisions (33+ days
  of overlap) prevents network splits from slow adopters.
- **Transparency:** All revision changes are visible in the source code.
  There are no hidden parameters or privileged overrides.

### 10.4 When Chain Revision Is Warranted

A chain revision for parameter bounds should be considered only when:

1. The adaptive controller is saturated at a bound for 10+ consecutive cycles
   AND the saturation is causing measurable harm (cycle durations consistently
   outside [0.5, 1.5] * target).
2. A structural change in network usage patterns makes the current bounds
   permanently inadequate (not merely a transient spike).
3. A security vulnerability is discovered in the controller logic itself.

Chain revisions should NOT be used to react to temporary adversarial
manipulation, as the controller self-corrects within 5 cycles (section 8).

---

## 11. Formal Manipulation Bound

### 11.1 Definitions

Let:
- `B` = adversary's budget in MTK for a single cycle
- `x` = any adaptive parameter
- `x(N)` = value of x at the start of cycle N
- `delta(N)` = `x(N+1) - x(N)` = parameter change achieved by the adversary

### 11.2 Theorem: Per-Cycle Manipulation Bound

**Theorem 11.1.** An adversary with budget B can shift parameter x by at
most:

```
|delta(N)| <= 0.5 * |x_bound - x(N)|
```

where `x_bound` is the clamp bound in the direction of manipulation. This
bound holds regardless of B.

**Proof.** The maximum possible raw change occurs when `duration_ratio` is
at its most extreme value. The most extreme `duration_ratio` is achieved by
forcing the earliest possible truncation:

```
duration_ratio_min = min_cycle_slots / target_cycle_slots
                   = 3,927 / 86,394
                   = 0.04545
```

For burn_rate (proportional to duration_ratio):
```
burn_rate_raw = burn_rate(N) * 0.04545
```

If `burn_rate_raw < x_min = 0.20`, the clamp activates:
```
burn_rate_raw_clamped = 0.20
```

After damping:
```
delta = 0.5 * (0.20 - burn_rate(N))
```

Since `burn_rate(N) >= 0.20` always (by BIBO), and the target is 0.20:
```
|delta| = 0.5 * |0.20 - burn_rate(N)| = 0.5 * |x_min - x(N)|
```

This is exactly `0.5 * |x_bound - x(N)|`.

The bound does not depend on B because the clamp saturates the raw change.
Once the adversary has forced early truncation (which requires spending
~9.77B MTK per section 5.3), making `duration_ratio` even smaller does not
change the clamped output. The marginal return on adversary spending beyond
the truncation threshold is zero.  []

### 11.3 Theorem: Budget-to-Influence Function

**Theorem 11.2.** Define `f(B)` as the maximum parameter shift achievable
with budget B in a single cycle. Then:

```
f(B) = { 0                                        if B < C_trunc
        { 0.5 * |x_bound - x(N)|                  if B >= C_trunc
```

where `C_trunc` is the cost of forcing early truncation (~9.77B MTK at
default parameters).

**Proof.** If the adversary's budget B is insufficient to trigger early
truncation, the cycle runs to full 11-day duration, producing
`duration_ratio = 1.0` and `delta = 0` (no parameter change from the
adversary's actions, since the cycle ended at its natural time).

If B >= C_trunc, the adversary can trigger early truncation at minimum cycle
length, producing the maximum `delta` as shown in Theorem 11.1. Spending more
than C_trunc provides no additional parameter movement because the clamp
bounds saturate the raw change.

Therefore f(B) is a step function, not a continuous function of B. The
adversary gets zero influence below threshold and bounded influence above
threshold. There is no efficient middle ground.  []

### 11.4 Corollary: Multi-Cycle Bound

**Corollary 11.3.** Over k cycles, the adversary with per-cycle budget B
(where B >= C_trunc each cycle) can move parameter x from x_0 toward x_bound
by at most:

```
|x(k) - x_0| <= |x_bound - x_0| * (1 - 0.5^k)
```

The total cost is at least `k * C_trunc`.

**Proof.** At each cycle, the adversary closes half the remaining gap to
x_bound:

```
gap(0) = |x_bound - x_0|
gap(k) = 0.5^k * gap(0)

|x(k) - x_0| = gap(0) - gap(k) = gap(0) * (1 - 0.5^k)
```

This converges to `|x_bound - x_0|` as k -> infinity, but never exceeds it
(the clamp prevents overshooting the bound). Each cycle costs at least
C_trunc (supply restores between cycles), so total cost is at least
`k * C_trunc`.

To reach within 5% of the bound: k >= 5 cycles, cost >= 5 * 9.77B = 48.8B.
To reach within 1% of the bound: k >= 7 cycles, cost >= 7 * 9.77B = 68.4B.

Both totals exceed the total supply (11B) by large factors, confirming
economic infeasibility.  []

---

## 12. Summary of Defense Properties

| Defense Layer | Property | Guarantee |
|---------------|----------|-----------|
| 50% Damping | Per-cycle influence | At most 50% of raw change |
| Hard Clamps | Absolute bounds | Parameters never leave [min, max] |
| Supply Restoration | Cost reset | Adversary must re-spend each cycle |
| EMA Fee Escalation | Spam cost amplification | Fees rise exponentially under sustained spam |
| No Oscillation | Resonance immunity | Real eigenvalue 0.5, no complex modes |
| Parameter Independence | No cascade | Manipulating one parameter does not affect others |
| Geometric Recovery | Post-attack healing | < 5% error in 5 cycles, < 1% in 7 cycles |
| Governance-Free | No social attack surface | Algorithmic-only parameter adjustment |
| Chain Revision | Emergency override | Software update can reset bounds if needed |
| Step-Function Influence | Budget efficiency | Zero influence below truncation cost, bounded above |
