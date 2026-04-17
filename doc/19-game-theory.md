# 19. Game-Theoretic Analysis

This document models strategic interactions among validators, users, and potential attackers within the UmbraVox protocol. Each section derives Nash equilibria and evaluates whether honest participation is the dominant strategy.

## Validator Participation Equilibrium

### Model

Validators choose to participate if their expected reward exceeds their opportunity cost. Each validator $i$ evaluates:

```
participate_i = true  iff  expected_reward_i > opportunity_cost_i
```

### Expected Reward Per Cycle

From doc/06-economics.md, the reward formula is:

```
StakeMultiplier_i = 0.5 + 0.3 * U_i
RawReward_i = StakeMultiplier_i * P_i
Reward_i = (RawReward_i / TotalRawReward) * PoolAllocation
```

Where:
- `U_i` = active_slots / total_cycle_slots (uptime ratio, [0,1])
- `StakeMultiplier_i` = baseline (0.5) + uptime component (0.3 * U_i), range [0.5, 0.8]
- `P_i` = P_flood * P_idle (punitive factor, [0,1])
- `PoolAllocation` = network reward pool allocation for the cycle

Under the Universe Cycle Model, the pool starts each cycle at `INITIAL_SUPPLY - staked - reserve - treasury`. Because the full supply is restored at every cycle boundary (burns are not permanent), the pool size is predictable and does not depend on cumulative burn history. This is a significant improvement over the v2 model, where permanent burns caused the pool to shrink monotonically across cycles.

For an honest validator with full uptime (U=1.0) and no penalties (P=1.0), StakeMultiplier = 0.5 + 0.3 = 0.8:

```
expected_reward ≈ PoolAllocation / N   (for N equally-performing validators)
```

The reward floor guarantees a minimum of 5,000 MTK per validator per cycle.

### Opportunity Cost

| Component | Estimated Cost |
|-----------|---------------|
| Hardware (VPS or dedicated) | ~$50/month (~$18/cycle) |
| Electricity (home node) | ~$5-15/month |
| Stake lockup (50,000 MTK minimum) | Opportunity cost of locked capital |
| Bandwidth (~100 GB/month) | ~$5-10/month |
| **Total** | **~$30-45 per cycle** |

### Equilibrium Analysis

As validator count N increases, per-validator reward decreases monotonically:

```
reward(N) = PoolAllocation * stake_share * stake_multiplier / N
```

Equilibrium occurs at N* where `reward(N*) = opportunity_cost`.

With the pool restored each cycle to `INITIAL_SUPPLY - staked - reserve - treasury`, using initial pool ≈ 9.35B * 0.85 = 7.9475B MTK:

```
max_validators = pool_allocation / min_reward
               = 7,947,500,000 / 5,000
               ≈ 1,589,500 validators (theoretical maximum)
```

Because the pool is restored at every cycle boundary, this theoretical maximum is stable across cycles — it does not shrink over time as it would under a permanent-burn model. In practice, diminishing returns set in earlier due to reward floor compression. As N approaches this ceiling, the per-validator reward compresses toward the 5,000 MTK floor. Validators with higher opportunity costs exit first, establishing a natural equilibrium well below the theoretical maximum.

### Validator Exit Spiral Prevention

A key concern in PoS systems is the death spiral: validators exit → security decreases → confidence drops → more validators exit.

UmbraVox prevents this via negative feedback:

```
If validators exit:
  → fewer validators compete for same pool
  → per-validator reward increases
  → incentive to join/stay increases
  → validator count stabilizes
```

The reward floor of 5,000 MTK guarantees a minimum return regardless of pool distribution dynamics. Under the Universe Cycle Model, the pool can never permanently shrink — each cycle starts with full supply restoration. This is strictly stronger than the v2 argument: even if within-cycle burns reduce the distributable pool temporarily, the next cycle resets to the full pool size. The negative feedback loop from validator exits (fewer validators → higher per-validator reward) combines with cyclical renewal to make an exit spiral structurally impossible.

## Spam Attack Profitability

### Cost Structure

From doc/06-economics.md:

```
Cost(message) = base_fee * ceil(size_bytes / 1024)
base_fee ∈ [10, 10000] MTK
```

At minimum fee (10 MTK per 1KB message):

| Spam Volume | Cost | Burned (65%) | Net Loss |
|-------------|------|-------------|----------|
| 1,000 msgs | 10,000 MTK | 6,500 MTK | 10,000 MTK |
| 100,000 msgs | 1,000,000 MTK | 650,000 MTK | 1,000,000 MTK |
| 1,000,000 msgs | 10,000,000 MTK | 6,500,000 MTK | 10,000,000 MTK |

Note: Under the Universe Cycle Model, burned tokens are restored to the pool at cycle boundary. However, this does not reduce the attacker's cost. The attacker's spendable balance decreases by the full fee amount within the cycle — the economic loss to the attacker is real and immediate regardless of whether the global burn resets.

### Revenue

None. The attacker gains no economic benefit from spamming a private messaging network. Messages are encrypted end-to-end; the attacker cannot monetize them.

### Fee Dynamics Under Sustained Spam

Sustained spam increases the EMA utilization metric:

```
target_msgs_per_epoch = 10,000
ema_msgs = exponential_moving_average(actual_msgs, window=3_epochs)

if ema_msgs > target * 1.5: base_fee *= 1.1  (congestion)
```

Under a 1M message spam attack spread over 3 epochs:
- EMA rises rapidly above 1.5x target
- Fee escalates by 10% per epoch
- After ~15 epochs of sustained overload, fee approaches the 10,000 MTK cap
- At cap: 1M messages costs 10B MTK (nearly the entire token supply)

The fee mechanism is self-regulating: spam makes spam exponentially more expensive. Even if the attacker forces early truncation via supply depletion (see "Supply Depletion Attack" below), the adaptive controller reduces burn rate for the next cycle, making repeat attacks less effective.

### Nash Equilibrium

For any rational actor: `utility(spam) = 0 - cost(spam) < 0`. The dominant strategy is to not spam. This holds at all fee levels within the [10, 10000] bound. The attacker loses their own tokens regardless of whether the global burn resets at cycle boundary — the cost is borne by the attacker's balance, not by the network's aggregate supply.

## Sybil Attack Cost Analysis

### Single-Subnet Attack

From doc/06-economics.md, quadratic bonding within a /16 subnet:

```
stake(n) = 50,000 * n^2 MTK
```

| Validator # | Stake Required | Cumulative |
|-------------|---------------|------------|
| 1st | 50,000 MTK | 50,000 MTK |
| 2nd | 200,000 MTK | 250,000 MTK |
| 3rd | 450,000 MTK | 700,000 MTK |
| 5th | 1,250,000 MTK | 2,750,000 MTK |
| 10th | 5,000,000 MTK | 19,250,000 MTK |

Total for 10 validators in one /16 subnet:

```
sum(50,000 * n^2, n=1..10) = 50,000 * (1 + 4 + 9 + 16 + 25 + 36 + 49 + 64 + 81 + 100)
                            = 50,000 * 385
                            = 19,250,000 MTK
```

This makes concentrated Sybil attacks within a single subnet prohibitively expensive.

### Multi-Subnet Attack

An attacker controlling S distinct /16 subnets places 1 validator per subnet at the minimum stake:

```
cost = 50,000 * S MTK  (linear scaling)
```

To capture 1/3 of a 1,000-validator network (the BFT threshold from doc/04-consensus.md):

```
required_sybils = 333 validators
cost = 333 * 50,000 = 16,650,000 MTK
subnet_requirement = 333 distinct /16 subnets
```

### Combined Cost Assessment

The quadratic bonding is effective within subnets but scales linearly across subnets. However, the PoW challenge adds a per-identity CPU cost:

```
Per Sybil identity: ~10 minutes CPU-bound PoW
333 identities: 333 * 10 min = 3,330 min ≈ 55.5 hours CPU time
```

Total attack cost for 1/3 network capture:
- **Capital**: 16,650,000 MTK staked (at risk of slashing)
- **Computation**: ~55.5 hours of CPU time
- **Infrastructure**: Control of 333 distinct /16 subnets (non-trivial in practice)
- **Risk**: If detected via statistical clustering, Tier 3 penalty applies — 25% stake slashed per identity = 4,162,500 MTK burned

### Recommendation

The cross-subnet linear scaling is the weakest link. Consider implementing cross-subnet detection via stake correlation analysis as a future improvement. Signals to detect: temporal correlation in registration, similar stake amounts, and correlated uptime patterns.

## Fee Market Equilibrium

### Supply Side

From doc/04-consensus.md:

```
slot_duration = 11 seconds
active_slot_coefficient = 0.20
blocks_per_day ≈ 86,400 / 11 * 0.20 ≈ 1,571 blocks/day
```

Block space supply is fixed by protocol parameters and is not responsive to price.

### Demand Side

User message demand is elastic with respect to fee:

```
demand(fee) = D_0 * (1 - elasticity * (fee - base_fee) / base_fee)
```

Users send fewer messages when fees are high and more when fees are low.

### EMA Feedback Mechanism

The EMA adjustment creates a negative feedback loop:

```
High demand → ema_msgs > 1.5 * target → base_fee *= 1.1
  → Demand decreases → ema_msgs falls → base_fee stabilizes or decreases

Low demand → ema_msgs < 0.5 * target → base_fee *= 0.9
  → Demand increases → ema_msgs rises → base_fee stabilizes or increases
```

### Equilibrium Point

Fees stabilize where demand equals supply at the EMA-adjusted base_fee level. The equilibrium fee `f*` satisfies:

```
demand(f*) ≈ target_msgs_per_epoch = 10,000
```

### Bounds Analysis

The hard bounds [10, 10000] MTK serve critical functions:

| Bound | Value | Purpose |
|-------|-------|---------|
| Floor | 10 MTK | Prevents zero-fee spam; ensures all messages have non-trivial cost |
| Ceiling | 10,000 MTK | Prevents prohibitive costs during demand spikes; maintains usability |

### Oscillation Analysis

With EMA parameters (alpha=0.5, window=3 epochs):

- The EMA is moderately responsive to demand changes
- Oscillation damping ratio ≈ 0.5 (underdamped but converging)
- After a demand shock, the fee stabilizes within 2-3 windows (6-9 epochs)
- The 10% adjustment rate (×1.1 or ×0.9) prevents overshooting
- Worst-case oscillation: fee alternates between 0.9x and 1.1x of equilibrium before converging

The combination of bounded fees, moderate EMA responsiveness, and small per-epoch adjustments ensures the fee market converges without runaway oscillation.

## User Rebate Gaming

### Attack Vector

A user creates 2 accounts (A and B) and sends 10 messages between them per cycle to qualify for the 5% rebate (doc/06-economics.md requires msgs_sent >= 10 AND msgs_received >= 10).

### Cost-Benefit Analysis

```
Messages sent: 20 (10 from A→B, 10 from B→A)
Cost per message: base_fee (minimum 10 MTK)
Total cost: 20 * 10 = 200 MTK minimum

Fee split (per doc/06-economics.md):
  65% burned:          130 MTK (burned within cycle, restored to pool at boundary)
  20% block producer:   40 MTK
  10% treasury:         20 MTK
   5% rebate pool:      10 MTK

Rebate earned: 5% of 200 MTK = 10 MTK (split between A and B)
Net cost: 200 - 10 = 190 MTK
```

### Why It Fails

The burn rate always exceeds the rebate rate at all adaptive parameter values. The rebate is 5% of the non-burn portion of the fee, not 5% of the total fee. This holds at both the default burn rate and the adaptive floor:

**At default burn rate (65%):**
```
Fee = 100 MTK
Burned:         65 MTK (65%)
Remaining:      35 MTK
  Block producer: 20 MTK
  Treasury:       10 MTK
  Rebate pool:     5 MTK

Rebate as % of fee: 5/100 = 5%
Net loss: 100 - 5 = 95 MTK (95% loss)
```

**At adaptive floor burn rate (20%):**
```
Fee = 100 MTK
Burned:         20 MTK (20%)
Remaining:      80 MTK
  Rebate pool:  5/35 * 80 = ~11.4 MTK

Rebate as % of fee: 11.4/100 = ~11.4%
Net loss: 100 - 11.4 = 88.6 MTK (88.6% loss)
```

At worst case (burn=20%), the attacker still loses 88.6% of all fees paid. The burn rate (minimum 20%) always exceeds the rebate rate (maximum ~11.4%):

```
For any burn_rate ∈ [0.20, 0.80] and any base_fee > 0: net_loss > 0
```

### Additional Costs for the Attacker

- Creating a second account requires a PoW puzzle (~10 min CPU)
- The second account requires its own onboarding grant or voucher
- If vouched, the voucher takes a 10% sympathetic penalty if the new account misbehaves

### Nash Equilibrium

Rebate gaming is strictly dominated by honest usage. The burn rate ensures message costs always exceed rebates at all adaptive parameter values (burn floor 20% to default 65%). No rational actor would spam messages solely to earn rebates.

## Validator Collusion (Cartel Attack)

### Scenario

A cartel controlling >1/3 of total stake attempts selective censorship — systematically excluding certain sender_addresses from blocks they produce.

### Detection Mechanism

Honest nodes maintain a mempool and can compare included transactions against expected inclusions:

```
For each block from suspected cartel member:
  expected_txs = mempool_txs with fee >= min_included_fee
  missing_txs = expected_txs - block_txs
  if missing_txs consistently exclude specific sender_addresses:
    flag block producer for censorship
```

### Cost-Benefit for Cartel

**Costs of censorship:**
- Tier 2 penalty if detected: P *= 0.5 (halves all future rewards)
- Tier 3 if confirmed Sybil/collusion: P = 0.0 for 10 cycles (110 days) + 25% stake slashed
- Reputational damage: other validators may refuse to peer with flagged nodes
- Reduced reward share: censored transactions still propagate via honest nodes

**Benefits:**
- Ability to delay (not prevent) specific users' messages
- Note: censorship is temporary — honest block producers will eventually include the transaction

### Forced Inclusion Rule

The protocol enforces a forced inclusion rule:

```
if transaction.mempool_age > 100 blocks (~5,500 seconds at f=0.20):
    next honest block producer MUST include it
    failure to include = slashable offense
```

This limits censorship to a maximum delay of ~5,500 seconds (100 blocks × ~55 seconds/block at f=0.20), after which any honest producer must include the transaction or face slashing.

### Assessment

Censorship is profitable only if the value of censoring a specific user exceeds the expected slashing penalty:

```
profit(censor) = value_of_censorship - probability(detection) * slashing_cost
```

With mempool comparison detection and forced inclusion after 100 blocks, the probability of detection approaches 1.0 for sustained censorship. The protocol cannot prevent censorship entirely (a fundamental limitation of any PoS system), but the punitive multiplier system makes it expensive. Rational validators will not censor unless the off-protocol value of censorship is extraordinarily high.

## Treasury Management

Treasury is capped at 10% of INITIAL_SUPPLY (1.1B MTK). Excess flows to pool. Treasury spending is managed through chain revisions (software updates agreed upon by the validator community), not through on-chain governance voting. Parameter changes and protocol upgrades follow the same chain revision process.

## Onboarding Incentive Analysis

Validators earn a 10% bonus on fees generated by users they onboard (attributed via `referrer_validator` field, lasting 3 cycles).

### Honest Onboarding Profitability
- Validator onboards 100 real users who each send 50 messages/cycle at average fee 100 MTK
- Referred fees: 100 * 50 * 100 = 500,000 MTK/cycle
- Onboarding bonus: 0.10 * 500,000 = 50,000 MTK/cycle (for 3 cycles)
- Initial grant cost: 100 * 10,000 = 1,000,000 MTK (one-time)
- Payback period: 1,000,000 / 50,000 = 20 cycles... but grants come from validator's own rewards, and users generate network effects
- At scale: 1,000 users generating 5M MTK in referred fees → 500K MTK bonus/cycle
- Conclusion: profitable for validators who can attract genuinely active users

### Sybil Onboarding Attack
- Attacker creates N fake accounts, generates minimum activity (10 msgs sent, 10 received = 20 messages per doc/06 rebate eligibility)
- Cost per fake account: PoW (10 min CPU) + initial grant (G MTK) + 20 * base_fee (minimum 200 MTK)
- Revenue per fake account: 0.10 * 20 * base_fee = 0.10 * 200 = 20 MTK
- Net loss per fake account: G + 180 MTK + PoW cost
- At minimum fee (10 MTK): cost = G + 200 MTK fees, bonus = 20 MTK, loss = G + 180 MTK
- Under the Universe Cycle Model, burned tokens reset at cycle boundary, but this does not help the attacker: the attacker's balance decreases by the full fee amount within the cycle. At minimum burn rate (20%), the net loss is still: cost - 10% bonus = 90% loss (not counting the 20% that is burned within cycle)
- Conclusion: Sybil onboarding is strictly unprofitable at all fee levels and all adaptive burn rates

### Competitor Undercutting
- Two validators compete to onboard users in the same region
- Validator A charges $5 per onboarding, Validator B charges $3
- Users prefer Validator B; A must lower price or offer better service
- Floor: operational cost of running a node (~$50/month)
- At 100 users/month, minimum charge ≈ $0.50/user to break even on hosting
- The 10% referral bonus subsidizes this: validators can onboard for free if referred user fees exceed hosting costs
- Equilibrium: free onboarding for users, validators profit from referral bonus alone

### Referral Expiry Game Theory
- 3-cycle expiry prevents rent-seeking: validators must continuously onboard to maintain bonus income
- Without expiry: early validators accumulate permanent income streams, creating incumbency advantage
- With expiry: new validators can compete for the same users by offering better service (users can re-onboard via a different validator after natural churn)
- Tradeoff: expiry reduces long-term incentive to onboard, but aligns with the 11-day ephemeral philosophy

## Supply Depletion Attack

An attacker attempts to force early truncation by generating maximum token burn through high-volume message sending.

### Cost Analysis

To trigger early truncation, the attacker must reduce circulating supply below 15% of INITIAL_SUPPLY. Starting from a full distribution, the attacker must cause the burn of approximately 85% of distributed spendable tokens.

With default parameters (burn_rate = 0.65, fee_floor = 10 MTK):
```
tokens_to_burn = 0.85 * distributed_spendable_supply
messages_required = tokens_to_burn / (fee * burn_rate)
attacker_cost = messages_required * fee  (attacker pays full fee, not just burned portion)
```

For a network distributing 7B MTK in spendable balances:
- Tokens to burn: 0.85 * 7B = 5.95B MTK
- At minimum fee: 5.95B / 6.5 = ~915M messages, costing ~9.15B MTK
- This exceeds the total distributed supply — the attacker cannot afford it

Even if the attacker controls a large fraction of supply:
- The EMA fee adjustment escalates fees under sustained spam
- Within ~15 epochs of sustained overload, fees approach the ceiling
- The attack becomes self-limiting

### Maximum Disruption

If an attacker somehow succeeds in triggering early truncation:
- The cycle is shortened (from 11 days to however long the supply lasted)
- The network snapshots, restores supply, and continues
- The adaptive controller reduces burn rate for the next cycle
- The attacker's damage is limited to one shortened cycle

### Repeated Attacks

If the attacker attempts to force early truncation every cycle:
- The adaptive controller drives burn rate toward the 20% floor
- Fee floor rises, making each message more expensive
- The network stabilizes at parameters where the attacker can no longer afford to deplete supply
- After the attacker stops, the controller gradually returns to normal parameters

### Nash Equilibrium

`utility(depletion_attack) = value(shortened_cycle) - cost(mass_fees) < 0`

A shortened cycle has no economic value to the attacker. The cost is massive (requires spending most of the circulating supply in fees). The dominant strategy is to not attack.

## Summary: Nash Equilibria

The following table summarizes the dominant strategies for each player type:

| Player Type | Strategy | Honest Action | Deviation | Outcome of Deviation |
|-------------|----------|--------------|-----------|---------------------|
| Validator | Participate honestly | Run node, produce blocks, maintain uptime | Go offline / censor | Reduced rewards, slashing |
| User | Send messages normally | Pay fees, maintain bidirectional activity | Spam / game rebates | Net loss (burn > rebate at all adaptive parameter values) |
| Attacker (Spam) | Don't spam | Abstain | Send bulk messages | Loses MTK at all fee levels |
| Attacker (Sybil) | Don't create Sybils | Single identity | Create multiple identities | Quadratic cost + detection risk |
| Attacker (Depletion) | Don't deplete supply | Abstain | Force early truncation | Cost exceeds total supply; adaptive controller compensates |
| Attacker (Cartel) | Don't collude | Independent block production | Selective censorship | Slashing risk > censorship value |
| Onboarder | Onboard real users | Attract genuinely active users | Sybil onboarding | Unprofitable (bonus < costs for fake users) |

**Conclusion**: Honest participation is the dominant strategy for all player types under the UmbraVox protocol's economic design. The Universe Cycle Model's cyclical renewal — where burned tokens are restored at each cycle boundary — eliminates permanent supply contraction while preserving within-cycle spam deterrence. The combination of adaptive fee burning (20%-65%), quadratic Sybil bonding, punitive multipliers with multi-cycle recovery, reward floors, forced inclusion rules, and supply restoration creates a mechanism where deviation from honest behavior is strictly unprofitable in expectation. Parameter changes happen via chain revisions, not on-chain governance. The protocol achieves incentive compatibility: individual rationality aligns with collective welfare across all cycle boundaries.

## Expert Game Theory Analysis

This section provides a rigorous, formal game-theoretic treatment of the UmbraVox mechanism. We model the protocol as a mechanism design problem and analyze equilibrium properties, coalition resistance, evolutionary stability, and welfare guarantees. Throughout, we denote the set of validators as $V = \{1, \ldots, N\}$, users as $U$, and adversaries as $A \subseteq V \cup U$. Let $\delta \in (0,1)$ denote the inter-cycle discount factor, $\beta \in [0.20, 0.80]$ the adaptive burn rate, and $\tau = 11$ days the target cycle length.

### 1. Formal Mechanism Design Properties

We evaluate the UmbraVox mechanism $\mathcal{M} = (\Sigma, g, p)$ where $\Sigma$ is the strategy space, $g$ is the allocation rule, and $p$ is the payment rule.

**Definition 1 (Incentive Compatibility).** A mechanism is dominant-strategy incentive compatible (DSIC) if for every player $i$ and every strategy profile $\sigma_{-i}$ of other players:

```
u_i(honest_i, sigma_{-i}) >= u_i(deviate_i, sigma_{-i})   for all deviate_i in Sigma_i
```

**Theorem 1 (Weak DSIC for Validators).** Honest validation (full uptime, no censorship) is a weakly dominant strategy for validators when the reward floor binds.

*Proof sketch.* Consider validator $i$ with strategy $s_i = (U_i, P_i)$:

- Uptime deviation: Setting $U_i < 1$ strictly reduces $\text{StakeMultiplier}_i = 0.5 + 0.3 \cdot U_i$ and thus $\text{RawReward}_i = \text{StakeMultiplier}_i \cdot P_i$ with no compensating benefit. The reward function is monotonically increasing in $U_i$.
- Censorship: Triggers punitive factor $P_i < 1$ with probability approaching 1 under sustained censorship (mempool comparison detection). Expected reward becomes $\mathbb{E}[\text{Reward}] = \text{StakeMultiplier}_i \cdot P_i \cdot (\text{PoolAllocation}/\sum_j \text{RawReward}_j)$, strictly decreasing in $P_i$.

The floor guarantee of 5,000 MTK ensures that even when competitive dynamics compress rewards, honest play yields at least the floor. No deviation can increase the floor payout; deviations can only trigger penalties that reduce it. $\square$

**Caveat.** DSIC holds *within the protocol's reward structure* but does not account for off-protocol payments (e.g., bribes for censorship). The mechanism is DSIC only in the weak sense: when off-protocol utility is zero, honest play weakly dominates. This is standard for blockchain mechanisms — no on-chain mechanism can prevent off-chain side payments (the "dark DAO" problem identified by Daian et al., 2020).

**Theorem 2 (Individual Rationality).** Participation is individually rational for validators when:

```
(PoolAllocation / N) * E[StakeMultiplier_i * P_i] >= opportunity_cost_i
```

Under the Universe Cycle Model, the pool restores to $\text{INITIAL\_SUPPLY} - \text{staked} - \text{reserve} - \text{treasury}$ each cycle, giving a stable lower bound on expected rewards. At current parameters with $N^* \leq 1,590,000$:

```
min_reward = 5,000 MTK per cycle
```

Participation is individually rational when 5,000 MTK exceeds the validator's 11-day operating cost in MTK-denominated terms. If MTK acquires any nonzero exchange value, the floor creates a standing individual rationality guarantee. The mechanism is ex-post individually rational: validators learn their exact reward before committing to the next cycle.

**Theorem 3 (Weak Budget Balance).** The mechanism is weakly budget-balanced: it neither requires external subsidy nor generates unbounded surplus.

*Proof.* The conservation invariant holds at all times:

```
sum(all_balances) + pool + onboarding_reserve + treasury + burned_total = INITIAL_SUPPLY = 11B
```

All rewards are funded from the pool. The pool is a closed-system allocation of pre-existing tokens. No tokens are created; all fees are redistributed or burned (and restored at cycle boundary). The mechanism is self-funding by construction. The 15% pool buffer retention ($\text{PoolAllocation} = 0.85 \cdot \text{pool}$) ensures the pool is never fully depleted in a single cycle, maintaining budget balance across cycles. $\square$

**Theorem 4 (Approximate Allocative Efficiency).** The mechanism achieves approximate allocative efficiency subject to the constraint that message ordering respects fee priority.

The EMA-adjusted fee mechanism acts as a congestion pricing scheme. At equilibrium, $\text{demand}(f^*) \approx \text{target\_msgs\_per\_epoch}$, and messages are included in fee-priority order. This approximates the welfare-maximizing allocation where users with the highest willingness-to-pay are served first. However, two sources of inefficiency exist:

1. **Burn deadweight loss**: The burned fraction $\beta \in [0.20, 0.80]$ of each fee is not redistributed to any agent within the cycle. While tokens are restored at cycle boundary, the intra-cycle burn creates a wedge between private cost and social cost. The deadweight loss is proportional to $\beta \cdot \text{total\_fees}$.

2. **Fee floor rigidity**: The hard floor of $\text{fee\_floor} \geq 5$ MTK may exclude low-value messages that would be socially efficient to include. This is an intentional trade-off: the floor is the spam prevention mechanism, and its welfare cost is the price of Sybil resistance in the message market.

### 2. Repeated Game Analysis

The Universe Cycle Model creates a naturally iterated game $G^\infty(\delta)$ where $G$ is the stage game (one 11-day cycle) and $\delta$ is the discount factor between cycles.

**Discount Factor Derivation.** For a validator with time preference rate $r$ per day:

```
delta = exp(-r * 11)
```

At $r = 0.001$/day (annualized ~44%): $\delta \approx 0.989$.
At $r = 0.01$/day (annualized ~3,660%): $\delta \approx 0.896$.

Since validator stakes persist across cycles and the pool restores fully, validator time preferences are the dominant factor. For any reasonable discount rate, $\delta > 0.85$.

**Theorem 5 (Folk Theorem Application).** For the UmbraVox repeated game with $\delta$ sufficiently close to 1, any individually rational payoff vector is sustainable as a subgame-perfect Nash equilibrium (SPNE) via trigger strategies.

*Application.* Let the cooperative payoff be $\pi^C = (\text{PoolAllocation} / N, \ldots, \text{PoolAllocation} / N)$ (equal sharing among honest validators). Let the defection payoff be $\pi^D_i$ (short-term gain from censorship or shirking) and the punishment payoff be $\pi^P_i$ (reward under Tier 2/3 penalties). Cooperation is sustainable if:

```
pi^C_i / (1 - delta) >= pi^D_i + delta * pi^P_i / (1 - delta)
```

Rearranging:

```
delta >= (pi^D_i - pi^C_i) / (pi^D_i - pi^P_i)
```

For censorship: $\pi^D_i \approx \pi^C_i + \epsilon$ (marginal short-term gain from excluding a transaction), and $\pi^P_i = P_{\text{tier2}} \cdot \pi^C_i = 0.5 \cdot \pi^C_i$ (50% reward reduction). Then:

```
delta >= epsilon / (epsilon + 0.5 * pi^C_i)
```

For small $\epsilon$ (typical: censorship of encrypted messages yields negligible on-chain benefit), $\delta \geq \epsilon / (0.5 \cdot \pi^C_i) \approx 0$. Cooperation is sustainable for essentially any $\delta > 0$.

For Tier 3 violations ($P = 0$ for 10 cycles, 25% stake slashed):

```
pi^P_i = 0 for 10 cycles, then P_recovery over subsequent cycles
NPV(punishment) = -0.25 * stake_i + sum_{t=11}^{inf} delta^t * P_recovery(t) * pi^C_i
```

This makes the punishment payoff deeply negative, further strengthening cooperation incentives.

**Trigger Strategy Implementation.** The protocol *automatically* implements grim trigger strategies through the punitive multiplier system:

- **Tier 1** (P *= 0.9): Mild punishment, recovery in ~2 cycles (22 days). Acts as a "tit-for-tat" response.
- **Tier 2** (P *= 0.5): Moderate punishment, recovery in ~22 cycles (242 days). Acts as a stronger deterrent.
- **Tier 3** (P = 0 for 10 cycles + 25% slash): Near-grim trigger. The validator is economically expelled.

This graduated punishment scheme is superior to a pure grim trigger because:
1. It is *proportional* to the offense (reducing false-positive damage).
2. It allows recovery, maintaining long-run participation incentives.
3. It is *automatic* — no coordination among honest validators is required.

**Renegotiation-Proofness.** The punishment mechanism is partially renegotiation-proof. Punitive factors are enforced on-chain and cannot be unilaterally forgiven by colluding validators. Penalty parameters can only be modified through chain revisions (coordinated software updates), not through on-chain governance votes. This makes renegotiation slow and highly visible, requiring broad validator community agreement to deploy a new client version.

**Formal limitation:** The mechanism is *not* strongly renegotiation-proof in the sense of Farrell and Maskin (1989). A coalition controlling a majority of validators could, in principle, deploy a modified client that reduces penalties for its members. The defense relies on the assumption that such a coalition cannot form cheaply and that client diversity limits coordinated deviation, which we analyze in Section 4.

### 3. Bayesian Game Theory (Incomplete Information)

We model the validator interaction as a Bayesian game $\Gamma^B = (V, \Theta, \Sigma, u, p)$ where:

- $\Theta_i \in \{\text{honest}, \text{adversarial}\}$ is validator $i$'s private type
- $p(\theta)$ is the common prior over type profiles
- $u_i(s, \theta)$ is the utility function

**Theorem 6 (Bayesian Nash Equilibrium).** Honest play constitutes a Bayesian Nash Equilibrium (BNE) when adversarial validators comprise less than 1/3 of total stake, regardless of the prior $p(\theta)$.

*Proof sketch.* Consider validator $i$ of type $\theta_i = \text{honest}$. Given any belief $\mu_i$ over others' types:

```
E[u_i(honest | mu_i)] = E[Reward_i(U=1, P=1) | mu_i]
E[u_i(deviate | mu_i)] = E[Reward_i(U', P') | mu_i]   where at least one of U', P' is suboptimal
```

Since $U_i, P_i$ affect only validator $i$'s own reward share (the mechanism is *separable* in individual strategies), and each component is monotonically rewarded, honest play is a best response regardless of beliefs about others' types. The separability property is key: validator $i$'s reward depends on others' strategies only through the denominator $\sum_j \text{RawReward}_j$. Even if other validators are adversarial (lower $U_j, P_j$), this *increases* $i$'s share, making honesty even more attractive.

**User-Side BNE.** Users face a different information problem: they do not know which validators are honest. Under Dandelion++ routing, users cannot directly select their relay path. The protocol's design ensures that *any* honest validator along the path suffices for message delivery. With adversarial fraction $\alpha < 1/3$:

```
P(message reaches honest validator within k hops) = 1 - alpha^k
```

For $\alpha = 0.33$ and $k = 3$ hops: $P \approx 1 - 0.036 = 0.964$. Users' best response is to participate (send messages) whenever the expected delivery probability exceeds their reservation utility, which holds for any $\alpha < 1/3$.

**Robustness to Type Uncertainty.** The mechanism's Bayesian properties degrade gracefully:

| Adversarial Fraction $\alpha$ | BNE Property | Network Effect |
|------|------|------|
| $\alpha < 0.10$ | Strong BNE; honest is strictly dominant | Normal operation |
| $0.10 \leq \alpha < 0.33$ | BNE holds; honest weakly dominates | Possible message delays, detection triggers penalties |
| $\alpha = 0.33$ | BNE is fragile; censorship becomes feasible | Forced inclusion rule limits damage to ~5,500s (~92 min) delay |
| $\alpha > 0.33$ | BNE may fail for liveness; safety preserved | Network can stall; chain revision intervention required |

### 4. Coalition Formation and Resistance

**Definition 2 (Coalition-Proofness).** A strategy profile $\sigma^*$ is *strong Nash* if no coalition $S \subseteq V$ can jointly deviate to improve all members' payoffs.

**Theorem 7 (Approximate Strong Nash for Small Coalitions).** The honest equilibrium is resilient to coalition deviations of size $|S| < N/3$ (in stake-weighted terms).

*Proof.* Consider a coalition $S$ with total stake $\text{stake}(S) < \text{total\_stake}/3$.

*Can the coalition increase rewards?* The reward formula $\text{Reward}_i = (\text{RawReward}_i / \sum_j \text{RawReward}_j) \cdot \text{PoolAllocation}$ is a proportional sharing rule. A coalition can increase its share only by:
1. Increasing own $\text{RawReward}_i$ — but members are already at maximum (U=1, R=optimal, P=1).
2. Decreasing others' $\text{RawReward}_j$ — this requires attacking honest validators, which triggers detection and slashing.

*Can the coalition censor profitably?* With $\text{stake}(S) < 1/3$, the coalition controls fewer than 1/3 of block production slots (in expectation, via VRF leader election). The forced inclusion rule guarantees that any censored transaction is included within 100 blocks by an honest producer. The coalition can delay but not prevent inclusion, and faces slashing if detected.

*Can the coalition extract MEV?* UmbraVox is a messaging protocol with encrypted payloads. There is no DeFi-style MEV (no swaps, no liquidations). Transaction ordering yields no extractable value beyond fee priority, which is already optimally exploited by including the highest-fee transactions first.

**Analysis at the 1/3 Byzantine Threshold.**

At exactly $\alpha = 1/3$ adversarial stake, the coalition reaches the theoretical BFT safety boundary. Key consequences:

```
Liveness: Coalition can stall consensus by withholding votes
  -> Defense: Ouroboros Praos is probabilistic; stalling requires withholding
     ALL coalition blocks, forfeiting ALL coalition rewards
  -> Cost: 1/3 of PoolAllocation per cycle (~2.25B MTK at full pool)

Safety: Coalition cannot forge blocks or double-spend
  -> The k=11/k=22 security parameters require >50% stake to violate safety
  -> At exactly 33%, safety is preserved with overwhelming probability

Censorship: Coalition can delay all targeted messages by up to ~5,500s (~92 min)
  -> Forced inclusion rule bounds the damage
  -> Sustained censorship triggers Tier 2/3 penalties on coalition members
  -> Expected penalty: 0.25 * stake(S) slashed = 0.25 * (total_stake/3)
```

The critical observation: at $\alpha = 1/3$, the coalition can disrupt liveness but only by sacrificing its own rewards. This creates a negative-sum game for the coalition — disruption costs more than it yields. The mechanism is not perfectly coalition-proof at this threshold (no BFT mechanism is), but the economic penalties make sustained coalition attacks unprofitable.

**Coalition Formation Cost.** For a coalition to reach 1/3 stake:

```
Minimum stake per validator: 50,000 MTK
Quadratic bonding within /16 subnet: 50,000 * n^2

Strategy A (single subnet, n validators):
  Cost = 50,000 * sum(k^2, k=1..n) = 50,000 * n(n+1)(2n+1)/6

Strategy B (distributed, 1 per /16 subnet):
  Cost = 50,000 * m  (for m validators across m subnets)
  Infrastructure: m distinct /16 subnets

To reach 1/3 of N=1000 validators (333 validators):
  Strategy A: 50,000 * 333 * 334 * 667 / 6 ≈ 6.2 * 10^11 MTK (exceeds total supply)
  Strategy B: 50,000 * 333 = 16.65M MTK + 333 distinct /16 subnets
```

Strategy A is impossible. Strategy B is the only feasible path, and it requires significant infrastructure diversity. The quadratic bonding makes concentrated coalition formation infeasible; coalition formation must be distributed, which increases coordination costs and detection risk.

### 5. Evolutionary Game Theory

We model the validator population as an evolutionary game with two pure strategies: $H$ (honest) and $A$ (adversarial).

**Payoff Matrix (per cycle, normalized by PoolAllocation/N):**

Let $x$ denote the fraction of validators playing $H$, and $(1-x)$ the fraction playing $A$.

```
                    Population fraction x plays H
                    ┌──────────────────────────────────┐
Strategy H payoff:  π_H(x) = 1.0   (full reward, no penalties)
Strategy A payoff:  π_A(x) = (1-x) * gain_from_colluding + x * P_detected * penalty
```

More precisely, for adversarial strategies (e.g., selective censorship):

```
pi_H(x) = PoolAllocation / N                          -- honest always gets fair share
pi_A(x) = (PoolAllocation / N) * E[P_effective] + V_censor
         = (PoolAllocation / N) * (1 - p_detect * (1 - P_tier)) + V_censor
```

Where $p_{\text{detect}}$ is the detection probability and $V_{\text{censor}}$ is the off-protocol censorship value.

**Theorem 8 (ESS Analysis).** Honest play $H$ is an Evolutionarily Stable Strategy (ESS) when $V_{\text{censor}} < p_{\text{detect}} \cdot (1 - P_{\text{tier}}) \cdot (\text{PoolAllocation}/N)$.

*Proof.* By Maynard Smith's ESS condition, $H$ is ESS if:

```
(i)  pi_H(H, H) > pi_A(H, H)   [strict best response against own type]
  OR
(ii) pi_H(H, H) = pi_A(H, H) AND pi_H(H, A) > pi_A(H, A)   [tie-breaking]
```

In a population of all-$H$, an $A$-mutant faces detection probability approaching 1 (it is the only anomalous validator). Thus:

```
pi_H(H, H) = PoolAllocation / N
pi_A(H, H) = (PoolAllocation / N) * P_tier2 + V_censor
           = (PoolAllocation / N) * 0.5 + V_censor
```

Condition (i) holds when $V_{\text{censor}} < 0.5 \cdot \text{PoolAllocation}/N$. For a network with 1000 validators and pool ≈ 7.9B MTK: threshold $\approx 0.5 \cdot (7.9 \cdot 0.85)B/1000 = 0.5 \cdot 6.715B/1000 \approx 3.36M$ MTK. The adversarial strategy can only invade if the off-protocol censorship value exceeds ~3.38M MTK per cycle — a very high bar for a private messaging system.

**Replicator Dynamics.**

The replicator equation for the honest strategy fraction $x$:

```
dx/dt = x * (pi_H(x) - pi_bar(x))
      = x * (pi_H(x) - x * pi_H(x) - (1-x) * pi_A(x))
      = x * (1-x) * (pi_H(x) - pi_A(x))
```

Since $\pi_H(x) > \pi_A(x)$ for all $x \in (0,1]$ (under the assumption $V_{\text{censor}} < $ penalty threshold):

- $dx/dt > 0$ for all $x \in (0,1)$: the honest fraction always increases.
- $x = 1$ is the unique stable fixed point.
- $x = 0$ is an unstable fixed point: any small mutation toward honesty invades.

**Can the adversarial strategy invade an honest population?** Only if $V_{\text{censor}}$ exceeds the detection-adjusted penalty. In a messaging protocol with encrypted payloads, $V_{\text{censor}} \approx 0$ for economic actors. For state-level censorship actors, $V_{\text{censor}}$ may be large but non-monetary — the mechanism cannot prevent censorship by actors with unbounded off-protocol budgets. This is a fundamental limitation, not a design flaw.

**Can the honest strategy invade an adversarial population?** At $x \approx 0$ (nearly all adversarial), an honest mutant earns $\pi_H(0) = \text{PoolAllocation}/N$ (full honest reward). Adversarial validators in this population earn reduced rewards due to mutual penalties. If the adversarial population has triggered widespread Tier 2 penalties:

```
pi_A(0) = (PoolAllocation / N) * 0.5^k   (where k = number of accumulated penalties)
pi_H(0) = PoolAllocation / N
```

Since $\pi_H(0) > \pi_A(0)$, the honest mutant outperforms. Honesty invades the adversarial population. The honest strategy is *globally* evolutionarily stable under the protocol's penalty structure.

### 6. Price of Anarchy / Price of Stability

**Definition 3.** Let $\text{SW}(\sigma)$ be the social welfare (total utility) under strategy profile $\sigma$. The Price of Anarchy (PoA) and Price of Stability (PoS) are:

```
PoA = max_{sigma in NE} SW(sigma^*) / SW(sigma)
PoS = min_{sigma in NE} SW(sigma^*) / SW(sigma)
```

where $\sigma^*$ is the social optimum.

**Social Welfare Function.** Define social welfare as total messages delivered minus total costs:

```
SW = sum_u [v_u(messages_u) - fee_u * messages_u] + sum_i [Reward_i - cost_i]
```

where $v_u$ is user $u$'s valuation of sending messages.

**Optimal Allocation (Centralized).** A benevolent dictator would set fees at marginal cost (near zero), include all valuable messages, and distribute rewards proportional to contribution. However, without fees, there is no spam prevention — the optimal allocation is infeasible in a permissionless system.

**Price of Anarchy Bound.**

The dominant source of welfare loss is the burn mechanism. At equilibrium:

```
SW(NE) = SW(optimal) - beta * total_fees - DWL(fee_floor)
```

where $\beta \cdot \text{total\_fees}$ is the burned value and $\text{DWL}(\text{fee\_floor})$ is the deadweight loss from the fee floor excluding low-value messages.

Under the Universe Cycle Model, burned tokens are restored at cycle boundary, limiting the welfare loss to *intra-cycle* effects. The effective PoA depends on cycle utilization:

```
PoA <= 1 / (1 - beta * utilization_ratio)
```

At default parameters ($\beta = 0.65$, typical utilization $\approx 0.60$):

```
PoA <= 1 / (1 - 0.65 * 0.60) = 1 / 0.61 ≈ 1.64
```

That is, selfish behavior causes at most ~64% welfare loss relative to the (infeasible) optimum. This is competitive with known results for congestion games (Roughgarden and Tardos, 2002, show PoA $\leq 4/3$ for linear congestion; UmbraVox's higher bound reflects the additional burn mechanism).

**Adaptive Controller Effect on PoA.** The adaptive controller acts as a feedback mechanism that drives the system toward the target cycle duration. When the cycle runs short (too much burning), the controller reduces $\beta$, reducing the PoA. When the cycle runs long (too little activity), the controller increases $\beta$, but this is offset by lower total fees. The damped proportional control converges to a steady state where:

```
beta_ss * total_fees_ss ≈ constant (determined by target cycle duration)
```

This means the adaptive controller *bounds* the PoA from growing unboundedly under demand shocks. The 50% damping factor prevents oscillation, ensuring that the PoA converges monotonically after a perturbation.

### 7. Auction Theory Perspective

The fee market can be modeled as a repeated multi-unit auction for block space, where each slot is an "item" and messages are "bids."

**Auction Format.** The current mechanism is a *first-price sealed-bid* (FPSB) auction with posted reserve price (fee floor). Each message pays its stated fee; the highest-fee messages are included first.

**Revenue Optimality (Myerson, 1981).** An optimal auction maximizes expected revenue subject to incentive compatibility. The UmbraVox fee mechanism is *not* revenue-optimal in the Myerson sense because:

1. The fee floor is a fixed reserve price, not calibrated to the bidder's value distribution.
2. The EMA adjustment is a heuristic, not derived from optimal auction theory.
3. Users may bid above their true value to ensure inclusion, creating overbidding inefficiency.

However, revenue optimality is explicitly *not* the design goal. The objective is spam prevention and network sustainability, not revenue maximization.

**Truthfulness Analysis.** The mechanism is *not truthful* (not a second-price auction). Users have incentive to:

- **Overbid** during congestion (to ensure inclusion) — creating a "priority fee" dynamic.
- **Wait** during high fees (demand elasticity) — deferring messages to lower-fee periods.
- **Underbid** during low congestion (fee floor is the binding constraint, so underbidding is impossible below the floor).

The non-truthfulness is bounded by the fee ceiling: no user can be forced to pay more than $\text{fee\_ceiling}$ MTK per KB. This bounds the maximum distortion from strategic bidding.

**Comparison with EIP-1559.** Ethereum's EIP-1559 uses a base fee + priority tip model:

| Property | EIP-1559 | UmbraVox EMA |
|----------|----------|-------------|
| Base fee adjustment | Multiplicative (12.5% per block) | Multiplicative (10% per epoch, EMA-smoothed) |
| Truthfulness | Near-truthful for base fee | Not truthful |
| Burn mechanism | 100% of base fee burned permanently | $\beta$% burned within cycle, restored at boundary |
| Tip/priority fee | Separate tip goes to producer | No separate tip; full fee goes through split |
| Responsiveness | Per-block | Per-epoch (slower, smoother) |
| Overshoot risk | Low (small per-block adjustment) | Low (50% EMA damping) |

Key difference: EIP-1559 achieves approximate truthfulness by separating the base fee (burned) from the priority tip (to producer). UmbraVox bundles these into a single fee with fixed proportional split. This simplifies the user experience (one fee parameter) at the cost of strategic bidding incentives.

**Recommendation.** A two-part fee (base + priority) would improve truthfulness. However, for a messaging protocol where fee variance is low and transactions are small, the current mechanism's simplicity may outweigh the theoretical efficiency gains. The welfare loss from non-truthfulness is bounded by $\text{fee\_ceiling} - \text{fee\_floor}$ per message, which is capped at $[5, 50000]$ MTK.

### 8. Information Economics

**Moral Hazard.** After staking and registering, validators can shirk by:

- Reducing uptime (running on unreliable hardware)
- Minimizing effort (not propagating blocks to all peers)
- "Idle gaming" (maintaining heartbeat but not performing useful work)

The principal-agent problem: the protocol (principal) cannot directly observe validator effort; it can only observe *outcomes* (uptime ratio, traffic patterns).

The protocol's response is a *monitoring contract* with the following structure:

```
Monitoring signals: {U_i, P_flood, P_idle}
Reward: monotonically increasing in {U_i}
Penalty: triggered by anomalous signal values
```

**Effectiveness of Monitoring.** By the informativeness principle (Holmstrom, 1979), a signal is useful if it is informative about the agent's action. Each monitoring signal is directly linked to validator behavior:

- $U_i$ (uptime): Direct measure of availability. Shirking requires going offline, which is observable.
- $P_{\text{idle}}$: Detects the specific moral hazard of "heartbeat-only" operation.

The combination of monitoring dimensions makes the contract *informationally rich*. A validator cannot simultaneously shirk and maintain signals at honest levels. Multi-dimensional monitoring is strictly more effective than any single signal (by Holmstrom's sufficient statistic theorem: the combined signal is a sufficient statistic for effort).

**Adverse Selection.** When rewards are high (e.g., early in the network's life, or after validator exits), the pool attracts both high-quality and low-quality validators. Low-quality validators (unreliable hardware, poor connectivity) earn lower rewards but may still enter if the floor exceeds their cost.

The protocol's screening mechanisms:

1. **Stake requirement** (50,000 MTK minimum): Creates a financial barrier that screens out actors without capital commitment.
2. **PoW challenge** (~10 min CPU): Screens out casual entrants.
3. **Uptime-proportional rewards**: Low-quality validators earn proportionally less, creating *self-selection* — only validators who can maintain high uptime find participation profitable.
4. **Quadratic bonding**: Prevents low-quality validators from concentrating in cheap subnets.

**Signaling via Composite Stake.** The effective stake formula $\text{stake}(n) = 50,000 \cdot n^2$ is a *costly signal* in the Spence (1973) sense. A validator's willingness to lock capital signals their type:

- High-quality validators expect to recoup stake through rewards (positive NPV project).
- Low-quality validators face negative NPV at high stake levels (rewards < opportunity cost).

The quadratic scaling amplifies the signaling effect: the marginal cost of an additional identity within a subnet grows linearly, creating a separating equilibrium where honest validators stake once and adversarial validators face rapidly escalating costs.

### 9. Attack Trees (Formal)

For each attack, we provide: preconditions, steps, cost, gain, Nash equilibrium analysis, and worst-case vs expected-case.

#### 9.1 Spam Attack

```
Preconditions: Attacker holds MTK balance >= fee * n_messages
Steps:
  1. Acquire MTK (faucet, purchase, or mining rewards)
  2. Generate n messages at base_fee per KB
  3. Submit to network
Cost:       C_spam = n * base_fee (escalating via EMA)
Gain:       G_spam = 0 (encrypted messages; no monetizable output)
Detection:  Tier 1 at 2x median, Tier 2 at 5x, Tier 3 at 10x
```

**Nash Equilibrium:** $u(\text{spam}) = 0 - C_{\text{spam}} < 0$. Strictly dominated. Not a Nash equilibrium strategy.

**Worst case:** Attacker controls large MTK supply, triggers early truncation. Damage: one shortened cycle. Adaptive controller compensates next cycle. **Expected case:** Attacker exhausts balance within a few epochs; EMA fee escalation makes continuation prohibitive.

#### 9.2 Sybil Attack

```
Preconditions: Control of S distinct /16 subnets, capital for S * 50,000 MTK
Steps:
  1. Provision S machines on distinct /16 subnets
  2. Complete PoW per identity (~10 min each)
  3. Stake 50,000 MTK per identity
  4. Operate validators to accumulate rewards or influence
Cost:       C_sybil = S * 50,000 MTK + S * PoW_cost + infra(S)
Gain:       G_sybil = S/N * PoolAllocation (reward share) - C_operating
Detection:  Statistical clustering (correlated uptime, registration timing)
```

**Nash Equilibrium:** For reward extraction: $G_{\text{sybil}} = (S/N) \cdot \text{PoolAllocation}$. Profitable only if reward share exceeds staking + infrastructure cost. At $N = 1000$, $S = 10$: gain $\approx 67.5M$ MTK/cycle, cost $\approx 500K$ MTK staked + infrastructure. This appears profitable — however, the attacker must maintain honest operation (full uptime) to earn rewards, effectively becoming a legitimate validator set. If the attacker deviates from honest behavior, penalties apply.

**Critical insight:** Sybil for reward extraction converges to honest validation. The mechanism is Sybil-tolerant for reward-seeking attackers: they can only earn rewards by performing useful work.

**Worst case:** 333 Sybil validators (1/3 threshold) collude for censorship. Cost: 16.65M MTK + 333 subnets. Damage: bounded by forced inclusion rule (~5,500s max delay). Slash risk: 25% of 16.65M = 4.16M MTK.

#### 9.3 Cartel / Censorship Attack

```
Preconditions: Coalition controlling >= 1/3 total stake
Steps:
  1. Form coalition (off-chain coordination)
  2. Agree on censorship target (specific sender addresses)
  3. Coalition members exclude target transactions from produced blocks
  4. Maintain coalition discipline across cycles
Cost:       C_cartel = P(detect) * slash_penalty + foregone_fees
Gain:       G_cartel = V_censor (off-protocol, e.g., political value)
Detection:  Mempool comparison, forced inclusion timer
```

**Nash Equilibrium:** Cartel is a Nash equilibrium *only* if $V_{\text{censor}} > \mathbb{E}[\text{penalty}]$ for all cartel members. Since $\mathbb{E}[\text{penalty}]$ includes Tier 2/3 slashing *and* lost future rewards over the recovery period:

```
E[penalty_i] = 0.25 * stake_i + sum_{t=1}^{10} delta^t * Reward_honest / N
```

For a validator with 50,000 MTK stake and per-validator reward of pool_allocation / N (e.g., ~6.72M MTK/cycle at pool ~7.9B and N=1,000): $\mathbb{E}[\text{penalty}] \approx 12,500 + 10 \cdot 6,720,000 \approx 67.2\text{M}$ MTK (present value over the 10-cycle recovery period). The cartel is profitable only if each member values censorship at >67M MTK over the recovery period.

**Worst case:** State-level actor with effectively unlimited off-protocol budget. The mechanism cannot prevent censorship by such actors — this is a fundamental limitation of any permissionless protocol.

#### 9.4 Supply Depletion Attack

```
Preconditions: Control of > 85% of circulating supply
Steps:
  1. Acquire large MTK supply
  2. Send maximum-fee messages continuously
  3. Trigger early truncation (supply < 15% threshold)
Cost:       C_deplete ≈ 0.85 * circulating_supply in fees
Gain:       G_deplete = disruption value of shortened cycle
Detection:  Automatic (on-chain supply monitoring)
```

**Nash Equilibrium:** $C_{\text{deplete}} > \text{total circulating supply}$ (attacker must spend more than exists). Infeasible without controlling nearly all tokens. Strictly dominated.

**Worst case:** Attacker controls 50% of supply, triggers early truncation at 60% of target cycle length. Adaptive controller adjusts: $\beta_{\text{next}} = \beta \cdot 0.6$, making repeat attacks harder. Network experiences a ~6.6 day shortened cycle, then recovers.

#### 9.5 Adaptive Controller Manipulation

```
Preconditions: Ability to influence actual_cycle_slots / target_cycle_slots ratio
Steps:
  1. Cause abnormal cycle duration (via supply depletion or demand suppression)
  2. Force adaptive controller to adjust parameters favorably
  3. Exploit adjusted parameters in subsequent cycle
Cost:       C_manipulate = cost of forcing abnormal cycle
Gain:       G_manipulate = advantage from manipulated parameters
Detection:  Controller output is deterministic and auditable
```

**Nash Equilibrium Analysis:** The 50% damping factor limits the controller's responsiveness to manipulation:

```
Parameter shift per cycle = 0.5 * (raw_adjustment - current_value)
```

An attacker forcing one shortened cycle shifts parameters by at most 50% of the maximum possible adjustment. Multiple cycles of sustained manipulation are required to push parameters to extremes, and each manipulation cycle costs the attacker real tokens. The bounded parameter ranges ($\beta \in [0.20, 0.80]$, etc.) cap the maximum exploitable advantage.

**Worst case:** Sustained manipulation over 5+ cycles pushes $\beta$ to 0.20 (minimum burn). At $\beta = 0.20$, spam becomes ~3.25x cheaper per message. However, the fee floor and ceiling bounds still apply, and the attacker has already spent enormous amounts over the manipulation cycles. Net negative expected value.

#### 9.6 Validator Exit Timing

```
Preconditions: Validator with active stake approaching cycle boundary
Steps:
  1. Maintain honest operation until late in cycle
  2. At cycle boundary - epsilon, go offline or reduce effort
  3. Collect full-cycle reward based on accumulated uptime
  4. Exit (unstake) at cycle boundary
Cost:       C_exit = foregone uptime ratio for final period
Gain:       G_exit = operational savings from early shutdown
Detection:  Uptime ratio tracking (active_slots / total_cycle_slots)
```

**Nash Equilibrium:** A validator going offline in the last ~2 days loses uptime credit for those slots, reducing their uptime ratio and thus their StakeMultiplier (0.5 + 0.3 * U_i). The gain from saving 2 days of operational cost ($\approx \$3-6$) is small relative to the reward reduction from lower uptime ratio. Strictly dominated for any validator intending to continue.

For validators permanently exiting: the timing game has minimal impact because the exit happens at most once. The mechanism is robust to one-shot exit timing.

### 10. Open Problems and Limitations

**10.1 Properties NOT Achieved**

1. **Strong incentive compatibility:** The mechanism is weakly DSIC but not strongly DSIC. Off-protocol payments (bribes, side deals) can create profitable deviations that the on-chain mechanism cannot prevent. This is a known impossibility result for any decentralized mechanism without a trusted third party.

2. **Strong coalition-proofness:** Coalitions above 1/3 stake can disrupt liveness. No BFT-based mechanism avoids this threshold.

3. **Truthful fee revelation:** The first-price fee mechanism is not truthful. Users have incentive to strategically time and price messages. A second-price or EIP-1559-style mechanism would improve truthfulness but adds complexity.

4. **Sybil-proofness across subnets:** The quadratic bonding is effective within subnets but linear across subnets. A well-funded attacker with access to diverse infrastructure can create Sybil identities at linear cost.

5. **MEV resistance:** While the current protocol has no DeFi-style MEV, future extensions (token transfers, smart contracts) could introduce ordering-dependent value extraction. The current mechanism has no explicit MEV protection.

**10.2 Required Assumptions**

The equilibrium results in this analysis require:

1. **Rational actors:** Players maximize expected utility. Irrational, ideological, or state-sponsored actors may deviate from equilibrium strategies regardless of cost.

2. **Common knowledge of rationality:** All players know all players are rational. If some players believe others are irrational, they may preemptively deviate.

3. **Bounded off-protocol value:** The analysis assumes $V_{\text{censor}} < \text{penalty threshold}$. For state-level adversaries, this may not hold.

4. **Detection efficacy:** Penalty mechanisms rely on statistical detection (traffic analysis, mempool comparison, uptime monitoring). If detection has false negatives, punishment strategies weaken.

5. **Honest majority in initial bootstrap:** The system requires $> 2/3$ honest stake at launch. If the initial validator set is adversarial, all equilibrium guarantees fail.

6. **Network synchrony (bounded delay):** Ouroboros Praos requires messages to arrive within a known time bound. Under network partitions, the consensus and economic guarantees weaken.

7. **No hash function breaks:** The PoW challenge (Argon2id) and VRF (Ed25519) must remain computationally hard. Quantum computers or algorithmic breakthroughs could undermine both.

**10.3 Potential Profitable Deviations Missed by Current Analysis**

1. **Cross-cycle information leakage:** Adaptive parameters are public and deterministic. A sophisticated attacker could model the controller's response function and orchestrate multi-cycle strategies that exploit the predictable parameter trajectory. Example: deliberately cause early truncation in cycle $N$ to obtain favorable (lower burn rate) parameters in cycle $N+1$, then execute a spam campaign at reduced cost. The 50% damping limits but does not eliminate this vector.

2. **Validator reward timing arbitrage:** The wallet reset mechanism (all spendable balances go to zero at cycle boundary, then new rewards are credited) creates a discontinuity. A validator who can predict the exact cycle boundary timing could time unstaking or fee-generating activity to maximize the rewards captured in the reset.

3. **Referral laundering:** A validator could establish a legitimate-seeming onboarding operation, then gradually shift to Sybil accounts that generate slightly above the activity threshold (10 messages sent, 10 received to distinct parties). With careful construction of a ring of fake accounts that message each other, the per-account cost might be reduced below the 90% loss estimated in the current analysis. The defense (requiring messages to distinct recipients other than the referrer) helps but does not fully prevent ring structures.

4. **Adaptive controller oscillation exploitation:** If an attacker can induce oscillation in the adaptive controller (alternating between extremely short and normal cycles), the 50% damping may not be sufficient to prevent exploitable parameter swings. This requires further analysis with formal control theory methods — specifically, examining whether the closed-loop system is BIBO (bounded-input, bounded-output) stable under adversarial input.

5. **Stake pool delegation risks:** If the protocol later adds delegation (allowing users to delegate stake to validators), this introduces a new principal-agent problem. Delegators have even less monitoring capability than the protocol, creating a moral hazard layer that the current analysis does not address.

6. **Dark DAO attacks:** A smart contract on another chain could coordinate validators to censor specific messages, paying bribes that are invisible to the UmbraVox protocol. This is the Daian et al. (2020) "dark DAO" problem: the attacker creates an off-chain coordination mechanism that undermines on-chain incentive compatibility. No on-chain mechanism fully prevents this.

**10.4 Summary of Game-Theoretic Guarantees**

| Property | Status | Confidence | Key Assumption |
|----------|--------|------------|----------------|
| Weak DSIC (validators) | Achieved | High | No off-protocol payments |
| Weak DSIC (users) | Achieved (bounded) | Medium | Fee bounds prevent extreme distortion |
| Individual rationality | Achieved | High | Reward floor > operating cost |
| Weak budget balance | Achieved | High | Conservation invariant (formally verified) |
| Approximate efficiency | Achieved (PoA ≤ 1.64) | Medium | Equilibrium fee market |
| BNE under incomplete info | Achieved ($\alpha < 1/3$) | High | Honest majority |
| ESS (honest strategy) | Achieved | High | $V_{\text{censor}} < $ penalty threshold |
| Coalition resistance ($|S| < N/3$) | Achieved | High | Quadratic bonding + penalties |
| Strong coalition-proofness | NOT achieved | N/A | Impossible for BFT mechanisms |
| Truthful fee mechanism | NOT achieved | N/A | FPSB inherently non-truthful |
| Renegotiation-proofness | Partial | Medium | Chain revisions cannot cheaply override penalties |
| Resistance to state actors | NOT achieved | N/A | Fundamental limitation |

This analysis demonstrates that the UmbraVox mechanism achieves the strongest game-theoretic properties that are *possible* for a permissionless, BFT-based protocol. The remaining gaps (strong coalition-proofness, state-actor resistance, perfect truthfulness) correspond to known impossibility results in mechanism design and distributed systems theory.
