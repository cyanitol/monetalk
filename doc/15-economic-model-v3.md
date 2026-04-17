# Economic Model v3 (Universe Cycle)

## Changes from v2

| Aspect | v2 | v3 | Rationale |
|--------|----|----|-----------|
| Supply model | Recycling pool with permanent burn | Universe Cycle: full supply restoration each cycle | Prevents long-term deflation, ensures sustainability |
| Burn behavior | Permanent (burned_total only increases) | Cycle-scoped (resets to 0 at boundary) | Each cycle is a fresh universe |
| Fee split | Fixed 65/20/10/5 | Adaptive burn (20-80%), proportional non-burn split | Self-tuning to network growth |
| Cycle duration | Fixed 11 days | Target 11 days, adaptive (early truncation if supply depletes) | Accommodates network growth |
| Parameter adjustment | None | Proportional adaptive controller | Self-tuning parameters |
| Early truncation | Not supported | Supply-based trigger (15% threshold) | Prevents network stall |
| Treasury | Unbounded growth | Capped at 10% of INITIAL_SUPPLY (1.1B) | Prevents concentration |

## Formal Invariants (DO-178C DAL A)

All must hold at all times, verified by property-based testing:

```
1.  Conservation: sum(all_balances) + pool + onboarding_reserve + treasury + burned_total == 11,000,000,000
2.  Intra-cycle burn monotonic: burned_total only increases within a cycle
3.  Cycle boundary: burned_total = 0
4.  Supply restoration: pool(N+1) = INITIAL_SUPPLY - staked - reserve - treasury
5.  Reward floor: reward_per_active_validator >= 5,000 MTK
6.  Fee bounds: fee_floor <= base_fee <= fee_ceiling
7.  Quadratic bonding: stake_required(n) == 50,000 * n^2
8.  Rebate cap: total_rebates <= rebate_rate * total_fees
9.  Punitive factors monotonically decrease during recovery
10. Onboarding bonus cap: <= 0.50 * treasury_allocation_per_cycle
11. Adaptive bounds: burn_rate in [0.20, 0.80], other params in their ranges
12. Minimum cycle: >= 1 epoch (3,927 slots at 11s/slot)
```

### Invariant 9: Punitive Factor Recovery

Epsilon = 0 (strict monotonic decrease during recovery; no gradual increases). Recovery formula:

```
P_carry(t+1) = P_floor + (1 - P_floor) * P_carry(t)
```

Where `P_floor` depends on penalty tier:

| Tier | Offense | P_floor | Recovery to P > 0.95 |
|------|---------|---------|----------------------|
| Tier 1 (minor: brief downtime) | 1st/2nd | 0.3 | 3 cycles (33 days) |
| Tier 2 (moderate: repeated downtime, missed attestations) | 3rd+ | 0.1 | ~22 cycles (242 days) |
| Tier 3 (severe: equivocation, double-signing) | Any | 0.0 | Never (must re-stake) |

## Universe Cycle Model

Each cycle represents a fresh economic universe. The total supply of 11B MTK is fully restored at each cycle boundary, preventing the long-term deflationary spiral that permanent burns would cause. Burning still provides intra-cycle fee pressure and value signaling, but no tokens are permanently destroyed across cycles.

### What Persists Across Cycles

- **Staked balances**: Validator stakes carry over unchanged.
- **Treasury** (capped): Accumulated treasury funds persist, subject to the 10% cap.
- **Onboarding reserve**: Faucet funds for new user onboarding.
- **Penalty carryover**: Punitive factors and recovery timers.
- **Referral attribution**: Validator-to-user referral records.
- **Adaptive parameters**: Controller outputs (burn rate, fee bounds, target messages).

### What Resets at Cycle Boundary

- **Spendable balances**: All non-staked wallet balances reset to 0.
- **burned_total**: Resets to 0 (Invariant 3).
- **Pool**: Recomputed from supply restoration formula (Invariant 4).
- **Fee escrow**: Any pending fee distributions are finalized and cleared.

## Adaptive Parameter Controller

The controller adjusts cycle parameters based on how the previous cycle performed relative to targets. A `duration_ratio` greater than 1.0 means the cycle ran long (underutilized); less than 1.0 means it ran short (high activity). 50% damping is applied to prevent oscillation.

```
duration_ratio = actual_cycle_slots / target_cycle_slots

burn_rate(N+1)    = clamp(burn_rate(N) * duration_ratio,    0.20,  0.80)
fee_floor(N+1)    = clamp(fee_floor(N) / duration_ratio,    5,     100)
fee_ceiling(N+1)  = clamp(fee_ceiling(N) / duration_ratio,  5000,  50000)
target_msgs(N+1)  = clamp(target_msgs(N) * duration_ratio,  1000,  100000000)
```

All adjustments are damped by 50%: the effective ratio used is `1.0 + 0.5 * (duration_ratio - 1.0)`.

### Throughput Context

With the redesigned protocol parameters (4,444 messages per block, 11-second slots, f=0.20), global throughput is ~80.8 msg/sec (~6.98M/day). The adaptive controller's `target_msgs` parameter operates within this capacity:

| Network Size | Msgs/User/Day | Assessment |
|-------------|---------------|------------|
| 1,000 users | ~6,981 | Abundant — very heavy usage supported |
| 10,000 users | ~698 | Comfortable for active messaging |
| 100,000 users | ~69.8 | Strong for privacy-focused communications |
| 1,000,000 users | ~6.98 | Moderate — sharding extends beyond this |

Fee calculations at ~6.98M msgs/day: with a minimum fee of 10 MTK and 65% initial burn rate, the daily burn is ~45.4M MTK. Over an 11-day cycle, total burn is ~499M MTK — well within the 11B supply, with early truncation threshold at 1.65B (15%).

The non-burn fee split (producer, treasury, rebate) is proportional. If burn rate is B, the remaining (1 - B) is split in the same relative proportions as v2 (65/20/10/5 normalized over the non-burn share).

## Early Truncation

If circulating supply drops below a threshold, the cycle terminates early to prevent network stall.

- **Threshold**: 15% of INITIAL_SUPPLY (1.65B MTK). Adaptive range: [5%, 25%].
- **Check frequency**: Evaluated at every epoch boundary.
- **Trigger**: When `sum(spendable_balances) < threshold`, the snapshot phase begins immediately.
- **Effect**: The cycle ends, supply is restored per the Universe Cycle model, and the adaptive controller records the shortened duration for next-cycle parameter adjustment.

## Treasury Cap

The treasury is capped at 10% of INITIAL_SUPPLY (1.1B MTK). When the treasury reaches its cap, any additional treasury-bound fees overflow into the pool, increasing available rewards and rebates for the current or next cycle. This prevents concentration while maintaining a sustainable operations fund. Treasury parameters are updated via chain revisions (see below), not on-chain governance.

## Chain Revisions

Economic parameters are updated via chain revision numbers embedded in genesis blocks, replacing on-chain governance. Nodes must support the current revision plus 3 prior revisions. Parameter changes activate at the next cycle boundary after a new revision is adopted. Operators upgrade node software to adopt new revisions; no voting or multisig is required.

## Wallet Reset Timing

Within each cycle boundary, the reset is atomic (steps 1-5 are indivisible; no intermediate state is observable):

1. **Snapshot**: Rewards calculated on pre-reset balances (end-of-cycle snapshot).
2. **Reset**: All spendable balances set to 0 (staked balances unchanged).
3. **Restore**: `pool = INITIAL_SUPPLY - staked - reserve - treasury`, `burned_total = 0`.
4. **Adjust**: Adaptive controller computes next cycle parameters from duration_ratio.
5. **Credit**: Rewards + rebates credited to wallets from the new pool.

**Result**: New balance = reward + rebate. The cycle begins with fully restored supply.

## Simulation Parameters

For Monte Carlo economic simulation (100,000 cycles):

- Validator count: 100 to 100,000
- Message volume: 100 to 76,800,000 per cycle (~6.98M/day × 11 days)
- Attacker strategies: spam, Sybil, cartel, fee manipulation
- Growth scenarios: 100 to 100,000 validators over 100 cycles
- Success metric: invariants 1-12 hold for all scenarios

Additional output metrics:
- `cycle_duration`: Actual duration of each simulated cycle
- `early_truncation_count`: Number of cycles that triggered early truncation
- `adaptive_param_convergence`: Convergence behavior of burn rate, fee bounds, and target messages
- `treasury_trajectory`: Treasury balance over time (must stay below cap)
