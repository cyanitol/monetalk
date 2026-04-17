# Token Economics (v3 — Universe Cycle Model)

## Initial Token Distribution

Genesis block distributes 11,000,000,000 MTK as follows:

```
9,350,000,000 MTK → Reward Pool       (protocol-controlled, not spendable)
1,100,000,000 MTK → Onboarding Reserve (faucet-controlled)
  550,000,000 MTK → Treasury           (protocol-controlled)
```

No pre-mine, no ICO. All tokens begin in protocol reserves. Users acquire tokens via the onboarding faucet or validator rewards.

## Universe Cycle Model

Each 11-day cycle is a self-contained economic universe. At cycle boundary, the full 11B supply is restored: `burned_total` resets to 0, and the pool absorbs all burned and unspent tokens. This creates intra-cycle scarcity (fees are burned during the cycle) while guaranteeing long-term supply availability.

### What Persists Across Cycles

- Staked balances (validator stakes carry over)
- Treasury balance (subject to cap)
- Onboarding reserve
- Penalty carryover (`P_carryover` per validator)
- Referral attribution (up to 3 cycles)
- Adaptive parameters (burn rate, fee bounds, target messages)

### What Resets at Cycle Boundary

- Spendable balances → 0 (then credited with rewards + rebates)
- `burned_total` → 0
- Pool restores to full allocation (minus persistent reserves)
- Fee escrow → 0

### Supply Restoration Formula

At each cycle boundary:

```
pool(N+1) = INITIAL_SUPPLY - sum(staked_balances) - onboarding_reserve - treasury
```

All burned tokens, unspent balances, and fee escrow are implicitly absorbed back into the pool through this restoration.

### Minimum Cycle Duration

A cycle must last at least 1 epoch (3,927 slots / 12 hours at 11s/slot). If the early truncation trigger fires before 1 epoch has elapsed, truncation is deferred to the end of the current epoch.

## Supply (Conservation Invariant)

```
INVARIANT (intra-cycle):
  sum(all_balances) + pool + onboarding_reserve + treasury + burned_total == INITIAL_SUPPLY
  where INITIAL_SUPPLY = 11,000,000,000 MTK

INVARIANT (cycle boundary):
  burned_total = 0
  pool = INITIAL_SUPPLY - sum(staked_balances) - onboarding_reserve - treasury
```

- `burned_total` is monotonically increasing within each cycle, but resets to 0 at cycle boundary.
- Slashed stake is transferred to `burned_total` within the current cycle.
- **Total**: 11,000,000,000 MTK (pre-generated, fixed, never created)
- **Network Reward Pool**: 85% (9.35B initial) — restored each cycle via supply restoration formula
- **Onboarding Reserve**: 10% (1.1B initial) — replenished via inactive account reclamation
- **Protocol Treasury**: 5% (550M initial, capped at 10% / 1.1B) — parameters updated via chain revisions
- **Burned**: 0 at cycle start — grows within cycle as fees are burned and stakes are slashed, resets at next cycle boundary

## Message Cost (Dynamic, EMA-Adjusted)

### EMA Parameters

```
window        = 3 epochs
alpha         = 2 / (window + 1) = 0.5
EMA(t)        = alpha * actual_utilization(t) + (1 - alpha) * EMA(t-1)
```

At network start (< 3 epochs of history), use simple average of available epochs.

### Fee Calculation

```
target_msgs_per_epoch = target_msgs   -- adaptive, initial 10,000

ema_msgs = EMA(actual_msgs)   -- computed as above with alpha = 0.5

if ema_msgs > target * 1.5:   base_fee = base_fee * 1.1   -- congestion
elif ema_msgs < target * 0.5: base_fee = base_fee * 0.9   -- underuse
else:                          base_fee unchanged           -- stable

base_fee = clamp(base_fee, fee_floor, fee_ceiling)  -- adaptive bounds
Cost(message) = base_fee * ceil(size_bytes / 1024)
```

- No external oracle needed (self-referential to on-chain activity)
- Bounded: `fee_floor` (initial 10 MTK, spam prevention), `fee_ceiling` (initial 10,000 MTK, usability)
- Fee bounds are adaptive per cycle (see Adaptive Parameter Controller)
- EMA smoothing prevents oscillation
- Deterministic: all nodes compute same fee from on-chain data

## Fee Destination (Adaptive Burn Model)

The burn rate is adaptive rather than fixed. The non-burn portion is split in fixed 20:10:5 ratios among producers, treasury, and rebates.

```
burn_rate     = adaptive, initial 0.65, range [0.20, 0.80]
non_burn_rate = 1.0 - burn_rate

Per message fee split:
  burn_rate          → burned (removed from circulation for remainder of cycle)
  non_burn * (20/35) → block producer reward (immediate)
  non_burn * (10/35) → protocol treasury
  non_burn * (5/35)  → user rebate pool (distributed to active users at cycle end)
```

Example at default 65% burn rate: 65% burned, 20% producer, 10% treasury, 5% rebate.
Example at 40% burn rate: 40% burned, ~34.3% producer, ~17.1% treasury, ~8.6% rebate.

## Early Truncation Trigger

If circulating supply drops too low, the cycle ends early to restore the economy.

```
circulating_supply = sum(all_spendable_balances)    -- excludes staked, pool, reserves
early_truncation_threshold = adaptive, initial 0.15, range [0.05, 0.25]

At each epoch boundary:
  if circulating_supply < early_truncation_threshold * INITIAL_SUPPLY:
      if current_epoch >= cycle_start_epoch + 1:   -- minimum 1 epoch duration
          trigger cycle boundary (early truncation)
      else:
          defer truncation to end of current epoch
```

Early truncation records `actual_cycle_slots` for the adaptive controller, then executes the standard cycle boundary process (supply restoration, reward distribution, parameter adjustment).

## Adaptive Parameter Controller

A proportional controller adjusts cycle parameters based on actual vs target cycle duration. Applied at each cycle boundary.

### Duration Ratio

```
target_cycle_slots = 22 * 3,927 = 86,394   -- 11 days in slots (22 epochs × 3,927 slots/epoch at 11s/slot)
duration_ratio = actual_cycle_slots / target_cycle_slots
```

### Parameter Adjustment (with 50% damping)

```
-- Compute raw next-cycle values
burn_rate_raw(N+1)   = clamp(burn_rate(N) * duration_ratio, 0.20, 0.80)
fee_floor_raw(N+1)   = clamp(fee_floor(N) / duration_ratio, 5, 100)
fee_ceiling_raw(N+1) = clamp(fee_ceiling(N) / duration_ratio, 5000, 50000)
target_msgs_raw(N+1) = clamp(target_msgs(N) * duration_ratio, 1000, 100000000)

-- Apply 50% damping to smooth transitions
burn_rate(N+1)   = burn_rate(N)   + 0.5 * (burn_rate_raw(N+1)   - burn_rate(N))
fee_floor(N+1)   = fee_floor(N)   + 0.5 * (fee_floor_raw(N+1)   - fee_floor(N))
fee_ceiling(N+1) = fee_ceiling(N) + 0.5 * (fee_ceiling_raw(N+1) - fee_ceiling(N))
target_msgs(N+1) = target_msgs(N) + 0.5 * (target_msgs_raw(N+1) - target_msgs(N))
```

### Interpretation

- **Cycle ran long** (`duration_ratio > 1`): burn rate increases (more scarcity needed), fee floor/ceiling decrease (cheaper to use), target messages increases.
- **Cycle ran short** (early truncation, `duration_ratio < 1`): burn rate decreases (too much scarcity), fee floor/ceiling increase (slow spending), target messages decreases.
- **50% damping** prevents over-correction from a single anomalous cycle.

### Initial Parameter Values

| Parameter      | Initial | Min     | Max     |
|----------------|---------|---------|---------|
| `burn_rate`    | 0.65    | 0.20    | 0.80    |
| `fee_floor`    | 10      | 5       | 100     |
| `fee_ceiling`  | 10,000  | 5,000   | 50,000  |
| `target_msgs`  | 10,000  | 1,000   | 100,000,000 |

## Treasury Cap

Treasury balance is capped at 10% of INITIAL_SUPPLY (1,100,000,000 MTK). When fees would cause the treasury to exceed this cap, the excess flows back to the pool.

```
treasury_incoming = non_burn * (10/35) * total_fees_this_epoch
if treasury + treasury_incoming > TREASURY_CAP:
    treasury_excess = (treasury + treasury_incoming) - TREASURY_CAP
    treasury = TREASURY_CAP
    pool += treasury_excess
```

## Reward Formula

### Pool Allocation

```
PoolAllocation = pool * 0.85
```

85% of the pool is distributed as rewards each cycle. 15% is retained as buffer for the next cycle.

### Uptime Measurement

```
uptime_ratio = (blocks_produced + heartbeat_responses) / (slots_assigned + heartbeats_received)
```

Tracked per-epoch, averaged over the cycle.

### Composite Stake Multiplier

```
S_i = 0.5 + 0.3 * UptimeRatio    -- range [0.5, 0.8]
```

- Baseline: 0.5 (all validators receive)
- Uptime factor: 0.3 * UptimeRatio (rewards validators with high availability)

### Reward Calculation

```
U_i = uptime_ratio                                          -- uptime [0,1]
S_i = 0.5 + 0.3 * U_i                                      -- stake multiplier [0.5, 0.8]
P_i = P_flood * P_idle                                      -- punitive [0,1]

RawReward_i = S_i * P_i
Reward_i = (RawReward_i / TotalRawReward) * PoolAllocation
```

### Validator Reward Floor

```
min_reward_per_validator = 5,000 MTK per cycle

pool_allocation = pool * 0.85

if pool_allocation / active_validators < min_reward_per_validator:
    max_validators = pool_allocation / min_reward_per_validator
    -- Excess validators queued by stake (highest = priority)
    -- Queued validators earn standby reward (1,000 MTK)
```

### User Rebate

```
rebate_rate = non_burn * (5/35)   -- adaptive with burn rate

if user.msgs_sent >= 10 AND user.msgs_received >= 10 (this cycle):
    user_rebate = rebate_rate * total_fees_paid_by_user_this_cycle
-- Funded from the rebate allocation of fees
-- Requires bidirectional activity (prevents self-messaging for rebate)
```

## Validator Onboarding Incentive

Validators who onboard new users earn a bonus proportional to the fees those users generate. This creates a federated onboarding model where every validator can operate as a local faucet and sustain revenue from growing the network.

### Mechanism

1. **Referral registration**: when a new user completes the onboarding PoW, they include an optional `referrer_validator` field (the pubkey hash of the validator who provided their initial tokens)
2. **Initial grant**: the referring validator sends tokens from their own wallet (off-protocol pricing — validators set their own rates)
3. **Fee tracking**: the protocol tracks total fees paid by each referred user per cycle, attributed to the referring validator
4. **Onboarding bonus**: at cycle boundary, referring validators receive a bonus from the treasury allocation:

```
referred_fees_i = sum(fees paid by all users referred by validator i, this cycle)
onboarding_bonus_i = 0.10 * referred_fees_i  -- 10% of referred user fees
```

Funded from the treasury allocation. Onboarding bonuses capped at 50% of the treasury allocation per cycle.

### Sybil Resistance

Self-referral is unprofitable because:
- Creating a fake account requires PoW (~10 min CPU)
- Messaging costs fees (minimum `fee_floor` MTK per message, `burn_rate`% burned within cycle)
- Onboarding bonus returns only 10% of the fees spent
- Net loss per fake active account: 90% of fees + PoW cost + initial grant

Example: validator creates 10 fake accounts, sends 10 messages each at minimum fee (10 MTK):
- Cost: 10 * 10 * 10 = 1,000 MTK in fees + 10 * initial_grant
- Burned (within cycle): 650 MTK (at default 65% burn rate)
- Bonus: 0.10 * 1,000 = 100 MTK
- Net loss: >= 900 MTK + 10 * initial_grant + PoW time

### Activity Threshold

Referred users only count toward the bonus if they meet minimum activity in their first cycle:
- At least 5 messages sent to distinct recipients (not the referring validator)
- At least 5 messages received from distinct senders (not the referring validator)
- This prevents circular messaging between validator and referred user

### Referral Expiry

- Referral attribution lasts 3 cycles (33 days) from onboarding
- After 3 cycles, the user's fees no longer generate a bonus for the original validator
- This prevents permanent rent-seeking on early users
- Referral attribution persists across cycle boundaries

### Validator-Operated Faucet

Each validator node can optionally expose a local onboarding endpoint via the JSON-RPC API:
```
faucet.request(pubkey, pow_proof) -> {grant_amount, referral_tx_hash}
```
- Validator sets their own grant amount and any off-protocol payment terms
- The protocol only records the referral_validator field in the onboarding transaction
- New users discover faucet operators via DHT announcements (validators advertise faucet availability in their peer metadata)

### Economic Impact

With the treasury allocation (capped at 1.1B MTK):
- Onboarding bonuses capped at 50% of treasury allocation per cycle
- At 10% bonus rate, this supports substantial referred user fee volume per cycle
- This creates a sustainable revenue stream for operators who actively grow the network

## Wallet Reset

At cycle boundary: all spendable balances → 0. New balance = calculated reward + earned rebate. Unspent tokens are absorbed into the pool via supply restoration. Staked balances persist across cycles.

## Punitive Multipliers (Tiered)

### Penalty Application Order

1. **Detection**: violation detected at cycle boundary via on-chain traffic analysis
2. **Tier assignment**: based on severity (see below)
3. **Immediate penalty**: P_tier applied multiplicatively to current P_carryover
4. **Recovery**: P_carryover converges back toward 1.0 over subsequent cycles
5. **Effective factor**: `P_effective = P_carryover` (P_tier is folded into P_carryover at application time)
6. **Persistence**: P_carryover persists across cycle boundaries

### Tier 1 (Minor: single violation)
- **Trigger**: traffic > 2x median in a cycle
- **Application**: `P_carryover = P_carryover * 0.9` (immediate 10% reduction)
- **Recovery**: each subsequent clean cycle: `P_carryover = 0.3 + 0.7 * P_carryover`
- **Timeline**: from P=0.9, reaches P>0.95 in ~3 cycles (33 days)
- **Example**: P=1.0 → violation → P=0.9 → clean → P=0.93 → clean → P=0.951 → clean → P=0.966

### Tier 2 (Moderate: flood > 5x median OR 3+ Tier 1 violations in 5 cycles)
- **Application**: `P_carryover = P_carryover * 0.5` (immediate 50% reduction)
- **Recovery**: each subsequent clean cycle: `P_carryover = 0.1 + 0.9 * P_carryover`
- **Timeline**: from P=0.5, reaches P>0.95 in ~22 cycles (242 days)
- Flagged for enhanced monitoring

### Tier 3 (Severe: flood > 10x median OR Tier 2 + continued violation)
- **Application**: `P_carryover = 0.0` (permanent). Validator cannot recover.
- **Stake slashed 25%** (transferred to `burned_total` within the current cycle)
- Validator must withdraw remaining stake and re-register with a fresh stake to participate again

### Slashing vs Conservation

Slashed stake is transferred to `burned_total` within the current cycle. At cycle boundary, `burned_total` resets to 0 and slashed tokens are absorbed into the pool via supply restoration. The intra-cycle conservation invariant accounts for slashing:

```
sum(all_balances) + pool + onboarding_reserve + treasury + burned_total == INITIAL_SUPPLY
```

Slashing increases `burned_total`, decreasing the slashed validator's balance, maintaining the invariant within the cycle. At cycle boundary, the slashed tokens become part of the restored pool.

### Detection Mechanisms
- **Flood**: traffic exceeding median-relative thresholds (2x = Tier 1, 5x = Tier 2, 10x = Tier 3)
- **Idle gaming**: >90% uptime but zero send for 3+ days
- **Sybil**: Quadratic bonding violation + statistical clustering + IP diversity violation

## New User Onboarding (Recycling Faucet)

- **Faucet**: `min(10,000, onboarding_reserve / estimated_remaining_capacity)` MTK initial grant
- Rate-limited by CPU-bound PoW puzzle (~10 minutes on commodity hardware)
- Rate limit: 1 faucet claim per pubkey per cycle
- **Vouching**: Existing node transfers up to 10% of balance; voucher takes 10% sympathetic penalty if new node misbehaves
- **Earn by running**: Join mid-cycle, earn uptime-proportional reward for next cycle
- **Inactive account reclamation**: Accounts inactive >5 cycles (55 days) with balance <1,000 MTK → balance returned to onboarding reserve

### PoW Puzzle Specification

```
Argon2id(
    passphrase = pubkey,
    salt       = epoch_nonce,
    t          = 3,            -- 3 iterations
    m          = 256 MB,       -- memory cost
    p          = 1             -- single thread
)
```

Must produce hash with 20 leading zero bits. Approximately 10 minutes on a 4-core commodity CPU. Rate limit: 1 faucet claim per pubkey per cycle.

## Sybil Resistance (Quadratic Bonding)

- **First validator**: 50,000 MTK minimum stake
- **nth validator from same /16 subnet**: 50,000 * n^2 MTK
  - 2nd: 200,000 MTK
  - 3rd: 450,000 MTK
  - 10th: 5,000,000 MTK
- **PoW challenge**: New validator registration requires ~10 minutes CPU-bound PoW
- Statistical clustering detection for coordinated abuse
- IP diversity scoring (max 2 peers per /16 subnet)

## Chain Revisions

Economic parameters (burn rate bounds, fee bounds, treasury cap, reward formula) are updated via chain revision numbers embedded in genesis blocks. There is no on-chain governance mechanism.

- Each genesis block carries a `chain_revision` integer.
- Nodes must support the current revision plus the 3 prior revisions.
- Parameter changes take effect at the cycle boundary following activation of a new revision.
- Operators upgrade node software to adopt new revisions; no voting or multisig required.

## Formal Economic Invariants (DO-178C DAL A)

All of the following must hold and are verified via property-based testing:

1. **Conservation**: `sum(all_balances) + pool + onboarding_reserve + treasury + burned_total == INITIAL_SUPPLY` (11B, holds at all times)
2. **Intra-cycle burn monotonic**: `burned_total` monotonically increasing within each cycle
3. **Cycle boundary reset**: `burned_total = 0` at every cycle boundary
4. **Supply restoration**: `pool(N+1) = INITIAL_SUPPLY - sum(staked_balances) - onboarding_reserve - treasury`
5. **Reward floor**: `reward_per_active_validator >= 5,000 MTK` when pool > 0
6. **Fee bounds**: `fee_floor <= base_fee <= fee_ceiling` at all times
7. **Quadratic bonding**: `stake_required(n) == 50,000 * n^2` for nth identity per subnet
8. **Rebate cap**: `total_rebates <= rebate_rate * total_fees_collected` per cycle
9. **Punitive monotonic decrease**: punitive factors monotonically decrease during recovery (no sudden increases without new violation)
10. **Onboarding bonus cap**: `onboarding_bonus_total <= 0.50 * treasury_allocation_per_cycle`
11. **Adaptive bounds**: `burn_rate in [0.20, 0.80]`, `fee_floor in [5, 100]`, `fee_ceiling in [5000, 50000]`, `target_msgs in [1000, 100000000]`
12. **Minimum cycle duration**: `actual_cycle_slots >= 3,927` (1 epoch at 11s/slot)
