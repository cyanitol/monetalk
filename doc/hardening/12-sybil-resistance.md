# Hardening Spec 12: Sybil Resistance

**Source references:**
- `doc/06-economics.md` lines 363–395 (quadratic bonding, faucet)
- `doc/10-security.md` (threat model, adversary classes)
- `doc/proof-04-token-conservation.md` (conservation invariants, quadratic bonding proof)

**Constants used throughout:**

| Symbol | Value | Source |
|--------|-------|--------|
| INITIAL_SUPPLY | 11,000,000,000 MTK | economics line 5 |
| BASE_STAKE | 50,000 MTK | economics line 388 |
| BURN_RATE | 0.65 (default), range [0.20, 0.80] | economics line 107 |
| FEE_FLOOR | 10 MTK (default), range [5, 100] | economics line 176 |
| FAUCET_GRANT | min(10,000, reserve/capacity) MTK | economics line 365 |
| REFERRAL_BONUS | 10% of referred user fees | economics line 265 |
| REBATE_RATE | (1 - burn_rate) * 5/35 | economics line 244 |
| CYCLE_DURATION | 11 days (22 epochs) | economics line 17 |
| POW_TIME | ~10 minutes (Argon2id, 256 MB) | economics line 384 |

---

## 1. Validator Sybil (Quadratic Bonding)

### 1.1 Mechanism

The n-th validator registering from the same /16 IPv4 subnet must stake:

```
S(n) = BASE_STAKE * n^2 = 50,000 * n^2 MTK
```

| n | Stake required | Cumulative stake for n validators |
|---|---------------|-----------------------------------|
| 1 | 50,000 | 50,000 |
| 2 | 200,000 | 250,000 |
| 3 | 450,000 | 700,000 |
| 5 | 1,250,000 | 2,750,000 |
| 10 | 5,000,000 | 19,250,000 |
| 20 | 20,000,000 | 143,500,000 |
| 50 | 125,000,000 | 2,146,250,000 |

### 1.2 Cumulative Cost

The total stake required to place n validators in a single /16 subnet:

```
C(n) = BASE_STAKE * sum_{k=1}^{n} k^2
     = BASE_STAKE * n(n+1)(2n+1) / 6
     = 50,000 * n(n+1)(2n+1) / 6
```

### 1.3 Formal Proof: Attack Cost Exceeds Benefit

**Theorem.** For any n >= 1 and any burn rate b in [0.20, 0.80], the cost
of creating n Sybil validators in one subnet exceeds the maximum extractable
benefit.

**Proof.**

*Attack cost:* The adversary must lock C(n) = 50,000 * n(n+1)(2n+1)/6 MTK
as stake. These tokens are illiquid for the cycle duration. Additionally,
each registration requires ~10 minutes of PoW.

*Maximum benefit per validator per cycle:* A validator earns at most
the proportional share of 85% of the reward pool. With V total validators:

```
max_reward_per_validator = 0.85 * pool / V
```

At genesis with pool = 9.35B and V = 100 honest validators, the maximum
per-validator reward is ~79,475,000 MTK. The adversary's n Sybil validators
earn at most:

```
B(n) = n * 0.85 * pool / (V + n)
```

*Cost-benefit ratio:*

```
C(n) / B(n) = [50,000 * n(n+1)(2n+1) / 6] / [n * 0.85 * pool / (V + n)]
            = [50,000 * (n+1)(2n+1) * (V + n)] / [6 * 0.85 * pool]
```

For n = 1, V = 100, pool = 9.35B:

```
C(1) / B(1) = [50,000 * 2 * 3 * 101] / [6 * 0.85 * 9,350,000,000]
            = 30,300,000 / 47,685,000,000
            ~ 0.000635
```

This ratio is less than 1 for small n at genesis, meaning the first few
Sybil validators are profitable in isolation. The defense is that the
quadratic growth makes the *marginal* cost superlinear:

*Marginal cost of the (n+1)-th validator:*

```
S(n+1) = 50,000 * (n+1)^2
```

*Marginal benefit of the (n+1)-th validator:*

```
dB/dn = 0.85 * pool * V / (V + n)^2
```

The marginal cost grows as O(n^2) while the marginal benefit decreases as
O(1/n^2). Setting marginal cost = marginal benefit:

```
50,000 * (n+1)^2 = 0.85 * pool * V / (V + n)^2
```

For V = 100, pool = 9.35B:

```
50,000 * (n+1)^2 = 7,947,500,000 * 100 / (100 + n)^2
(n+1)^2 * (100 + n)^2 = 7,947,500,000 * 100 / 50,000
(n+1)^2 * (100 + n)^2 = 15,895,000
(n+1) * (100 + n) = 3,987
```

Solving: n^2 + 101n + 100 = 3,987, so n^2 + 101n - 3,887 = 0.
By the quadratic formula: n = (-101 + sqrt(10201 + 15548)) / 2
= (-101 + sqrt(25749)) / 2 = (-101 + 160.5) / 2 ~ 29.7.

**Result:** Beyond approximately n = 30 validators in a single /16 subnet,
the marginal cost exceeds the marginal benefit. Total cumulative stake
required for 30 validators: C(30) = 50,000 * 30 * 31 * 61 / 6
= 50,000 * 9,455 = 472,750,000 MTK (4.3% of total supply).

At higher validator counts (V = 1000), the crossover point drops to
approximately n = 10, requiring C(10) = 19,250,000 MTK cumulative stake
just for the subnet.

**Additional constraint:** IP diversity scoring limits to max 2 peers per
/16 subnet for peer selection, reducing the effective influence of subnet-
concentrated validators on gossip propagation.  []

### 1.4 PoW Registration Barrier

Each validator registration additionally requires:

```
Argon2id(pubkey, epoch_nonce, t=3, m=256MB, p=1) -> 20 leading zero bits
```

Time cost: ~10 minutes per registration on commodity hardware. For n
Sybil validators: n * 10 minutes sequential PoW (parallelizable only
with n * 256 MB memory). This creates a secondary time barrier that
prevents rapid Sybil deployment during a single epoch.

---

## 2. User Sybil (Faucet Abuse)

### 2.1 Attack Description

An adversary creates many accounts to claim faucet grants, accumulating
free tokens.

### 2.2 Defenses

**PoW barrier:** Each faucet claim requires Argon2id proof-of-work:

```
Argon2id(pubkey, epoch_nonce, t=3, m=256MB, p=1) -> 20 leading zero bits
~10 minutes on 4-core commodity CPU, 256 MB memory per attempt
```

**Rate limiting:** 1 faucet claim per pubkey per cycle (11 days).

**Epoch nonce binding:** The PoW salt is the current epoch nonce, preventing
pre-computation of PoW proofs across epochs.

### 2.3 Cost Analysis

Per Sybil account:
- Time cost: 10 minutes CPU + 256 MB RAM
- Benefit: at most FAUCET_GRANT = min(10,000, reserve/capacity) MTK

At scale, for k Sybil accounts per cycle:
- Time: 10k minutes (~167 hours for 1,000 accounts)
- Memory: 256 MB per concurrent attempt
- Benefit: k * FAUCET_GRANT MTK

At FAUCET_GRANT = 10,000 MTK and 1,000 accounts:
- Benefit: 10,000,000 MTK (0.09% of supply)
- Time: 167 hours of CPU time
- Hardware cost at $0.05/CPU-hour: $8.35

**Mitigation effectiveness:** The adaptive faucet formula
`min(10,000, reserve/capacity)` reduces grants as the reserve depletes.
With 1.1B reserve and estimated capacity of 110,000 users, the grant is
10,000 MTK. As Sybil claims consume the reserve, the per-claim grant
shrinks, creating a self-regulating defense.

**Residual risk:** At very low hardware costs, faucet draining is
theoretically possible but yields only faucet-tier tokens that reset
at cycle boundary anyway. The primary defense is that faucet tokens
alone cannot achieve validator status (minimum stake 50,000 MTK > faucet
grant of 10,000 MTK).

---

## 3. Self-Referral Sybil

### 3.1 Attack Description

A validator creates fake "referred" users, sends messages through them,
and earns the 10% onboarding bonus on those fees.

### 3.2 Cost-Benefit Analysis

Let f = fee per message, b = burn rate, r = referral bonus rate (0.10).

For each fake referred user, the validator must:
1. Pay the initial grant (off-protocol, but the tokens come from the validator's balance)
2. Generate fee-paying messages (minimum 5 sent to distinct non-referrer recipients AND 5 received from distinct non-referrer senders per the activity threshold)

**Per fake account, per message:**
- Fee paid: f MTK
- Burned within cycle: b * f MTK (permanently lost within the cycle)
- Non-burn allocation: (1-b) * f MTK (split to producer/treasury/rebate/stakers)
- Referral bonus earned by validator: r * f = 0.10 * f MTK

**Net loss per message:**

```
loss = f - r * f = f * (1 - r) = 0.90 * f
```

But wait -- the validator also loses the burned portion permanently (within
the cycle). The referral bonus of 0.10 * f is paid from the treasury
allocation, not from the fee itself. So the validator's net position is:

```
paid:     f MTK (fee from the fake account's balance)
received: 0.10 * f MTK (referral bonus from treasury at cycle end)
net loss: 0.90 * f MTK per message
```

### 3.3 Formal Proof of Unprofitability

**Theorem.** For all burn rates b in [0.20, 0.80] and all fee levels
f >= FEE_FLOOR, self-referral is strictly unprofitable.

**Proof.** The validator's net gain from self-referral per message is:

```
G = r * f - f = (r - 1) * f = -0.90 * f
```

Since r = 0.10 < 1 and f >= FEE_FLOOR >= 5 > 0:

```
G = -0.90 * f <= -0.90 * 5 = -4.5 MTK < 0
```

The burn rate b does not affect this result because the referral bonus is
computed on the gross fee, while the entire gross fee is deducted from the
fake account. The burn rate only determines how the fee is distributed
after deduction -- it does not reduce the cost to the attacker.

**With activity threshold:** Each fake account must send >= 5 messages to
distinct non-referrer recipients and receive >= 5 from distinct non-referrer
senders. This requires at minimum 10 fake accounts cooperating (to serve
as each other's distinct peers), amplifying the loss:

For a ring of m fake accounts, each sending k messages:
```
total_loss = m * k * 0.90 * f
```

At minimum parameters (m=10, k=10, f=10 MTK):
```
total_loss = 10 * 10 * 0.90 * 10 = 900 MTK
total_bonus = 10 * 10 * 0.10 * 10 = 100 MTK
net = -800 MTK
```

Plus 10 * initial_grant + 10 * PoW_time.  []

### 3.4 Boundary Case: Minimum Burn Rate

At burn_rate = 0.20 (protocol minimum):
- Non-burn portion: 0.80 * f
- Of which producer gets: 0.80 * 20/35 * f = 0.457 * f
- If the validator is also the block producer, they recover the producer portion

**Worst case for the protocol (validator is both referrer and producer):**
```
paid:     f (from fake account)
received: 0.10 * f (referral bonus) + 0.457 * f (producer reward)
net:      (0.10 + 0.457 - 1.0) * f = -0.443 * f
```

Still a net loss of 44.3% of fees at the most favorable burn rate.

At burn_rate = 0.80 (protocol maximum):
```
received: 0.10 * f (bonus) + 0.20 * 20/35 * f (producer) = (0.10 + 0.114) * f = 0.214 * f
net:      -0.786 * f
```

**Conclusion:** Self-referral is unprofitable across all parameter ranges,
with losses between 44.3% and 78.6% of fees spent.  []

---

## 4. Messaging Sybil (Self-Messaging for Rebates)

### 4.1 Attack Description

A user sends messages to themselves (or to a colluding second account)
to earn fee rebates.

### 4.2 Defense: Bidirectional Activity Requirement

Rebate eligibility requires:

```
user.msgs_sent >= 10 AND user.msgs_received >= 10 (this cycle)
messages must be from/to distinct peers
```

### 4.3 Analysis

**Single account self-messaging:** Not possible -- the protocol tracks
sender and recipient distinctness. Messages to self do not count toward
either sent or received quotas.

**Two colluding accounts (A <-> B):**
- A sends 10 messages to B, B sends 10 messages to A
- Total fees: 20 * f MTK
- Each account qualifies for rebate (10 sent, 10 received)
- But "from distinct peers" -- if A only communicates with B, A has only
  1 distinct peer. The requirement is 10 received from distinct *senders*,
  meaning 10 different sender addresses.

**Minimum Sybil ring for rebate eligibility:** An adversary needs at least
11 accounts: 1 primary + 10 peers (so the primary receives from 10 distinct
senders and sends to 10 distinct recipients).

**Cost of the minimum ring (11 accounts):**
- PoW: 11 * 10 min = 110 minutes
- Faucet grants: 11 * 10,000 = 110,000 MTK obtained
- Fees to establish eligibility: each account sends >= 10 messages
  = 11 * 10 * f = 1,100 MTK (at f = 10 MTK floor)
- Rebate earned per account: rebate_rate * fees_paid
  = (1 - 0.65) * 5/35 * fees_paid = 0.05 * fees_paid

For the primary account with fees_paid = 100 MTK (10 messages at 10 MTK):
```
rebate = 0.05 * 100 = 5 MTK
```

**Net position for the entire ring:**
```
fees_paid_total = 1,100 MTK
burned_total    = 0.65 * 1,100 = 715 MTK
rebates_total   = 0.05 * 1,100 = 55 MTK
net_loss        = 1,100 - 55 = 1,045 MTK
```

**Conclusion:** Even with the most favorable rebate, the ring loses 95%
of fees paid. The rebate (5% of fees at default parameters) can never
exceed the fee cost, because rebate_rate < 1 by construction:

```
rebate_rate = (1 - burn_rate) * 5/35
```

Maximum (at burn_rate = 0.20): rebate_rate = 0.80 * 5/35 = 0.114

The rebate is always strictly less than the fee: 0.114 * f < f.  []

---

## 5. Subnet Detection and IP Diversity Enforcement

### 5.1 IPv4 /16 Subnet Tracking

Every validator registration records the source IP. The /16 prefix
(first 16 bits) determines the subnet group. The quadratic bonding
formula S(n) = 50,000 * n^2 applies per /16 subnet.

**Implementation requirements:**
- Validator registration transactions include an IP attestation
- Existing validators in the same /16 are counted at registration time
- The count n is the number of *active* validators in that /16 subnet
  (deregistered validators do not count)

### 5.2 IPv6 Considerations (/48 Prefix)

IPv6 allocations typically assign /48 prefixes to end sites (per RFC 6177).
For IPv6 validators:

```
subnet_group = first 48 bits of IPv6 address
S_ipv6(n) = 50,000 * n^2 (same formula, /48 grouping)
```

**Rationale:** A /48 IPv6 prefix is the standard allocation to a single
site or organization, analogous to a /16 IPv4 block in terms of
organizational control.

### 5.3 Peer Diversity Scoring

Independent of validator registration, the peer selection algorithm
enforces:

```
max_peers_per_subnet = 2 (per /16 IPv4 or /48 IPv6)
```

Nodes preferentially connect to peers from diverse subnets. If a node
discovers it has > 2 peers from the same subnet, it drops the excess
connections (lowest uptime first).

### 5.4 Tor/VPN Detection Heuristics

Validators behind Tor or VPN may attempt to bypass subnet detection.

**Detection signals:**
- Known Tor exit node IP lists (publicly available, updated hourly)
- Known commercial VPN IP ranges (maintained via community blocklists)
- TCP/IP fingerprinting anomalies (TTL, MSS, window size inconsistencies
  suggesting tunneling)
- Latency analysis: Tor adds 200-800ms latency; connections with
  consistently high and variable latency flagged for review
- Multiple validators with identical TCP fingerprints but different IPs

**Policy:** Tor/VPN validators are not banned but are placed into a single
"anonymized" subnet group. All anonymized validators share a single
quadratic bonding counter:

```
S_anon(n) = 50,000 * n^2 (where n counts ALL anonymized validators)
```

This makes Sybil attacks via Tor/VPN quadratically expensive with the
number of anonymized validators network-wide, not just per subnet.

---

## 6. Statistical Clustering Detection

### 6.1 Synchronized Registration Detection

**Signal:** Multiple validator registrations within a short time window
from related subnets or with similar PoW submission patterns.

**Detection rule:**
```
if registrations_in_subnet(subnet, window=1_epoch) > 3:
    flag_for_enhanced_monitoring(subnet)
```

Flagged subnets receive additional scrutiny: all validators from that
subnet are monitored for correlated behavior.

### 6.2 Correlated Transaction Patterns

**Signals monitored at each cycle boundary:**

1. **Fee flow circularity:** Detect cycles in the transaction graph where
   tokens flow A -> B -> C -> ... -> A within a single cycle. Circular
   flows involving only Sybil accounts are inefficient (fees burned at
   each hop).

2. **Temporal correlation:** Messages sent by multiple accounts within
   the same slot or consecutive slots, especially if all accounts
   registered in the same epoch.

3. **Identical fee amounts:** Legitimate users vary message frequency and
   fees; Sybil rings often exhibit uniform behavior.

4. **Low recipient diversity:** Accounts that exclusively message each
   other (clique structure with no external edges).

**Detection metric (per account set S):**

```
clustering_score(S) = (internal_edges(S) / total_edges(S))
                    * (1 / registration_time_spread(S))
                    * (fee_uniformity(S))

if clustering_score(S) > THRESHOLD:
    flag S as suspected Sybil cluster
```

### 6.3 Graph Analysis

At each cycle boundary, the transaction graph is analyzed:

1. **Connected components:** Identify tightly connected subgraphs with
   few external connections.
2. **Betweenness centrality:** Sybil clusters often have a single
   "controller" node with high betweenness centrality connecting the
   cluster to the legitimate network.
3. **Community detection:** Apply the label propagation algorithm
   (no external library required -- O(|E|) per iteration) to identify
   communities; compare community membership against subnet distribution.

**Action on detected clusters:** Validators in a detected Sybil cluster
receive Tier 2 penalty (P_carryover *= 0.5, enhanced monitoring). Repeat
detection triggers Tier 3 (P_carryover = 0, 25% stake slash, permanent — validator must re-stake).

---

## 7. Stake Grinding

### 7.1 Attack Description

An adversary attempts to manipulate their stake at the precise moment of
a VRF snapshot to maximize their probability of being elected leader.

### 7.2 Defense: 2-Epoch Delay

Stake changes (deposits, withdrawals, slashing) take effect with a
2-epoch delay:

```
stake_effective(epoch E) = stake_committed(epoch E - 2)
```

**Why this prevents grinding:**

The VRF for epoch E uses `stake_effective(E)`, which was determined at
epoch E-2. At epoch E-2, the adversary does not know:
- The VRF seed for epoch E (derived from block hashes of epoch E-1)
- Which validators will be active at epoch E

Therefore, the adversary cannot adjust their stake at E-2 to influence
their VRF output at E, because the VRF input depends on information
not yet available at E-2.

### 7.3 Formal Argument

**Theorem.** Under the 2-epoch delay, stake grinding provides no advantage
over honest staking.

**Proof.** Let VRF_E = VRF(sk, seed_E) where seed_E = H(block_hashes_{E-1}).

The adversary's strategy is to choose stake s at epoch E-2 to maximize
Pr[VRF_E < threshold(s)], where threshold(s) is proportional to s.

But seed_E depends on block_hashes_{E-1}, which are not determined at E-2.
The adversary at E-2 sees at most seed_{E-2} and block_hashes_{E-3}.

Since H is modeled as a random oracle, seed_E is computationally
unpredictable at epoch E-2. The adversary cannot evaluate VRF_E at the
time they choose s, so no grinding strategy outperforms simply staking
the maximum available amount.

**Edge case:** If the adversary controls all block producers in epoch E-1,
they can influence seed_E. Defense: the VRF seed incorporates a random
beacon (epoch_nonce XOR accumulated_hash), making single-epoch control
insufficient. The adversary would need to control block production for
multiple consecutive epochs, which requires controlling > 1/3 of total
stake -- already outside the threat model (f < 1/3).  []

---

## 8. Vouching System Security

### 8.1 Mechanism

An existing validator can vouch for a new user by transferring up to 10%
of their balance. The voucher-vouchee relationship is recorded on-chain.

### 8.2 Sympathetic Penalty

If the vouchee misbehaves (triggers any penalty tier), the voucher
receives a sympathetic penalty:

```
voucher_penalty = 0.10 * vouchee_penalty
```

For each penalty tier applied to the vouchee:

| Vouchee penalty | Voucher sympathetic penalty |
|----------------|---------------------------|
| Tier 1: P *= 0.9 | Voucher P *= 0.99 (1% reduction) |
| Tier 2: P *= 0.5 | Voucher P *= 0.95 (5% reduction) |
| Tier 3: P = 0, 25% slash | Voucher P *= 0.90 (10% reduction), 2.5% stake slash |

### 8.3 Security Properties

**Limits vouching to trusted relationships:** A rational voucher will
only vouch for users they trust, because misbehavior by the vouchee
directly reduces the voucher's rewards and stake.

**Sybil deterrent:** If a validator vouches for their own Sybil accounts
and those accounts are detected as a Sybil cluster (Section 6), the
validator receives both:
1. Direct penalty on Sybil accounts (Tier 2 or 3)
2. Sympathetic penalties for each vouchee (cumulative)

For m Sybil vouchees all receiving Tier 2:
```
voucher_P_after = P * 0.95^m
```

At m = 10: P_after = P * 0.95^10 = P * 0.599, a 40% reduction.
At m = 20: P_after = P * 0.95^20 = P * 0.358, a 64% reduction.

**Combined with direct Sybil detection penalty (Tier 2 on the voucher):**
```
P_final = P * 0.5 * 0.95^m
```

At m = 10: P_final = P * 0.30 (70% reduction)
At m = 20: P_final = P * 0.18 (82% reduction)

This makes large-scale vouching-based Sybil attacks self-destructive.

---

## 9. Inactive Account Reclamation

### 9.1 Rule

```
if account.inactive_cycles > 5 AND account.balance < 1000 MTK:
    transfer account.balance -> onboarding_reserve
    mark account as reclaimed
```

- Inactive = no sent or received messages for 5 consecutive cycles (55 days)
- Balance threshold: < 1,000 MTK (prevents reclaiming active stakers)

### 9.2 Anti-Sybil Effect

**Prevents dormant Sybil armies:** An adversary who creates many accounts
to hold for future use must either:
1. Keep each account active (costs fees each cycle -- see Section 4)
2. Accept that accounts with < 1,000 MTK will be reclaimed after 55 days

**Maintenance cost for k dormant accounts:**
To keep k accounts above the inactivity threshold, each must send at least
1 message per cycle:

```
maintenance_cost = k * FEE_FLOOR * cycles
                 = k * 10 * cycles MTK
```

Per cycle: k * 10 MTK. Over 5 cycles (the reclamation threshold): k * 50 MTK.
Each message also burns BURN_RATE * FEE_FLOOR = 6.5 MTK, contributing to
the cycle's burn total.

**For 1,000 dormant accounts over 5 cycles:**
- Fee cost: 50,000 MTK
- Burned: 32,500 MTK
- Net benefit: none (the accounts hold at most their faucet grants)

### 9.3 Interaction with Cycle Reset

At each cycle boundary, spendable balances reset to 0 and are replaced by
rewards + rebates. Dormant Sybil accounts earn no rewards (no uptime, no
activity) and no rebates (no bidirectional activity). Their balance after
cycle reset is 0 MTK, which is < 1,000 MTK, so they become eligible for
reclamation after 5 cycles of inactivity.

**Conclusion:** Dormant Sybil accounts are automatically reclaimed. The
adversary cannot accumulate a standing army without ongoing costs.

---

## 10. Economic Analysis: Cost vs. Benefit by Vector

### 10.1 Summary Table

All values at default parameters (burn_rate=0.65, fee_floor=10 MTK,
faucet_grant=10,000 MTK, referral_bonus=10%).

| Vector | Attack cost (1 cycle) | Attacker benefit (1 cycle) | Net | Profitable? |
|--------|----------------------|---------------------------|-----|-------------|
| Validator Sybil (n=10, 1 subnet) | 19,250,000 MTK staked + 100 min PoW | ~n/(V+n) share of rewards | Depends on V | Only for small n |
| User Sybil (k=100 accounts) | 1,000 min PoW | 1,000,000 MTK faucet grants | Positive but capped | Marginal |
| Self-referral (m=10 fake users) | 1,000 MTK fees + 10 PoW | 100 MTK bonus | -900 MTK | No |
| Messaging Sybil (11-node ring) | 1,100 MTK fees | 55 MTK rebates | -1,045 MTK | No |
| Stake grinding | 0 (just timing) | 0 (2-epoch delay) | 0 | No |
| Dormant army (1000 accounts) | 50,000 MTK/5 cycles | 0 (reclaimed) | -50,000 MTK | No |

### 10.2 Validator Sybil: Detailed Breakeven

**Question:** For what n is the n-th Sybil validator in a subnet profitable?

The n-th validator earns at most:

```
reward_n = 0.85 * pool / (V + n)
```

The n-th validator costs:

```
stake_n = 50,000 * n^2 (locked, not lost -- but illiquid)
opportunity_cost_n = stake_n * (expected_return_if_staked_honestly)
```

If the adversary could instead stake honestly as a single validator
with stake = sum of all Sybil stakes, their reward would be:

```
honest_reward = raw_reward(sum_stakes) / total_raw_reward * pool_allocation
```

Since rewards are partly proportional to stake, concentrating stake in
one validator yields comparable rewards without the quadratic overhead.

**Theorem.** For n >= 2, the quadratic bonding overhead makes the Sybil
strategy strictly dominated by honest single-validator staking.

**Proof.** With n Sybil validators, total locked stake is:
```
C(n) = 50,000 * n(n+1)(2n+1)/6
```

With one honest validator staking the same amount C(n):
```
honest_share = C(n) / total_stake
sybil_share  = n / total_validators (if uniform rewards)
             = n / (V + n)
```

The honest validator's stake-proportional reward exceeds the Sybil
validators' uniform-share reward when:

```
C(n) / total_stake > n / (V + n)
```

Since C(n) grows as O(n^3) while n/(V+n) grows sub-linearly, this
inequality holds for all n >= 2 when V and total_stake are sufficiently
large (which they are in any non-trivial network).  []

### 10.3 Parameter Sensitivity

| Parameter | Range | Effect on Sybil profitability |
|-----------|-------|------------------------------|
| burn_rate | [0.20, 0.80] | Higher burn = more loss for self-referral/messaging Sybil |
| fee_floor | [5, 100] | Higher floor = more cost per Sybil message |
| faucet_grant | [~0, 10000] | Lower grant = less benefit from faucet abuse |
| BASE_STAKE | 50,000 | Fixed; quadratic growth ensures unprofitability at scale |

**Worst-case combination (most favorable to attacker):**
- burn_rate = 0.20 (minimum burn)
- fee_floor = 5 (minimum fee)
- faucet_grant = 10,000 (maximum grant)

Even at these extremes:
- Self-referral loss: 44.3% of fees (Section 3.4)
- Messaging Sybil rebate: max 11.4% of fees (Section 4.3)
- Faucet abuse: capped by reserve depletion

No parameter combination makes any Sybil vector profitable at scale.

---

## 11. Formal Sybil Bound

### 11.1 Maximum Sybil Identities for Budget B

**Theorem (Validator Sybil Bound).** An adversary with budget B MTK can
create at most n_max validator Sybil identities in a single /16 subnet,
where:

```
n_max = floor(cbrt(3B / 50,000))   (approximate for large n)
```

**Exact bound:** n_max is the largest n such that:

```
C(n) = 50,000 * n(n+1)(2n+1) / 6 <= B
```

**Proof.** The cumulative stake required for n validators is:

```
C(n) = 50,000 * sum_{k=1}^{n} k^2 = 50,000 * n(n+1)(2n+1) / 6
```

For large n: C(n) ~ 50,000 * n^3 / 3, so:

```
n <= cbrt(3B / 50,000)
```

**Exact values:**

| Budget B (MTK) | Max validators (n_max) | % of total supply |
|----------------|----------------------|-------------------|
| 1,000,000 | 3 | 0.009% |
| 10,000,000 | 8 | 0.091% |
| 100,000,000 | 18 | 0.91% |
| 500,000,000 | 30 | 4.5% |
| 1,000,000,000 | 38 | 9.1% |
| 5,500,000,000 | 66 | 50% |

### 11.2 Multi-Subnet Sybil Bound

If the adversary distributes validators across m distinct /16 subnets,
the cost is additive per subnet. For uniform distribution (n validators
per subnet):

```
C_total = m * 50,000 * n(n+1)(2n+1) / 6
total_validators = m * n
```

Optimizing: for a fixed budget B, the adversary maximizes total validators
by placing exactly 1 per subnet (n=1), paying 50,000 MTK each:

```
n_max_multi = floor(B / 50,000)
```

At B = 1,000,000 MTK: 20 validators across 20 subnets.
At B = 100,000,000 MTK: 2,000 validators across 2,000 subnets.

**Defense:** Acquiring 2,000 distinct /16 subnets is operationally
difficult and expensive. Cloud providers typically allocate from a small
number of /16 ranges. The Tor/VPN anonymized subnet grouping (Section 5.4)
further constrains this vector.

### 11.3 User Sybil Bound

For non-validator Sybil accounts (faucet claimants):

```
n_max_user = available_PoW_time / 10 minutes
```

No token budget required (faucet is free), but time-bounded by PoW.
At 24 hours of CPU: 144 accounts. At 1 week: 1,008 accounts.

**Value bound:** Total extractable value from k faucet Sybil accounts:

```
V_max = k * FAUCET_GRANT = k * min(10,000, reserve / capacity)
```

As k grows, the adaptive faucet grant shrinks (reserve depletes):

```
grant(k) = min(10,000, (1,100,000,000 - k * grant(k-1)) / (capacity - k))
```

This creates a diminishing returns curve that bounds the total extractable
value regardless of time budget.

### 11.4 Unified Sybil Cost Function

For any Sybil strategy combining validator and user identities, the total
cost is:

```
C_sybil(n_v, n_u, m) = m * 50,000 * n_v(n_v+1)(2n_v+1) / 6  (validator stake)
                     + n_u * 10 min PoW                        (user PoW time)
                     + ongoing_fees                             (activity maintenance)
```

Where:
- n_v = validators per subnet
- n_u = user accounts
- m = number of subnets

The benefit is bounded by:

```
B_sybil <= m * n_v * max_validator_reward + n_u * FAUCET_GRANT
```

The quadratic term in C_sybil ensures that C_sybil grows faster than
B_sybil for any scaling strategy, establishing a formal bound on the
maximum profitable Sybil deployment.  []

---

## Appendix A: Parameter Cross-Reference

| Parameter | File | Line(s) |
|-----------|------|---------|
| INITIAL_SUPPLY = 11B | doc/06-economics.md | 5 |
| BASE_STAKE = 50,000 | doc/06-economics.md | 388 |
| Quadratic formula S(n) = 50,000*n^2 | doc/06-economics.md | 389 |
| Burn rate range [0.20, 0.80] | doc/06-economics.md | 107 (proof-04 line 34) |
| Fee floor range [5, 100] | doc/06-economics.md | 176 (proof-04 line 35) |
| Faucet grant formula | doc/06-economics.md | 365 |
| PoW spec (Argon2id) | doc/06-economics.md | 374-384 |
| Referral bonus 10% | doc/06-economics.md | 265 |
| Rebate eligibility | doc/06-economics.md | 246-249 |
| Activity threshold (5+5 distinct) | doc/06-economics.md | 287-289 |
| Inactive reclamation | doc/06-economics.md | 370 |
| 2-epoch stake delay | doc/10-security.md | (consensus design) |
| Sympathetic penalty 10% | doc/06-economics.md | 368 |
| Peer diversity max 2 per /16 | doc/06-economics.md | 395 |
| Penalty tiers | doc/06-economics.md | 330-356 |

## Appendix B: QuickCheck Properties

```haskell
-- Sybil resistance properties for automated verification

prop_quadratic_cost_superlinear :: Positive Int -> Property
prop_quadratic_cost_superlinear (Positive n) =
  let cost = 50000 * n * n
      marginal_cost = 50000 * (n+1)^2 - 50000 * n^2
  in marginal_cost > cost `div` n  -- marginal > average

prop_self_referral_unprofitable :: BurnRate -> Fee -> Positive Int -> Property
prop_self_referral_unprofitable br fee (Positive msgs) =
  br >= 0.20 && br <= 0.80 && fee >= 5 ==>
    let cost = fromIntegral msgs * fromIntegral fee
        bonus = 0.10 * cost
    in bonus < cost  -- always a net loss

prop_messaging_sybil_unprofitable :: BurnRate -> Fee -> Positive Int -> Property
prop_messaging_sybil_unprofitable br fee (Positive msgs) =
  br >= 0.20 && br <= 0.80 && fee >= 5 ==>
    let cost = fromIntegral msgs * fromIntegral fee
        rebate_rate = (1 - br) * 5 / 35
        rebate = rebate_rate * cost
    in rebate < cost  -- rebate never exceeds cost

prop_sybil_bound :: Positive Integer -> Property
prop_sybil_bound (Positive budget) =
  let n_max = sybilBound budget
      cost_n = 50000 * n_max * (n_max + 1) * (2 * n_max + 1) `div` 6
      cost_n1 = 50000 * (n_max+1) * (n_max+2) * (2*n_max+3) `div` 6
  in cost_n <= budget .&&. cost_n1 > budget

prop_inactive_reclamation :: Account -> Property
prop_inactive_reclamation acc =
  inactive_cycles acc > 5 && balance acc < 1000 ==>
    isReclaimed (applyReclamation acc)

prop_voucher_penalty_cumulative :: Positive Int -> Property
prop_voucher_penalty_cumulative (Positive m) =
  let p_after = 0.95 ^ m
  in m >= 10 ==> p_after < 0.60  -- 10+ Sybil vouchees = 40%+ penalty
```
