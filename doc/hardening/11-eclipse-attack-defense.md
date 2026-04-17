# Hardening Spec 11: Eclipse Attack Defense

**Status:** Normative specification
**Applies to:** All UmbraVox full nodes and validators
**References:** `doc/04-consensus.md`, `doc/10-security.md` (Eclipse attack row), `doc/proof-03-consensus.md`
**Adversary model:** Up to f' < 0.5 of network nodes (network-layer threshold per `doc/10-security.md`)

---

## 1. Attack Description

An **eclipse attack** isolates a victim node from the honest network by ensuring that every one of the victim's peer connections terminates at an adversary-controlled node. Once eclipsed, the victim is subject to:

| Capability | Impact on UmbraVox |
|---|---|
| Feed false chain data | Victim accepts adversary fork; may finalize invalid blocks locally |
| Censor transactions | Victim's outbound messages and token transfers never reach honest validators |
| Delay blocks | Victim's view of chain tip falls behind; stale stake snapshots used for VRF evaluation |
| Double-spend against victim | Adversary presents a fork where a payment to the victim is reversed |
| Partition consensus view | Victim's heartbeat responses never propagate; uptime ratio degrades, effective stake decreases |

Eclipse attacks are the network-layer prerequisite for many higher-level attacks (selfish mining amplification, transaction censorship, double-spending). This specification defines the structural and protocol-level defenses that make full eclipse prohibitively expensive.

---

## 2. Peer Diversity Requirements

### 2.1 Connection Counts

| Parameter | Value | Rationale |
|---|---|---|
| `MIN_OUTBOUND` | 8 | Minimum outbound connections; node MUST maintain at least this many |
| `MAX_OUTBOUND` | 12 | Soft cap on outbound connections to limit resource usage |
| `MAX_INBOUND` | 117 | Accept inbound up to this limit (total max peers = 129) |
| `MAX_TOTAL_PEERS` | 129 | Hard cap on simultaneous connections |

A node that drops below `MIN_OUTBOUND` MUST immediately attempt to establish new outbound connections from its peer table. If the node cannot reach `MIN_OUTBOUND` within 120 seconds, it MUST log a critical alert (see Section 10).

### 2.2 Subnet and AS Limits

| Constraint | Limit | Scope |
|---|---|---|
| Max peers per /16 IPv4 subnet | 2 | Combined outbound + inbound |
| Max peers per /48 IPv6 prefix | 2 | Combined outbound + inbound |
| Max peers per Autonomous System (AS) | 4 | Combined outbound + inbound |
| Max outbound peers per /16 subnet | 2 | Outbound only (matches hardening/02 MAX_PEERS_PER_SUBNET; 2 allows sufficient connectivity while subnet diversity requirements in Section 2.3 provide eclipse resistance) |
| Max outbound peers per AS | 2 | Outbound only |

AS number is resolved via a local table shipped with the software (updated at each chain revision). The table maps IP prefix ranges to AS numbers. No runtime DNS or WHOIS queries are performed.

### 2.3 Geographic Diversity Heuristic

Nodes SHOULD maintain outbound connections across at least 3 distinct geographic regions, determined by AS-to-region mapping in the local table. This is a SHOULD-level requirement because enforcement would prevent nodes in under-served regions from bootstrapping. The peer selection algorithm applies a preference weight:

```
region_weight(candidate) =
  if region(candidate) not in current_outbound_regions: 1.5
  else: 1.0
```

This weight multiplies the candidate's selection probability during outbound peer rotation (Section 4).

---

## 3. Outbound-Only Trust Model

### 3.1 Peer Table Separation

The node maintains two independent peer tables:

| Table | Source | Trust level | Used for |
|---|---|---|---|
| `tried_table` | Peers the node has successfully connected to outbound | Higher | Outbound connection candidates |
| `new_table` | Peers received via `ADDR` gossip or DNS seeds | Lower | Candidates to promote to `tried_table` after successful outbound connection |

Each table is a bucketed hash table (256 buckets, 64 entries per bucket):

```
tried_table: 256 buckets * 64 entries = 16,384 max entries
new_table:   256 buckets * 64 entries = 16,384 max entries
```

### 3.2 Bucket Assignment

Bucket index is derived deterministically from a per-node secret key to prevent adversary prediction:

```
tried_bucket(peer_addr) = SHA-256(node_secret || peer_addr || "tried")[0..7] mod 256
new_bucket(peer_addr, source_addr) = SHA-256(node_secret || peer_addr || source_addr || "new")[0..7] mod 256
```

The `source_addr` in `new_table` hashing ensures that the same peer advertised by different sources lands in different buckets, limiting a single adversary source from flooding one bucket.

### 3.3 Outbound Trust Principle

- **Outbound connections** are initiated by the node itself, selecting from `tried_table` (preferred) or `new_table` (fallback). The node chose the peer; the adversary cannot force which peer is selected without controlling the table.
- **Inbound connections** are accepted passively. The remote party chose to connect. No trust is extended.
- Chain tip data, block announcements, and transaction relay from inbound-only peers MUST be cross-validated against data from at least 1 outbound peer before acceptance.
- Fork choice evaluation MUST weight outbound-sourced chain data: if all outbound peers agree on a chain tip and inbound peers present a conflicting tip, the outbound-sourced tip is preferred unless the conflicting tip has strictly greater density (per `doc/04-consensus.md` fork choice rule).

---

## 4. Peer Rotation

### 4.1 Rotation Schedule

| Parameter | Value |
|---|---|
| `ROTATION_INTERVAL` | 1 epoch (3,927 slots = 12 hours) |
| `PEERS_ROTATED_PER_INTERVAL` | 1 outbound peer |
| `ROTATION_JITTER` | Uniform random delay in [0, 393] slots (0-72 minutes) |

At each rotation event:

1. Select the longest-tenured non-anchor outbound peer.
2. Disconnect it gracefully (send `BYE` message, wait 5 seconds, close).
3. Select a replacement from `tried_table`, applying subnet/AS/region constraints (Section 2).
4. If no valid candidate in `tried_table`, select from `new_table` and attempt outbound connection.
5. If connection fails, retry up to 3 times with different candidates before logging a warning.

### 4.2 Rotation Jitter

The `ROTATION_JITTER` prevents all nodes from rotating simultaneously (which could cause a network-wide connection churn spike). The jitter is derived deterministically:

```
jitter_slots = SHA-256(node_secret || epoch_number || "rotation_jitter")[0..7] mod 393
```

### 4.3 Eviction of Misbehaving Peers

Peers are evicted immediately (outside the rotation schedule) for:

| Offense | Action |
|---|---|
| Sending invalid block (fails consensus validation) | Disconnect + ban 24 hours |
| Sending block with invalid VRF proof | Disconnect + ban 24 hours |
| Not responding to ping within 60 seconds (3 consecutive) | Disconnect, move to `new_table` |
| Sending >10 `ADDR` messages per minute | Disconnect + ban 1 hour |
| Presenting chain with density < 0.25 * expected density over 100 slots | Disconnect + flag for review |

---

## 5. Anchor Peers

### 5.1 Configuration

Each node maintains a list of **anchor peers**: trusted, long-lived nodes that are always connected. These are stored in the node's persistent configuration.

| Parameter | Value |
|---|---|
| `MIN_ANCHOR_PEERS` | 2 |
| `MAX_ANCHOR_PEERS` | 8 |
| `ANCHOR_RECONNECT_INTERVAL` | 60 seconds (retry if disconnected) |
| `ANCHOR_RECONNECT_MAX_BACKOFF` | 3600 seconds (1 hour) |

Anchor peers count toward `MIN_OUTBOUND` but are exempt from periodic rotation (Section 4). If an anchor peer is unreachable for >24 hours, the node SHOULD log a warning but MUST NOT remove it from the anchor list automatically.

### 5.2 DNS Seed Bootstrapping

On first startup or when `tried_table` has fewer than 16 entries, the node queries DNS seeds for initial peer discovery:

| Requirement | Value |
|---|---|
| Minimum independent DNS seeds queried | 4 |
| DNS seeds operated by distinct organizations | Required (seeds MUST be operated by at least 3 independent entities) |
| DNS response caching | TTL-based, minimum 300 seconds |
| Fallback if DNS fails | Hardcoded IP list (at least 8 addresses, updated per chain revision) |

DNS seed results are placed in `new_table`. The node then attempts outbound connections to promote candidates to `tried_table`.

### 5.3 Anchor Persistence Across Restarts

On clean shutdown, the node writes its current outbound peers (excluding inbound-only) to a file (`anchors.dat`). On restart, these are loaded as temporary anchors and connected to first, providing continuity across restarts and making post-restart eclipse harder.

```
anchors.dat format:
  [4 bytes] magic: 0x554D5658 ("UMVX")
  [4 bytes] version: 1
  [4 bytes] count: N
  N * [18 bytes] peer entries: [16 bytes IPv6-mapped addr][2 bytes port]
  [32 bytes] HMAC-SHA-256(node_secret, all preceding bytes)
```

The HMAC prevents tampering with the anchor file by a local attacker.

---

## 6. Chain Consistency Checks

### 6.1 Expected Block Rate

With active slot coefficient f = 0.20 and slot duration 11 seconds, the expected block rate is:

```
expected_blocks_per_minute = (60 / 11) * 0.20 = 1.09 blocks/minute
expected_blocks_per_hour = 65.5
```

### 6.2 Divergence Detection

The node continuously monitors the chain received from its peers and compares against expected production rate:

| Check | Threshold | Action |
|---|---|---|
| Block rate < 25% of expected over trailing 200 slots | < 10 blocks in 200 slots (expected: 40) | `CHAIN_DIVERGENCE_WARNING` |
| Block rate < 10% of expected over trailing 500 slots | < 10 blocks in 500 slots (expected: 100) | `CHAIN_DIVERGENCE_CRITICAL` |
| Chain tip slot is > 300 slots behind current wall-clock slot | Tip is >55 minutes stale | `CHAIN_STALE_CRITICAL` |
| Received chain forks from local chain at depth > k_val/2 = 11 | Fork point is deep | `DEEP_FORK_WARNING` |

### 6.3 Divergence Response Protocol

On `CHAIN_DIVERGENCE_WARNING`:
1. Query all connected peers for their chain tip.
2. If >50% of outbound peers agree with the received chain, accept it (network may be under genuine low load).
3. If <50% of outbound peers agree, initiate emergency peer discovery (Section 6.4).

On `CHAIN_DIVERGENCE_CRITICAL` or `CHAIN_STALE_CRITICAL`:
1. Immediately attempt to connect to 4 additional outbound peers from `new_table` (temporarily exceeding `MAX_OUTBOUND`).
2. Query anchor peers and DNS seeds for current chain tip.
3. If the newly acquired chain tip differs from the eclipsed view by >k blocks, adopt the longer/denser chain per fork choice rule.
4. Alert the user via local notification (see Section 10).
5. Log all peer addresses that provided the divergent chain for post-incident analysis.

### 6.4 Emergency Peer Discovery

When divergence is detected, the node performs an out-of-band peer acquisition:

1. Re-query all configured DNS seeds.
2. Attempt connections to all entries in `new_table` that are not in the current peer set, up to 20 simultaneous attempts.
3. Accept the first 4 successful connections as temporary outbound peers.
4. These temporary peers are retained for at least 1 epoch before being subject to normal rotation.

---

## 7. Checkpoint System

### 7.1 Embedded Checkpoints

The node software embeds a set of **hardcoded checkpoints**: (block_height, block_hash) pairs that are known-good chain states.

| Parameter | Value |
|---|---|
| Checkpoint interval | Every 100,000 blocks (~23 days at expected rate) |
| Checkpoint format | `(block_height: Word64, block_hash: ByteString[32])` |
| Checkpoint enforcement | A chain that does not include the checkpoint block hash at the specified height is rejected |
| Update mechanism | New checkpoints added with each chain revision |

### 7.2 Checkpoint Validation Rule

```
validate_chain(chain):
  for each (cp_height, cp_hash) in CHECKPOINTS:
    if Len(chain) >= cp_height:
      if hash(chain[cp_height]) != cp_hash:
        REJECT chain -- "checkpoint mismatch at height cp_height"
  ACCEPT chain
```

### 7.3 Long-Range Attack Prevention

Checkpoints prevent an adversary from presenting an alternative chain history that diverges before the most recent checkpoint. Without checkpoints, an adversary who acquires old validator keys (from validators who have since exited) could construct a valid-looking alternative chain from genesis.

**Guarantee:** No chain reorganization can occur deeper than the most recent embedded checkpoint. This complements the k=11/22 (two-tier) probabilistic finality with a deterministic anchor.

### 7.4 Checkpoint Trust Model

Checkpoints are trusted because they are embedded in the software binary, which is itself distributed and verified through standard software distribution channels. This is equivalent to the trust placed in the consensus rules themselves. Checkpoints do NOT introduce a new trust assumption; they formalize an existing one.

---

## 8. Block Delay Detection

### 8.1 Delay Thresholds

| Condition | Threshold | Action |
|---|---|---|
| No new block received | > 55 slots (10 minutes) | `BLOCK_DELAY_WARNING` |
| No new block received | > 109 slots (20 minutes) | `BLOCK_DELAY_CRITICAL` |
| No new block received | > 327 slots (60 minutes) | `BLOCK_DELAY_EMERGENCY` |

Note: With f = 0.20 and 3,927 slots/epoch, the probability of 300 consecutive empty slots under honest conditions is:

```
Pr[55 consecutive empty slots] = (1 - f)^55 = 0.80^55 ~ 1.8 * 10^{-6}
```

A gap of 55 slots without a block is overwhelmingly indicative of eclipse, partition, or catastrophic network failure.

### 8.2 Response Actions

**On `BLOCK_DELAY_WARNING`:**
1. Log warning with timestamp and current peer set.
2. Send `GETBLOCKS` request to all connected peers.
3. If any peer responds with a newer block, adopt and clear the warning.
4. If no peer responds with a newer block within 30 seconds, escalate to proactive peer seeking: attempt 4 new outbound connections.

**On `BLOCK_DELAY_CRITICAL`:**
1. Execute full emergency peer discovery (Section 6.4).
2. Alert user: "No blocks received for 20 minutes. Possible eclipse attack or network partition."
3. If node is a validator, suspend block production until chain tip is refreshed (producing blocks on a stale chain wastes the slot and may cause forks on reconnection).

**On `BLOCK_DELAY_EMERGENCY`:**
1. All actions from `BLOCK_DELAY_CRITICAL`.
2. Re-query DNS seeds and hardcoded IP fallback list.
3. Alert user with elevated severity: "No blocks for 60 minutes. Node may be fully eclipsed. Manual intervention recommended."
4. If validator, begin automatic stake protection: do not sign any blocks until chain state is verified against at least 2 anchor peers.

---

## 9. Sybil Resistance at Network Layer

### 9.1 Proof-of-Work Peer Admission

To limit Sybil attacks on the peer table, new inbound connections must complete a lightweight proof-of-work puzzle before being fully admitted:

```
Puzzle protocol:
  1. Server sends challenge: nonce_s = random 16 bytes
  2. Client must find nonce_c (8 bytes) such that:
       SHA-256(nonce_s || nonce_c || client_ip)[0..3] has leading_zeros >= PUZZLE_DIFFICULTY
  3. PUZZLE_DIFFICULTY = 20 bits (expected ~2^20 = 1,048,576 hash operations)
  4. Time limit: client must solve within 30 seconds
  5. Solution is verified in O(1) by the server
```

| Parameter | Value |
|---|---|
| `PUZZLE_DIFFICULTY` | 20 leading zero bits |
| `PUZZLE_TIMEOUT` | 30 seconds |
| `PUZZLE_NONCE_SIZE` | 8 bytes |
| Expected solve time (modern CPU) | ~0.5-2 seconds |
| Expected solve time (1000 Sybil nodes) | ~500-2000 CPU-seconds total |

The puzzle is required for **inbound connections only**. Outbound connections (initiated by the node) do not require a puzzle because the connecting node already demonstrated intent by selecting the peer.

### 9.2 Rate Limiting

| Limit | Value |
|---|---|
| Max new inbound connections per source IP per hour | 3 |
| Max new inbound connections per /16 subnet per hour | 10 |
| Max total new inbound connections per minute | 20 |
| Backoff on failed puzzle attempts per IP | Exponential: 30s, 60s, 120s, 240s, ban 1 hour |

### 9.3 Connection Prioritization

When `MAX_INBOUND` is reached and a new valid inbound connection arrives, the node evicts the lowest-priority inbound peer. Priority scoring:

```
priority(peer) =
    1000 * is_validator(peer)           -- validators get priority
  +  500 * (blocks_relayed / age_hours) -- useful relay peers score higher
  +  100 * unique_subnet_bonus          -- diversity bonus
  -  200 * violation_count              -- penalty for protocol violations
```

This ensures that an adversary cannot displace useful peers simply by opening many connections.

---

## 10. Monitoring and Alerting

### 10.1 Eclipse Detection Metrics

The node MUST continuously compute and expose the following metrics:

| Metric | Computation | Alert threshold |
|---|---|---|
| `peer_diversity_score` | (unique /16 subnets among outbound) / MIN_OUTBOUND | < 0.75 |
| `as_diversity_score` | (unique AS numbers among outbound) / MIN_OUTBOUND | < 0.50 |
| `chain_tip_freshness` | current_slot - chain_tip_slot | > 300 slots |
| `block_arrival_rate` | blocks received in trailing 200 slots / 200 | < 0.05 (expected: 0.20) |
| `outbound_peer_count` | count of active outbound connections | < MIN_OUTBOUND (8) |
| `peer_churn_rate` | peer disconnections per hour | > 20 |
| `addr_message_rate` | ADDR messages received per minute | > 50 |
| `checkpoint_valid` | most recent checkpoint verified | false |

### 10.2 Composite Eclipse Risk Score

```
eclipse_risk =
    0.30 * (1 - peer_diversity_score)
  + 0.20 * (1 - as_diversity_score)
  + 0.20 * clamp(chain_tip_freshness / 600, 0, 1)
  + 0.15 * clamp(1 - block_arrival_rate / 0.20, 0, 1)
  + 0.10 * clamp(1 - outbound_peer_count / MIN_OUTBOUND, 0, 1)
  + 0.05 * clamp(peer_churn_rate / 30, 0, 1)

Alert levels:
  eclipse_risk < 0.20 : NOMINAL
  eclipse_risk in [0.20, 0.50) : ELEVATED -- log warning every 10 minutes
  eclipse_risk in [0.50, 0.80) : HIGH -- trigger emergency peer discovery, alert user
  eclipse_risk >= 0.80 : CRITICAL -- suspend validator operations, alert user, seek manual intervention
```

### 10.3 Logging Requirements

All eclipse-related events MUST be logged with:
- UTC timestamp (ISO 8601)
- Current `eclipse_risk` score
- Full peer set snapshot (IP, port, AS, connection direction, tenure)
- Chain tip height and hash

Log entries are retained for a minimum of 30 days for post-incident forensic analysis.

---

## 11. Formal Bound: Eclipse Probability

### 11.1 Model

Let:
- **n** = number of honest peers in the network's peer pool
- **m** = number of adversary-controlled peers in the network's peer pool
- **k** = number of outbound connections the victim maintains (`MIN_OUTBOUND` = 8)

The victim selects k outbound peers uniformly at random from a pool of n + m candidates. The victim is **fully eclipsed** if and only if all k selected peers are adversary-controlled.

### 11.2 Eclipse Probability (Without Replacement)

The probability that all k outbound connections land on adversary nodes, sampling without replacement from a pool of n + m:

```
P(eclipse) = C(m, k) / C(n + m, k)

           = m! * (n + m - k)! / ((m - k)! * (n + m)!)

           = product_{i=0}^{k-1} (m - i) / (n + m - i)
```

For large pools where n + m >> k, this approximates to:

```
P(eclipse) ~ (m / (n + m))^k = alpha^k
```

where alpha = m / (n + m) is the adversary's fraction of the peer pool.

### 11.3 Numerical Bounds

| Adversary fraction (alpha) | k = 8 | k = 10 | k = 12 |
|---|---|---|---|
| 0.10 | 10^{-8} | 10^{-10} | 10^{-12} |
| 0.25 | 1.5 * 10^{-5} | 9.5 * 10^{-7} | 5.9 * 10^{-8} |
| 0.33 | 1.5 * 10^{-4} | 1.7 * 10^{-5} | 1.9 * 10^{-6} |
| 0.50 | 3.9 * 10^{-3} | 9.8 * 10^{-4} | 2.4 * 10^{-4} |

With the subnet and AS constraints (Section 2), the effective adversary fraction is reduced because the adversary must control IPs across many distinct subnets and AS numbers. If the adversary controls m nodes but they span only s_adv distinct /16 subnets, and the constraint limits 1 outbound per /16, the effective adversary capacity for outbound slots is min(m, s_adv).

### 11.4 Adjusted Bound with Subnet Constraints

Let s_adv = number of distinct /16 subnets controlled by the adversary, and s_hon = distinct /16 subnets of honest peers. The effective eclipse probability becomes:

```
P(eclipse | subnet constraint) ~ (s_adv / (s_adv + s_hon))^k
```

For an adversary with 500 nodes on 50 subnets, against 2000 honest nodes on 800 subnets:

```
P(eclipse) ~ (50 / 850)^8 ~ (0.059)^8 ~ 1.5 * 10^{-10}
```

### 11.5 Time-to-Eclipse Under Peer Rotation

With peer rotation replacing 1 peer per epoch (Section 4), an adversary who gradually populates the victim's `tried_table` with malicious entries must wait for all k outbound slots to rotate to adversary nodes simultaneously. If each slot rotates independently with period k_rot epochs, the expected time to full eclipse is:

```
E[time to eclipse] >= 1 / P(eclipse) * ROTATION_INTERVAL
                     = (1 / alpha^k) * 12 hours
```

For alpha = 0.33, k = 8: E[time] >= 6,667 * 12 hours ~ 9.1 years.

This bound assumes the adversary has already filled the `tried_table` with a fraction alpha of malicious entries, which itself requires sustained attack over many epochs.

### 11.6 Combined Defense Efficacy

The defenses in this specification are layered. An adversary must simultaneously:

1. Control sufficient nodes across enough /16 subnets and AS numbers to fill all k outbound slots (Section 2, 11.4).
2. Overcome the PoW admission puzzle to maintain Sybil identities (Section 9).
3. Avoid detection by chain consistency checks during the eclipse (Section 6).
4. Avoid detection by block delay monitoring (Section 8).
5. Persist through peer rotation without losing all k slots (Section 4).
6. Compromise or become unreachable from all anchor peers (Section 5).
7. Present a chain consistent with embedded checkpoints (Section 7).

The conjunction of these independent requirements makes sustained eclipse attacks economically and operationally infeasible against a correctly configured UmbraVox node.

---

## Appendix A: Configuration Summary

```
[eclipse_defense]
min_outbound_peers          = 8
max_outbound_peers          = 12
max_inbound_peers           = 117
max_total_peers             = 129
max_peers_per_ipv4_16       = 2
max_peers_per_ipv6_48       = 2
max_peers_per_as            = 4
max_outbound_per_ipv4_16    = 2
max_outbound_per_as         = 2
rotation_interval_slots     = 3927
rotation_peers_count        = 1
rotation_jitter_max_slots   = 393
min_anchor_peers            = 2
max_anchor_peers            = 8
anchor_reconnect_seconds    = 60
anchor_reconnect_max_backoff = 3600
puzzle_difficulty_bits       = 20
puzzle_timeout_seconds       = 30
max_inbound_per_ip_per_hour = 3
max_inbound_per_16_per_hour = 10
max_new_inbound_per_minute  = 20
block_delay_warning_slots   = 55
block_delay_critical_slots  = 109
block_delay_emergency_slots = 327
checkpoint_interval_blocks  = 100000
min_dns_seeds               = 4
emergency_discovery_peers   = 4
```

## Appendix B: References

- Heilman, Kendler, Zohar, Goldberg. "Eclipse Attacks on Bitcoin's Peer-to-Peer Network." USENIX Security 2015.
- Marcus, Heilman, Goldberg. "Low-Resource Eclipse Attacks on Ethereum's Peer-to-Peer Network." Cryptology ePrint 2018/236.
- David, Gazi, Kiayias, Russell. "Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain." Eurocrypt 2018.
- `doc/04-consensus.md` -- UmbraVox consensus parameters (f=0.20, k=11/22 (two-tier), slot=11s, epoch=3927 slots).
- `doc/10-security.md` -- Threat model, adversary classes, eclipse attack mitigation summary.
