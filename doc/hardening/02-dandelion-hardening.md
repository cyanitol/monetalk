# Dandelion++ Anonymity Layer Hardening Specification

**Status:** Normative
**Applies to:** All UmbraVox full nodes and validators
**References:** Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees", ACM SIGMETRICS 2018; `doc/10-security.md`; `doc/proof-07-cryptanalysis-resistance.md` Section 6.4
**Security target:** Pr[correct attribution] no better than adversary's network fraction p for p < 0.50

---

## 1. Stem Path Construction

### 1.1 Epoch-Based Stem Graph

Each node constructs a local stem graph at the start of every Dandelion++ epoch. The stem graph determines which peer a node forwards stem-phase transactions to.

```
DANDELION_EPOCH_DURATION = 600 seconds (10 minutes)
STEM_PEERS_PER_NODE     = 2           -- outbound stem relay targets
MIN_OUTBOUND_PEERS      = 8           -- minimum connected outbound peers
```

**Epoch boundary computation:**

```
epoch_id = floor(unix_timestamp_seconds / DANDELION_EPOCH_DURATION)
```

All nodes derive their epoch boundary independently from their local clock. Clock skew up to the consensus tolerance (+-1 second, `doc/04-consensus.md` lines 167-181) produces negligible epoch boundary disagreement (at most 1 second out of 600).

### 1.2 Stem Peer Selection

At each epoch boundary, every node selects exactly `STEM_PEERS_PER_NODE = 2` outbound stem peers from its current outbound peer set:

```
stem_peer_selection(node_secret_key, epoch_id, outbound_peers):
    -- Deterministic but unpredictable selection
    seed = HMAC-SHA-256(node_secret_key, "dandelion_stem_epoch" || encode_u64(epoch_id))

    -- Shuffle outbound peers using Fisher-Yates with seed-derived CSPRNG
    shuffled = fisher_yates_shuffle(outbound_peers, ChaCha20_CSPRNG(seed))

    -- Select first STEM_PEERS_PER_NODE peers
    primary_stem   = shuffled[0]
    secondary_stem = shuffled[1]

    return (primary_stem, secondary_stem)
```

**Requirements:**

- The selection MUST be deterministic given the same inputs (reproducible for debugging).
- The selection MUST NOT be predictable by any peer (keyed by node's secret key).
- Both stem peers MUST be distinct outbound connections (never the same peer).
- If fewer than 2 outbound peers are available, the node MUST NOT enter stem mode and MUST broadcast all transactions directly in fluff mode (Section 2.4).

### 1.3 Path Length Distribution

Each node that originates a transaction draws a stem hop count from a geometric distribution:

```
STEM_CONTINUATION_PROBABILITY = 0.90  -- q parameter
```

At each stem hop, the forwarding node transitions to fluff with probability `1 - q = 0.10`. Equivalently, the total stem length follows:

```
Pr[stem_length = h] = (1 - q) * q^(h-1)    for h >= 1
E[stem_length]      = 1 / (1 - q) = 10 hops
Var[stem_length]    = q / (1 - q)^2 = 90
Std[stem_length]    = sqrt(90) ~ 9.49 hops
```

The originating node always performs at least 1 stem hop (it never fluffs its own transaction immediately). The fluff/continue decision at each hop is made independently by the forwarding node using local randomness:

```
stem_or_fluff(node_secret_key, tx_hash, hop_number):
    r = HMAC-SHA-256(node_secret_key, "dandelion_fluff_coin" || tx_hash || encode_u64(hop_number))
    coin = r[0..7] as uint64
    if coin < floor((1 - STEM_CONTINUATION_PROBABILITY) * 2^64):
        return FLUFF
    else:
        return STEM
```

This deterministic coin flip ensures that if a node receives the same transaction again (e.g., via a redundant stem path), it makes the same decision, preventing inconsistent behavior.

### 1.4 Stem Peer Offline Fallback

If the selected primary stem peer is unreachable (connection closed, timeout, or not responding):

```
stem_fallback(primary, secondary, tx):
    if primary.is_connected():
        send_stem(primary, tx)
    else if secondary.is_connected():
        send_stem(secondary, tx)
    else:
        -- Both stem peers offline: immediate fluff broadcast
        broadcast_fluff(tx)
        log_event(DANDELION_STEM_FALLBACK, tx_hash_prefix_8bytes)
```

A node MUST NOT retry stem forwarding to a disconnected peer. The fallback to fluff is immediate. The rationale is that retrying with delay would create observable timing anomalies.

### 1.5 Epoch Rotation

At each epoch boundary:

1. Select new stem peers (Section 1.2).
2. Any transaction still in stem phase (received but not yet fluffed) continues with the **new** stem peers.
3. No state about the previous epoch's stem graph is retained beyond the epoch boundary.

---

## 2. Fluff Transition

### 2.1 Transition Mechanics

When a stem-phase transaction transitions to fluff, the transitioning node acts as the apparent originator for all gossip-layer observers. It broadcasts the transaction to ALL connected peers using standard gossip protocol (inventory announcement followed by data transmission on request).

### 2.2 Probability Distribution

Each stem hop independently decides whether to transition:

| Hop | Pr[fluff at this hop] | Pr[still in stem after this hop] |
|-----|----------------------|----------------------------------|
| 1   | 0.10                 | 0.90                             |
| 2   | 0.10                 | 0.81                             |
| 3   | 0.10                 | 0.729                            |
| 5   | 0.10                 | 0.590                            |
| 10  | 0.10                 | 0.349                            |
| 20  | 0.10                 | 0.122                            |
| 30  | 0.10                 | 0.042                            |

**Cumulative distribution function:**

```
Pr[stem_length <= h] = 1 - 0.90^h
Pr[stem_length <= 10] = 0.651    -- median is approximately 7 hops
Pr[stem_length <= 20] = 0.878
Pr[stem_length <= 30] = 0.958
Pr[stem_length <= 50] = 0.995
```

### 2.3 Maximum Stem Length Cap

To prevent pathological cases where a transaction circulates in stem phase indefinitely:

```
MAX_STEM_HOPS = 50
```

If a transaction has been forwarded through 50 stem hops without transitioning to fluff, the 50th node MUST transition to fluff unconditionally. This caps the maximum stem-phase latency at approximately 50 * (stem hop delay) ~ 50 * 500ms = 25 seconds (see Section 4 for delay parameters).

### 2.4 Forced Fluff Conditions

A node MUST immediately broadcast a transaction in fluff mode (bypassing stem phase entirely) when ANY of the following conditions hold:

1. Fewer than `MIN_OUTBOUND_PEERS = 8` outbound peers are connected.
2. Fewer than 2 outbound peers are available for stem selection.
3. The transaction is a time-critical consensus message (heartbeat response, `doc/04-consensus.md` lines 188-209).
4. The node is currently in a degraded state (recovering from partition, initial sync).

---

## 3. Adversary Models

### 3.1 Passive Observer (Network Fraction p)

**Model:** The adversary controls a fraction p of all network nodes. Controlled nodes follow the protocol honestly but record all received transactions and their arrival times.

**Capability:** The adversary observes:
- The first node from which it received a stem-phase transaction.
- The timing of receipt at each of its controlled nodes.
- The IP addresses of all peers of its controlled nodes.

**Limitation:** The adversary cannot distinguish stem-phase forwarding from fluff-phase broadcasting by observing message content alone (see Section 5 for fingerprinting resistance).

**Anonymity bound:** See Section 8.

### 3.2 Active Attacker (Colluding Nodes)

**Model:** The adversary controls p < 0.50 of network nodes. Colluding nodes share all observed data in real time and may deviate from protocol.

**Additional capabilities beyond passive:**
- Drop stem-phase transactions (black hole attack, Section 6).
- Introduce artificial delays to manipulate timing.
- Establish many connections to honest nodes to maximize observation surface.
- Refuse to transition to fluff, extending stem phase through adversary-controlled nodes.

**Mitigation:** Redundant stem paths (Section 6), timeout-based fluff fallback (Section 6.3), peer diversity requirements (Section 7.3).

### 3.3 ISP-Level Observer

**Model:** The adversary operates at network infrastructure level (ISP, IX, backbone). Observes all TCP connections and packet timing for a subset of nodes under its jurisdiction.

**Capabilities:**
- Correlate transaction origination time with TCP connection activity.
- Observe which node first transmitted a transaction to any peer.
- Deep packet inspection (if traffic is unencrypted at transport layer).

**Mitigations:**
- All peer-to-peer connections MUST use TLS 1.3 (minimum). Content is opaque to ISP.
- Stem-phase random delays (Section 4) decorrelate transaction creation time from network transmission time.
- Nodes SHOULD maintain persistent connections to peers, sending keepalive traffic at randomized intervals, to prevent connection establishment timing from leaking transaction origination.

**Recommended keepalive parameters:**

```
KEEPALIVE_INTERVAL_BASE = 30 seconds
KEEPALIVE_JITTER        = +-15 seconds (uniform)
KEEPALIVE_PAYLOAD       = 32 bytes random (indistinguishable from transaction preamble)
```

### 3.4 Timing Correlation Attacker

**Model:** The adversary combines network observation (ISP-level or node-level) with blockchain timestamp analysis to correlate transaction creation events with external metadata (user activity, application-level events).

**Capabilities:**
- Measure the time delta between a transaction's first observation at adversary nodes and its inclusion in a block.
- Correlate cross-epoch timing patterns of repeat senders.

**Mitigations:**
- Stem-phase delay injection (Section 4) adds randomized latency that dominates the signal.
- Batch flushing (Section 4.3) aggregates multiple transactions, destroying individual timing signals.
- Nodes SHOULD NOT create transactions at precisely periodic intervals; application-layer jitter SHOULD be added for automated/scheduled messages.

---

## 4. Stem-Phase Timing Defense

### 4.1 Per-Hop Random Delay

Each node holding a stem-phase transaction MUST delay forwarding by a random interval before relaying to the next stem peer:

```
STEM_DELAY_DISTRIBUTION = Exponential(lambda = 2.0)  -- mean 500ms
STEM_DELAY_MIN          = 50 milliseconds
STEM_DELAY_MAX          = 3000 milliseconds (3 seconds)
```

**Delay sampling procedure:**

```
stem_delay():
    raw = exponential_sample(lambda = 2.0)  -- in seconds
    clamped = clamp(raw, 0.050, 3.000)
    return clamped
```

The exponential distribution provides:
- Most delays are short (median ~ 347ms), preserving transaction propagation latency.
- Occasional long delays (tail) make timing correlation unreliable.
- The memoryless property of the exponential distribution means observing one delay provides no information about previous or future delays.

**Security justification:** An adversary observing two consecutive stem nodes sees a delay that is the sum of two independent exponential variables (Erlang-2 distribution). The variance grows linearly with the number of hops, making it increasingly difficult to estimate the total stem length from end-to-end timing.

### 4.2 Delay Randomness Source

Delay values MUST be derived from a CSPRNG seeded independently of the transaction content:

```
delay_rng_seed = HMAC-SHA-256(node_secret_key, "dandelion_delay" || local_monotonic_counter)
local_monotonic_counter += 1
```

The delay MUST NOT be derivable from the transaction hash, as this would allow an adversary to predict delays for known transactions.

### 4.3 Batch Flushing

To further resist timing analysis, stem-phase nodes MAY accumulate multiple stem transactions and flush them in a single batch:

```
STEM_BATCH_INTERVAL  = 200 milliseconds
STEM_BATCH_MAX_SIZE  = 8 transactions
```

**Batch flushing rules:**
1. Incoming stem transactions are queued in a local stem buffer.
2. The buffer is flushed when EITHER:
   - `STEM_BATCH_INTERVAL` has elapsed since the last flush, OR
   - The buffer contains `STEM_BATCH_MAX_SIZE` transactions.
3. All transactions in a batch are forwarded simultaneously to the stem peer.
4. Per-transaction random delays (Section 4.1) are applied BEFORE queueing, not after — the batch flush adds a second layer of temporal aggregation.

### 4.4 Jitter on Fluff Broadcast

When transitioning from stem to fluff, the broadcasting node MUST add jitter before initiating gossip:

```
FLUFF_JITTER_DISTRIBUTION = Uniform(0, 500) milliseconds
```

This prevents an adversary from identifying the fluff-transition node by observing which node broadcasts with zero delay.

---

## 5. Transaction Fingerprinting Resistance

### 5.1 Canonical Serialization

All transactions in stem phase MUST be serialized in canonical form. Two honest nodes processing the same logical transaction MUST produce byte-identical serializations.

**Canonical form requirements:**

```
1. Field ordering: fixed by protocol schema (not alphabetical, not implementation-dependent).
2. Integer encoding: unsigned, big-endian, fixed-width (no variable-length encoding).
3. No optional padding or alignment bytes.
4. No node-specific metadata (no relay counter, no timestamp of receipt, no path information).
5. No implementation-specific serialization markers (no language-specific type tags).
```

### 5.2 No Node-Specific Metadata

A stem-phase transaction MUST NOT carry any of the following:

| Prohibited field            | Rationale                                             |
|-----------------------------|-------------------------------------------------------|
| Relay hop count             | Reveals position in stem path                         |
| Forwarding node identifier  | Directly identifies intermediate node                 |
| Receipt timestamp           | Enables timing correlation between hops               |
| Node software version       | Narrows anonymity set                                 |
| Peer list or topology hints | Reveals network structure                             |
| TTL or expiry counter       | Hop count can be inferred from decrement              |

### 5.3 Stem vs. Fluff Indistinguishability

The stem-phase forwarding message MUST be structurally identical to a fluff-phase gossip message at the wire level. An intermediate node receiving a transaction MUST NOT be able to determine with certainty whether it arrived via stem or fluff.

**Implementation:**

```
-- Both stem and fluff use the same message type
data TxRelay = TxRelay
    { trPayload :: !ByteString    -- canonical serialized transaction
    , trMode    :: !RelayMode     -- STEM | FLUFF, visible only to sender/receiver
    }
```

The `trMode` field is communicated via a single flag bit in the peer-to-peer message header. An adversary controlling both endpoints of a connection can observe this bit, but an eavesdropper on the encrypted TLS channel cannot.

### 5.4 Transaction Deduplication

Nodes MUST deduplicate transactions by transaction hash (SHA-256 of the canonical serialization). A transaction seen in stem phase and later received again (stem or fluff) MUST be silently dropped without any observable behavioral difference (no error response, no re-broadcast, no timing change).

Deduplication state is maintained for a rolling window:

```
DEDUP_WINDOW = 600 seconds (10 minutes, matches epoch duration)
DEDUP_TABLE_MAX_ENTRIES = 100,000
```

---

## 6. Black Hole Attack Resistance

### 6.1 Attack Description

A malicious stem peer accepts stem-phase transactions but never forwards them (drops silently). The transaction never reaches fluff phase and is never included in a block.

### 6.2 Redundant Stem Paths

Each originating node sends its transaction along TWO independent stem paths:

```
originate_transaction(tx):
    -- Send to both stem peers (selected in Section 1.2)
    send_stem(primary_stem_peer, tx)
    send_stem(secondary_stem_peer, tx)
```

Both paths proceed independently through the stem graph. The transaction transitions to fluff on whichever path reaches a fluff-transition node first. Even if one path is entirely controlled by adversary nodes, the other path is likely to contain honest nodes that will propagate the transaction.

**Analysis:** For the black hole attack to succeed against redundant paths, the adversary must control ALL nodes on BOTH stem paths. For two independent paths of expected length 10 with adversary fraction p:

```
Pr[both paths black-holed] = (p^10)^2 = p^20
For p = 0.20: Pr = 0.20^20 ~ 1.05 * 10^{-14}
```

### 6.3 Timeout-Based Fluff Fallback

The originating node monitors its transaction for confirmation:

```
STEM_TIMEOUT = 30 seconds
```

**Timeout procedure:**

```
after_originate(tx):
    start_timer(STEM_TIMEOUT)

    on_timer_expired:
        if tx NOT in mempool AND tx NOT in any recent block:
            -- Transaction likely dropped; broadcast directly in fluff
            broadcast_fluff(tx)
            log_event(DANDELION_STEM_TIMEOUT, tx_hash_prefix_8bytes)
```

**Detection mechanism:** The originating node checks for its transaction by monitoring:
1. Gossip-layer inventory announcements (the transaction should appear in fluff within `STEM_TIMEOUT`).
2. Block inclusions (the transaction may have been included directly).

If neither is observed, the originating node assumes the stem path failed and falls back to direct fluff broadcast.

### 6.4 Stem Peer Reputation

Nodes MUST NOT maintain persistent reputation scores for stem peers, as this creates a side channel. However, nodes MAY track per-epoch failure counts:

```
STEM_FAILURE_THRESHOLD = 3  -- per epoch
```

If a stem peer triggers more than `STEM_FAILURE_THRESHOLD` timeout-based fallbacks within a single epoch, the node:
1. Selects a replacement stem peer for the remainder of the epoch.
2. Does NOT disconnect from the suspected peer (disconnection is observable).
3. Clears the failure count at the next epoch boundary.

---

## 7. Intersection Attack Resistance

### 7.1 Attack Description

An intersection attack exploits the fact that if a transaction always arrives at adversary nodes from the same direction, the adversary can narrow down the origin over multiple observations across epochs. If stem graphs are static, repeated transactions from the same sender follow the same path, enabling progressive deanonymization.

### 7.2 Rotating Stem Graphs

Stem graphs rotate every `DANDELION_EPOCH_DURATION = 600 seconds` (Section 1.1). Each epoch produces a fresh, independently selected stem graph. Over N epochs, the adversary's observations are drawn from N independent graph samples.

**Intersection resistance bound:**

For an adversary controlling fraction p of nodes, after observing T transactions from the same sender across T different epochs:

```
-- The adversary's candidate set after T observations
-- Each observation eliminates non-stem-neighbors of adversary nodes
-- Expected candidate set size after T epochs:
E[candidate_set] = n * (1 - (1 - Pr[node is on stem path]))^T

-- For a random graph with degree d and stem length h:
Pr[node is on stem path] ~ h * d / n

E[candidate_set] ~ n * (1 - h*d/n)^T ~ n * exp(-T*h*d/n)
```

For the intersection attack to narrow the candidate set to 1 node, the adversary needs approximately:

```
T ~ n * ln(n) / (h * d)
```

With n = 10,000 nodes, h = 10, d = 2 (stem out-degree):

```
T ~ 10000 * ln(10000) / (10 * 2) ~ 10000 * 9.21 / 20 ~ 4605 epochs
```

At 10-minute epochs, this requires approximately 32 days of continuous observation of the same sender. The 11-day truncation cycle (`doc/04-consensus.md` lines 48-52) resets wallet addresses before this threshold is reached.

### 7.3 Minimum Peer Diversity Requirements

To ensure stem graphs have sufficient entropy:

```
MIN_OUTBOUND_PEERS     = 8       -- minimum outbound connections
MIN_DISTINCT_SUBNETS   = 4       -- outbound peers must span at least 4 distinct /16 subnets
MAX_PEERS_PER_SUBNET   = 2       -- at most 2 outbound peers from same /16 subnet
```

**Rationale:** If all outbound peers are in the same subnet, an ISP-level adversary observing that subnet can trivially deanonymize stem traffic. Subnet diversity ensures that stem paths cross multiple network jurisdictions.

**Enforcement:** If a node cannot meet the `MIN_DISTINCT_SUBNETS` requirement, it MUST log a warning and continue with the available peers, but SHOULD prioritize acquiring peers from underrepresented subnets during peer discovery.

### 7.4 Address Rotation Synergy

UmbraVox's 11-day truncation cycle provides a natural identity rotation point. Users SHOULD generate new wallet addresses at each cycle boundary. Combined with epoch-based stem graph rotation, this limits the adversary's observation window:

- **Within an epoch** (10 minutes): single stem graph, single observation.
- **Within a cycle** (11 days): ~1584 independent stem graphs, same address.
- **Across cycles**: different addresses, observations cannot be linked (absent external correlation).

---

## 8. Formal Anonymity Bound

### 8.1 Threat Model Assumptions

- **A7' (Network adversary bound):** Adversary controls fraction p < 0.50 of all network nodes (`doc/10-security.md` line 5).
- **A-NET-1:** The adversary's controlled nodes are distributed uniformly at random in the network topology (no targeted placement).
- **A-NET-2:** The network graph is connected; every honest node has at least `MIN_OUTBOUND_PEERS` outbound connections.
- **A-NET-3:** Stem peer selection is independent of the transaction content.

### 8.2 Attribution Probability Theorem

**Theorem 8.1 (Dandelion++ Anonymity Bound).** For an adversary controlling a fraction p < 0.50 of network nodes, with stem continuation probability q = 0.90 and redundant dual stem paths, the probability of correctly attributing a transaction to its true originator is bounded by:

```
Pr[correct attribution] <= p + (1 - p) * p^h_min
```

where h_min is the minimum stem length (h_min = 1 by construction).

**In expectation over the geometric stem length distribution:**

```
Pr[correct attribution] <= p + (1 - p) * sum_{h=1}^{inf} [(1-q) * q^{h-1} * p^h]
                         = p + (1 - p) * (1 - q) * p / (1 - q*p)
                         = p + (1 - p) * (1 - q) * p / (1 - q*p)
```

**Numerical evaluation:**

| Adversary fraction p | E[Pr[correct attribution]] | Improvement over naive gossip |
|---------------------|---------------------------|-------------------------------|
| 0.05                | 0.050 + 0.950 * 0.10 * 0.05 / (1 - 0.045) = 0.0550 | ~19x vs. p_gossip ~ 1.0 |
| 0.10                | 0.100 + 0.900 * 0.10 * 0.10 / (1 - 0.090) = 0.1099 | ~9x  |
| 0.20                | 0.200 + 0.800 * 0.10 * 0.20 / (1 - 0.180) = 0.2195 | ~4.6x |
| 0.30                | 0.300 + 0.700 * 0.10 * 0.30 / (1 - 0.270) = 0.3288 | ~3.0x |
| 0.40                | 0.400 + 0.600 * 0.10 * 0.40 / (1 - 0.360) = 0.4375 | ~2.3x |

**Interpretation:** The adversary's attribution probability is approximately equal to their network fraction p plus a small correction term. For p <= 0.20, the correction is less than 0.02, meaning the adversary does negligibly better than random guessing among all nodes.

### 8.3 Proof

**Proof of Theorem 8.1.**

A correct attribution occurs in exactly one of two disjoint events:

**Event E1:** The originating node is controlled by the adversary.
- Probability: p.
- The adversary trivially knows it originated the transaction.

**Event E2:** The originating node is honest, but the adversary can trace the stem path back to the origin.
- This requires that every node on the stem path (from origin to the first honest-to-adversary handoff) is controlled by the adversary. In the worst case, the adversary must control all h nodes on the stem path between the originator and the fluff transition point.
- For a stem path of length h, the probability that all h nodes are adversary-controlled is p^h.
- The stem length h is drawn from Geometric(1 - q):

```
E_2 = (1 - p) * sum_{h=1}^{inf} Pr[H = h] * p^h
    = (1 - p) * sum_{h=1}^{inf} (1 - q) * q^{h-1} * p^h
    = (1 - p) * (1 - q) * p * sum_{h=0}^{inf} (q*p)^h
    = (1 - p) * (1 - q) * p / (1 - q*p)        [geometric series, |q*p| < 1]
```

Combining:

```
Pr[correct attribution] = E_1 + E_2
                        = p + (1 - p)(1 - q) * p / (1 - q*p)
```

With dual redundant stem paths (Section 6.2), the adversary must trace BOTH paths. Let h_1, h_2 be independent geometric(1-q) stem lengths for the two paths. The adversary must control all nodes on at least one complete path to trace back to the origin, but deanonymization requires both paths to be compromised (since either path independently looks like a potential origin):

```
Pr[both paths traced] = [sum (1-q)*q^{h-1} * p^h]^2
                       = [(1-q)*p / (1-q*p)]^2
```

For p = 0.20: [(0.10 * 0.20) / (1 - 0.18)]^2 = [0.02439]^2 ~ 5.95 * 10^{-4}.

This makes the E_2 term negligible, reducing Pr[correct attribution] to approximately p.  QED.

### 8.4 Limitations of the Bound

The formal bound assumes:

1. **Uniform adversary placement.** A targeted adversary that strategically connects to high-degree nodes may achieve higher attribution rates. Mitigation: peer diversity requirements (Section 7.3).

2. **No timing side channel.** If the adversary can measure propagation delays with high precision, it may narrow the candidate set beyond what the combinatorial analysis suggests. Mitigation: stem-phase delay injection (Section 4).

3. **Single transaction analysis.** Repeated transactions from the same sender enable intersection attacks (Section 7). The bound applies to a single transaction in a single epoch.

4. **Honest stem forwarding.** If adversary nodes manipulate stem forwarding (e.g., always continuing stem to maximize observation), the effective stem length distribution changes. The timeout fallback (Section 6.3) limits this attack's duration.

---

## 9. Integration with Consensus

### 9.1 Block Producer Anonymity

A slot leader (block producer) includes transactions from its mempool in a block. The block header contains the leader's public key and VRF proof (`doc/04-consensus.md` lines 96-113). This creates a deanonymization risk: if a transaction appears ONLY in the block producer's mempool (not yet propagated via gossip), the block producer is revealed as the transaction's originator or a close stem-phase neighbor.

**Requirement:** A block producer MUST NOT include a transaction in a block unless that transaction has been observed in fluff phase (received via standard gossip from at least one peer, or the producer itself transitioned the transaction to fluff).

```
block_inclusion_policy(tx, mempool_entry):
    if mempool_entry.received_via == STEM:
        -- Transaction still in stem phase; do NOT include in block
        return EXCLUDE
    else:
        -- Transaction received via fluff or originated locally and already fluffed
        return INCLUDE
```

**Exception:** If a transaction has been in the local mempool for longer than `STEM_TIMEOUT` (30 seconds) without being observed in fluff, the block producer MAY include it (the timeout fallback in Section 6.3 should have already triggered fluff broadcast).

### 9.2 Mempool Synchronization

Block producers reveal their mempool contents through their block inclusions. To prevent mempool-based deanonymization:

1. Block producers SHOULD include transactions in the order determined by the deterministic ordering rule (fee descending, then transaction hash; `doc/04-consensus.md` lines 213-218) without preferential treatment for locally-originated transactions.
2. A block producer MUST NOT preferentially include its own transactions ahead of higher-fee transactions from other nodes.
3. Transaction ordering within a block is deterministic by transaction hash (`doc/10-security.md` lines 72-80), removing producer discretion.

### 9.3 Heartbeat Response Handling

Heartbeat responses (`doc/04-consensus.md` lines 188-209) are time-sensitive (10-slot window = 110 seconds). These MUST bypass stem phase entirely and be broadcast directly in fluff mode:

```
heartbeat_response(challenge, validator_sk):
    response = sign(challenge || validator_pubkey, validator_sk)
    broadcast_fluff(response)  -- no stem phase for heartbeat responses
```

This is acceptable because heartbeat responses are inherently attributable (they contain the validator's public key), so Dandelion++ provides no additional anonymity for them.

---

## 10. Configuration Parameters

### 10.1 Complete Parameter Table

| Parameter | Value | Unit | Range | Security Justification |
|-----------|-------|------|-------|----------------------|
| `DANDELION_EPOCH_DURATION` | 600 | seconds | [300, 1800] | Shorter epochs increase intersection attack resistance but add stem graph churn overhead. 600s balances both. |
| `STEM_PEERS_PER_NODE` | 2 | count | [2, 4] | 2 provides redundancy against black holes; >4 increases adversary observation surface. |
| `STEM_CONTINUATION_PROBABILITY` | 0.90 | probability | [0.80, 0.95] | q=0.90 yields E[h]=10 hops. Lower q reduces anonymity; higher q increases latency. |
| `MAX_STEM_HOPS` | 50 | count | [20, 100] | Caps worst-case latency. Pr[h>50] < 0.005, so this rarely triggers. |
| `STEM_DELAY_LAMBDA` | 2.0 | 1/seconds | [1.0, 5.0] | Lambda=2.0 gives mean 500ms delay per hop. Higher lambda = less delay = less timing defense. |
| `STEM_DELAY_MIN` | 50 | milliseconds | [10, 200] | Prevents zero-delay forwarding that leaks stem position. |
| `STEM_DELAY_MAX` | 3000 | milliseconds | [1000, 5000] | Caps worst-case per-hop latency. |
| `STEM_BATCH_INTERVAL` | 200 | milliseconds | [100, 1000] | Batching window. Larger = more privacy, more latency. |
| `STEM_BATCH_MAX_SIZE` | 8 | count | [4, 16] | Maximum transactions per batch flush. |
| `FLUFF_JITTER_MAX` | 500 | milliseconds | [200, 1000] | Uniform jitter on fluff transition. |
| `STEM_TIMEOUT` | 30 | seconds | [15, 60] | Timeout before originator falls back to direct fluff. Must exceed E[stem latency] = 10 * 500ms = 5s by a comfortable margin. |
| `STEM_FAILURE_THRESHOLD` | 3 | count/epoch | [2, 5] | Per-epoch failure count before stem peer replacement. |
| `MIN_OUTBOUND_PEERS` | 8 | count | [6, 12] | Minimum outbound connections for stem path diversity. |
| `MIN_DISTINCT_SUBNETS` | 4 | count | [3, 6] | Minimum /16 subnets represented in outbound peers. |
| `MAX_PEERS_PER_SUBNET` | 2 | count | [1, 3] | Limits adversary leverage from controlling a single subnet. |
| `DEDUP_WINDOW` | 600 | seconds | [300, 1200] | Transaction deduplication window. Matches epoch duration. |
| `DEDUP_TABLE_MAX_ENTRIES` | 100,000 | count | [50000, 500000] | Memory-bounded deduplication table. |
| `KEEPALIVE_INTERVAL_BASE` | 30 | seconds | [15, 60] | Base interval for keepalive traffic to prevent connection timing analysis. |
| `KEEPALIVE_JITTER` | 15 | seconds | [5, 30] | Uniform jitter around keepalive base interval. |

### 10.2 Parameter Modification

All Dandelion++ parameters are compile-time constants. They MUST NOT be adjustable at runtime or via configuration files in production deployments. Changes require a new software release and are subject to the chain revision mechanism (`doc/04-consensus.md` lines 271-285).

**Rationale:** Runtime-configurable anonymity parameters create a fingerprinting vector (nodes with different configurations behave observably differently) and an attack surface (adversary could manipulate configuration to weaken anonymity).

### 10.3 Testnet Overrides

For testnet and development environments ONLY, the following overrides are permitted:

```
TESTNET_STEM_CONTINUATION_PROBABILITY = 0.50  -- shorter stems for faster testing
TESTNET_STEM_DELAY_LAMBDA             = 10.0  -- faster propagation
TESTNET_STEM_TIMEOUT                  = 10    -- faster fallback
```

These MUST be gated behind a compile-time `TESTNET` flag and MUST NOT be present in production builds.

---

## 11. Monitoring Without Deanonymization

### 11.1 Design Principle

Network operators and node runners need to detect Dandelion++ failures (dropped transactions, excessive latency, misconfigured peers) without logging information that could deanonymize users. The monitoring system MUST satisfy:

1. **No transaction content logging.** Monitoring events MUST NOT include full transaction hashes, sender addresses, recipient addresses, or transaction payloads.
2. **No stem path logging.** Monitoring events MUST NOT record which peer forwarded a transaction or which peer a transaction was forwarded to.
3. **Aggregate metrics only.** All metrics MUST be aggregated over time windows, never per-transaction.

### 11.2 Permitted Metrics

The following aggregate metrics MAY be collected and exposed (e.g., via a local metrics endpoint):

| Metric | Type | Aggregation | Description |
|--------|------|-------------|-------------|
| `dandelion_stem_txs_forwarded` | Counter | Per epoch | Total transactions forwarded in stem phase this epoch. |
| `dandelion_fluff_transitions` | Counter | Per epoch | Total transactions transitioned from stem to fluff by this node. |
| `dandelion_stem_timeouts` | Counter | Per epoch | Transactions that triggered timeout-based fluff fallback. |
| `dandelion_stem_peer_fallbacks` | Counter | Per epoch | Times the secondary stem peer was used due to primary failure. |
| `dandelion_forced_fluff` | Counter | Per epoch | Transactions broadcast directly in fluff (bypassing stem). |
| `dandelion_stem_latency_p50` | Gauge | Per epoch | Median delay between receiving a stem tx and forwarding it (local processing time only). |
| `dandelion_stem_latency_p99` | Gauge | Per epoch | 99th percentile of the above. |
| `dandelion_epoch_stem_peers` | Gauge | Per epoch | Number of stem peers selected this epoch (expected: 2). |
| `dandelion_outbound_peer_count` | Gauge | Per epoch | Total outbound peer connections. |
| `dandelion_outbound_subnet_count` | Gauge | Per epoch | Distinct /16 subnets in outbound peer set. |
| `dandelion_dedup_table_size` | Gauge | Sampled | Current size of the deduplication table. |
| `dandelion_black_hole_suspicions` | Counter | Per epoch | Times a stem peer exceeded `STEM_FAILURE_THRESHOLD`. |

### 11.3 Prohibited Logging

The following MUST NOT appear in any log output, metrics endpoint, or debug trace in production builds:

| Prohibited data | Reason |
|-----------------|--------|
| Transaction hash (full) | Links monitoring data to specific transactions |
| Transaction hash prefix (> 4 bytes) | Partial hashes may still be correlatable |
| Stem peer identity (IP, pubkey) | Reveals stem graph structure |
| Stem path length for specific transactions | Reveals anonymity level of individual transactions |
| Per-transaction timing (creation time, receipt time) | Enables timing correlation |
| Mempool contents at stem/fluff transition | Reveals which transactions were in stem phase |

### 11.4 Alerting

Node operators SHOULD configure alerts on the following conditions:

| Condition | Threshold | Action |
|-----------|-----------|--------|
| `dandelion_stem_timeouts` > 10% of `stem_txs_forwarded` | Per epoch | Investigate peer connectivity; possible black hole peers |
| `dandelion_outbound_peer_count` < `MIN_OUTBOUND_PEERS` | Continuous | Node is in degraded mode (forced fluff); investigate peer discovery |
| `dandelion_outbound_subnet_count` < `MIN_DISTINCT_SUBNETS` | Continuous | Anonymity may be reduced; diversify peer connections |
| `dandelion_black_hole_suspicions` > 0 | Per epoch | Possible adversarial stem peer; monitor trend across epochs |
| `dandelion_epoch_stem_peers` < 2 | Per epoch | Stem redundancy lost; investigate outbound peer availability |

### 11.5 Debug Mode (Non-Production Only)

A compile-time `DANDELION_DEBUG` flag MAY enable additional per-transaction logging for development and testing purposes. When enabled:

- Full transaction hashes MAY be logged.
- Stem path decisions (stem/fluff coin flip results) MAY be logged.
- Peer identities for stem forwarding MAY be logged.

This flag MUST be disabled in all production and testnet builds. The build system MUST enforce that `DANDELION_DEBUG` and `PRODUCTION` flags are mutually exclusive.

---

## Appendix A: Wire Protocol Messages

### A.1 Stem Relay Message

```
message TxStemRelay {
    bytes  tx_payload = 1;     -- canonical serialized transaction
    uint32 relay_flag = 2;     -- 0x01 = STEM, 0x02 = FLUFF
}
```

The `relay_flag` is visible only to directly connected peers (encrypted by TLS). An eavesdropper on the network cannot distinguish stem from fluff traffic.

### A.2 Stem Inventory Announcement

Stem-phase transactions MUST NOT be announced via inventory (inv) messages. They are forwarded directly as full payloads to the stem peer. This prevents adversary nodes from selectively requesting stem transactions from multiple peers to triangulate the origin.

Fluff-phase transactions follow standard gossip: inventory announcement followed by data request.

---

## Appendix B: Interaction with Sybil Attacks

A Sybil attacker creating many fake node identities can increase their effective network fraction p. Dandelion++ does not independently defend against Sybil attacks; it relies on the peer management layer to limit Sybil influence.

**Peer management requirements for Dandelion++ security:**

1. Outbound connections are initiated by the node, not accepted from inbound requests. Stem peers are selected ONLY from outbound connections.
2. Inbound connections are never used for stem forwarding (inbound peers may be Sybils).
3. Peer discovery should use diverse bootstrap sources to prevent eclipsing.
4. The `MAX_PEERS_PER_SUBNET` limit (Section 7.3) bounds Sybil leverage from a single network location.

---

## Appendix C: Comparison with Tor and Mixnets

| Property | Dandelion++ (this spec) | Tor | Mixnet (Loopix) |
|----------|------------------------|-----|-----------------|
| Latency overhead | ~5 seconds (E[10 hops] * 500ms) | 200-1000ms (3 relays) | Seconds to minutes |
| Anonymity set | All network nodes | All Tor users | All mixnet users |
| Adversary model | Fraction p of nodes | Global passive + some active | Global passive |
| Infrastructure | None (peer-to-peer) | Dedicated relay network | Dedicated mix servers |
| Integration cost | Protocol-native | Requires external dependency | Requires external dependency |
| Sender anonymity | Medium (p-bounded) | High (onion routing) | High (mixing + cover traffic) |

Dandelion++ is chosen for UmbraVox because it requires no external infrastructure, adds minimal latency suitable for chat applications, and integrates natively with the peer-to-peer gossip layer. The anonymity guarantee is weaker than Tor or mixnets but sufficient for the threat model where p < 0.50 and the primary goal is preventing IP-to-transaction linkage by passive observers.
