# Traffic Analysis Defense Specification

**Hardening Document 13**
**Source requirements:** `doc/10-security.md` (threat matrix: IP deanonymization, on-chain metadata), `doc/03-cryptography.md` (padding, CSPRNG), `doc/proof-07-cryptanalysis-resistance.md` (section 6)
**Depends on:** `doc/08-dandelion.md`, `doc/07-message-format.md`
**Security target:** Reduce traffic-analysis advantage to negligible for passive adversaries at privacy level MEDIUM; reduce to formally bounded leakage at privacy level HIGH.

---

## 0. Notation and Definitions

| Symbol | Definition |
|--------|-----------|
| `A` | Adversary (PPT unless stated otherwise) |
| `O(t, s, src, dst)` | A single observation tuple: timestamp `t` (ms), ciphertext size `s` (bytes), source IP `src`, destination IP `dst` |
| `T` | Observation trace: ordered sequence of tuples `[O_1, O_2, ..., O_n]` |
| `lambda` | Security parameter (128 bits) |
| `U[a, b]` | Continuous uniform distribution on interval `[a, b]` |
| `Geom(p)` | Geometric distribution with success probability `p` |
| `Exp(r)` | Exponential distribution with rate `r` |
| `negl(lambda)` | Negligible function in `lambda` |
| `H_min(X)` | Min-entropy of random variable `X` |

---

## 1. Message Timing Correlation

### 1.1 Attack Description

An observer at the network layer correlates the time Alice transmits a transaction with the time Bob's node receives and processes it. Even with Dandelion++ stem-phase indirection, an adversary observing both Alice's outbound link and Bob's inbound link can correlate by timestamp proximity.

### 1.2 Threat Model

The adversary observes `(t_send, src=Alice_IP)` and `(t_recv, dst=Bob_IP)` and tests whether `|t_recv - t_send - E[stem_delay]|` falls within a statistical threshold.

### 1.3 Countermeasure: Application-Layer Random Delay

Before handing a transaction to the Dandelion++ stem layer, the sending node injects a random delay:

```
delay_inject :: IO ()
delay_inject = do
  d <- csprng_uniform_double 0.0 2.0   -- seconds, from ChaCha20 CSPRNG
  threadDelay (round (d * 1_000_000))   -- microseconds
```

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Distribution | `U[0, 2000]` ms | Uniform provides maximum entropy per unit of added latency |
| Source | ChaCha20 CSPRNG (`doc/03-cryptography.md` line 40) | Cryptographic uniformity; no bias |
| Application point | After user action, before `on_create_local_tx` | Decouples user-observable action from network emission |

**Composition with Dandelion++ delays:**

Total sender-to-fluff delay becomes:

```
T_total = T_app_delay + T_stem_traversal + T_fluff_propagation
        = U[0, 2000ms] + Geom(0.10) * U[80, 160ms] + ~200ms
```

Expected: `1000 + 10*120 + 200 = 2400ms`. Standard deviation: ~620ms.

### 1.4 Formal Bound

**Claim 1.1.** For an adversary observing both Alice's outbound link and Bob's inbound link, the correlation advantage from timing alone is:

```
Adv^timing-corr(A) <= 1 / sqrt(2 * pi * sigma^2) * delta_t
```

where `sigma^2 = Var(T_total)` and `delta_t` is the adversary's timing resolution.

For `sigma ~ 620ms` and `delta_t = 50ms` (typical network jitter resolution):

```
Adv^timing-corr(A) <= 50 / (620 * sqrt(2 * pi)) ~ 0.032
```

This per-observation advantage compounds across multiple observations. After `k` independent observations of Alice-to-Bob traffic, the adversary's confidence grows as `1 - (1 - 0.032)^k`. At `k = 100` observations, confidence reaches ~96%. Mitigation: cover traffic (section 2) introduces false positives that prevent clean accumulation.

---

## 2. Message Frequency Analysis

### 2.1 Attack Description

An adversary monitoring a node's outbound traffic rate can distinguish active conversation periods from idle periods. Transaction rate spikes correlate with conversation activity.

### 2.2 Countermeasure: Cover Traffic (Dummy Messages)

Nodes generate dummy transactions at a configurable rate to maintain a baseline traffic level that masks real activity.

#### 2.2.1 Dummy Transaction Specification

Dummy transactions use `msg_type = 0xFF` (DUMMY) as defined in `doc/07-message-format.md` line 44. They are:

- Encrypted with an ephemeral key (indistinguishable from real traffic to relay peers)
- Padded to exactly 1024 bytes (single block, identical size to real single-block messages)
- Addressed to a random `recipient_id` (20 bytes from CSPRNG)
- Filtered at mempool entry by block producers (never included in blocks, cost 0 MTK)
- Indistinguishable from real stem transactions at the network layer

#### 2.2.2 Cover Traffic Generation Algorithm

```
cover_traffic_loop :: CoverConfig -> IO ()
cover_traffic_loop cfg = forever $ do
  -- Inter-arrival time: exponential distribution for Poisson process
  rate <- pure (coverRate cfg)                 -- messages per second
  delay_s <- csprng_exponential rate           -- Exp(rate)
  threadDelay (round (delay_s * 1_000_000))

  -- Generate and send dummy
  dummy <- generate_dummy_tx
  on_create_local_tx dummy                     -- enters Dandelion++ stem
```

#### 2.2.3 Cover Traffic Rate Parameters

| Privacy Level | Rate (msgs/sec) | Rate (msgs/epoch, 120s) | Bandwidth Overhead |
|---------------|-----------------|-------------------------|--------------------|
| LOW | 0 (disabled) | 0 | 0 |
| MEDIUM | 1/30 (~0.033) | ~4 | ~4 KB / 120s (~0.27 kbps) |
| HIGH | 1/5 (0.20) | ~24 | ~24 KB / 120s (~1.6 kbps) |

The existing Dandelion++ spec (`doc/08-dandelion.md` line 93) defines 1 dummy per epoch as a baseline. The MEDIUM level increases this to ~4/epoch; HIGH to ~24/epoch.

#### 2.2.4 Formal Traffic Indistinguishability

**Definition 2.1 (Traffic Indistinguishability).** A cover traffic scheme achieves `(epsilon, delta)`-indistinguishability if for all PPT adversaries `A` observing the outbound traffic trace `T`:

```
|Pr[A(T_active) = 1] - Pr[A(T_idle) = 1]| <= epsilon
```

where `T_active` is the trace during an active conversation and `T_idle` is the trace during idle (cover traffic only), with failure probability at most `delta`.

**Claim 2.1.** At MEDIUM privacy level (cover rate 1/30 Hz) with real message rate <= 1/30 Hz, the cover traffic makes active and idle periods `(0.15, 2^{-40})`-indistinguishable over any 120-second observation window.

**Proof sketch.** Under the Poisson cover model, the idle traffic follows `Poisson(4)` per epoch. Active traffic adds at most 4 real messages per epoch (matching the cover rate). The combined active trace follows `Poisson(8)`. The adversary must distinguish `Poisson(4)` from `Poisson(8)` in a single epoch. The total variation distance between `Poisson(4)` and `Poisson(8)` is bounded by `sqrt(1 - e^{-(8-4)^2 / (2*4)}) ~ 0.15` (Pinsker's inequality applied to Poisson KL divergence). Over multiple epochs, accumulation is mitigated by the independent randomness per epoch.

When real message rate exceeds the cover rate, the excess is visible. Users sending at high rates should increase their cover rate or use constant-rate mode (section 11, HIGH privacy level).

---

## 3. Message Size Analysis

### 3.1 Current Padding (1024-byte blocks)

Per `doc/07-message-format.md`, all messages are padded to 1024-byte blocks. A single-block message always appears as exactly 1024 bytes on the wire (1198 bytes in the transaction envelope). The padding field (54 bytes at offset 970) is filled with CSPRNG random bytes.

### 3.2 Residual Leakage: Block Count

The number of blocks in a multi-block message is visible to any observer (each block is a separate transaction sharing the same `message_id`). This reveals the message size class:

| Blocks | Plaintext Size Range | Typical Content |
|--------|---------------------|-----------------|
| 1 | 0 -- 782 bytes | Chat messages (vast majority) |
| 2 | 783 -- 1,564 bytes | Long messages, key exchange, ratchet refresh |
| 3 | 1,565 -- 2,346 bytes | Short file attachments |
| 4+ | 2,347+ bytes | File transfers |

### 3.3 Block-Count Leakage Quantification

**Information leaked per message:** `log2(total_blocks)` bits of length information.

For typical chat (single block): 0 bits leaked (all messages look identical).

For multi-block messages, the adversary learns `ceil(plaintext_length / 782)`. The conditional entropy of exact length given block count:

```
H(length | blocks = n) = log2(782)  ~ 9.6 bits
```

The adversary loses ~9.6 bits of length precision per block but gains the block count itself.

### 3.4 Mitigation: Random Block Padding

For MEDIUM privacy level, append 0--2 additional dummy blocks (CSPRNG-selected) to multi-block messages:

```
padded_block_count :: Word16 -> IO Word16
padded_block_count real_blocks = do
  extra <- csprng_uniform_int 0 2
  pure (real_blocks + fromIntegral extra)
```

Dummy blocks have `block_index` values beyond `total_blocks - 1` and are filled with CSPRNG random bytes. The receiver discards blocks with `block_index >= total_blocks` (the real `total_blocks` is inside the encrypted header of block 0).

**Implementation note:** The `total_blocks` field in the plaintext header (offset 134, encrypted within the payload) reflects the true block count. The outer transaction-level block count visible to observers includes the padding blocks. The receiver reconstructs the message from only the first `total_blocks` blocks.

---

## 4. Extended Padding: Fixed-Size Messages

### 4.1 Fixed-Size Message Mode

For HIGH privacy level, all messages are padded to a fixed number of blocks regardless of content:

```
FIXED_MESSAGE_SIZE = 4 blocks = 4096 bytes on wire
```

#### 4.1.1 Algorithm

```
fixed_pad :: ByteString -> [Block]
fixed_pad plaintext =
  let real_blocks = encode_blocks plaintext            -- 1..N blocks
      pad_count   = FIXED_MESSAGE_SIZE - length real_blocks
  in if pad_count < 0
     then chunk_to_fixed real_blocks                   -- split into FIXED_MESSAGE_SIZE groups
     else real_blocks ++ replicate pad_count dummy_block
```

For messages exceeding `FIXED_MESSAGE_SIZE` blocks, the message is split into multiple fixed-size groups, each appearing as an independent `FIXED_MESSAGE_SIZE`-block message with a distinct `message_id`. The receiver reassembles using a secondary sequence number inside the encrypted payload.

#### 4.1.2 Bandwidth vs. Privacy Trade-off

| Mode | Avg Chat Message (200 bytes) | Bandwidth | Privacy Gain |
|------|------------------------------|-----------|-------------|
| Standard (1 block) | 1,024 bytes | 1x | Block-level size classes visible |
| Random pad (1-3 blocks) | ~2,048 bytes avg | ~2x | Block count randomized |
| Fixed 4-block | 4,096 bytes | 4x | Zero length information leaked |

#### 4.1.3 Configurable Fixed Size

The fixed block count is configurable per node:

| Setting | Blocks | Wire Size | Use Case |
|---------|--------|-----------|----------|
| `FIXED_SIZE_SMALL` | 2 | 2,048 bytes | Chat-only nodes |
| `FIXED_SIZE_MEDIUM` | 4 | 4,096 bytes | Default HIGH mode |
| `FIXED_SIZE_LARGE` | 8 | 8,192 bytes | File transfer privacy |

All nodes in a conversation should use the same fixed size to prevent the fixed size itself from becoming a fingerprint. The fixed size is negotiated during PQXDH session establishment (included in the encrypted first-message payload).

---

## 5. Conversation Pattern Fingerprinting

### 5.1 Attack Description

An adversary classifies conversation type by observing traffic pattern features:

| Pattern Feature | Chat | File Transfer | Group Message |
|----------------|------|---------------|---------------|
| Message rate | Bursty, bidirectional | Sustained unidirectional | Fan-out (1:N) |
| Block count | 1 (mostly) | 4+ (consistently) | 1 per recipient |
| Inter-message timing | Variable, correlated | Regular, short intervals | Near-simultaneous burst |
| Duration | Minutes to hours | Seconds to minutes | Single burst |

### 5.2 Countermeasure: Pattern Normalization

#### 5.2.1 File Transfer Fragmentation

Large file transfers are rate-limited and interleaved with cover traffic to appear as extended chat sessions:

```
file_transfer_normalize :: ByteString -> IO ()
file_transfer_normalize file_data = do
  let chunks = chunk_to_fixed_blocks file_data    -- 4-block groups
  forM_ chunks $ \chunk -> do
    delay <- csprng_uniform_double 0.5 3.0         -- seconds
    threadDelay (round (delay * 1_000_000))
    send_message chunk
    -- Inject 0-2 dummy messages between chunks
    n_dummies <- csprng_uniform_int 0 2
    replicateM_ n_dummies $ do
      d <- csprng_uniform_double 0.2 1.5
      threadDelay (round (d * 1_000_000))
      send_dummy
```

**Trade-off:** File transfer throughput drops to approximately 1-2 blocks/second (6-12 kbps effective throughput). Acceptable for the privacy-sensitive use case; users needing high throughput should use LOW privacy level.

#### 5.2.2 Group Message De-Correlation

When sending a message to N group members, the sender inserts random delays between individual sends:

```
group_send :: [RecipientId] -> ByteString -> IO ()
group_send recipients msg = do
  order <- csprng_shuffle recipients             -- random send order
  forM_ order $ \r -> do
    delay <- csprng_uniform_double 0.0 5.0       -- up to 5s between recipients
    threadDelay (round (delay * 1_000_000))
    send_to r msg
```

This spreads the fan-out burst over 0--5*N seconds, making it resemble independent conversations.

#### 5.2.3 Bidirectional Padding

For chat sessions, if traffic is predominantly unidirectional for > 10 seconds, the quiet side generates 1-2 dummy messages to maintain bidirectional appearance:

```
bidirectional_pad :: SessionState -> IO ()
bidirectional_pad session = do
  let silence = time_since_last_send session
  when (silence > 10_000) $ do     -- 10 seconds, milliseconds
    n <- csprng_uniform_int 1 2
    replicateM_ n (send_dummy_to (sessionPeer session))
```

---

## 6. Network-Layer Fingerprinting

### 6.1 Attack Description

Below the application layer, TCP behavior and TLS record structure can leak information:

| Observable | Information Leaked |
|-----------|-------------------|
| TCP segment sizes | Maps to application message boundaries |
| TLS record sizes | Application data length visible to network observer |
| TCP timing (Nagle, ACK) | Distinguishes interactive vs. bulk transfer |
| TLS version/cipher suite | Identifies UmbraVox nodes vs. other traffic |
| TCP connection duration | Session length correlates with conversation type |

### 6.2 Countermeasure: TLS Record Padding

#### 6.2.1 TLS 1.3 Record Padding

TLS 1.3 (RFC 8446) natively supports record padding via the `ContentType` byte. All UmbraVox TLS records are padded to one of the following fixed sizes:

```
TLS_RECORD_SIZES = [2048, 4096, 8192]   -- bytes of TLS record payload
```

**Algorithm:**

```
pad_tls_record :: ByteString -> ByteString
pad_tls_record payload =
  let target = minimum (filter (>= BS.length payload) TLS_RECORD_SIZES)
      pad_len = target - BS.length payload
  in payload <> BS.replicate pad_len 0x00       -- TLS 1.3 padding
```

If payload exceeds 8192 bytes, it is split into multiple 8192-byte records.

#### 6.2.2 TCP Behavior Normalization

- **Disable Nagle algorithm** (`TCP_NODELAY` socket option) for all peer connections. Prevents TCP-level message coalescing that creates timing patterns.
- **Fixed TCP write schedule:** Buffer application writes and flush to the TCP socket at fixed 50ms intervals, regardless of whether data is pending. Empty flushes produce no TCP segment (no wire observable), but the regularity prevents timing leakage from write bursts.

#### 6.2.3 TLS Cipher Suite Restriction

All UmbraVox peer connections use TLS 1.3 with a single cipher suite:

```
TLS_AES_256_GCM_SHA384 (0x1302)
```

No cipher suite negotiation variability. This is consistent across all nodes to prevent fingerprinting by cipher suite selection.

#### 6.2.4 Connection Multiplexing

All peer-to-peer traffic (gossip, stem relay, block propagation) shares a single persistent TLS connection per peer. This prevents an observer from correlating connection establishment with conversation initiation.

---

## 7. ISP-Level Observation

### 7.1 Adversary Capability

An ISP observes all traffic entering and leaving a subscriber's connection:

- All `(timestamp, size, dst_IP)` tuples
- DNS queries (unless DoH/DoT)
- Connection establishment patterns
- Total bandwidth consumption over time

### 7.2 What the ISP Can Infer

| Observable | Inference | Confidence |
|-----------|-----------|------------|
| Connection to known UmbraVox node IP | User runs UmbraVox | High |
| Traffic volume spikes | Active conversation periods | Medium (mitigated by cover traffic) |
| Number of peer connections | Node role (full node vs. light client) | Medium |
| DNS queries for bootstrap nodes | UmbraVox user | High |
| Connection timing to specific peers | Possible social graph edges | Low (all full nodes connect to many peers) |

### 7.3 Countermeasure: VPN/Tor Integration

For HIGH privacy level, all UmbraVox traffic is routed through a transport-layer anonymization network.

#### 7.3.1 Tor Integration (Recommended for HIGH)

```
tor_transport :: TransportConfig
tor_transport = TransportConfig
  { tcSocksProxy  = "127.0.0.1:9050"      -- local Tor SOCKS5 proxy
  , tcOnionService = True                   -- expose node as .onion service
  , tcCircuitIsolation = PerPeer            -- separate Tor circuit per peer
  , tcDNSResolution = ViaTor               -- all DNS through Tor
  }
```

**Requirements:**
- All peer connections routed through Tor (SOCKS5 proxy)
- Node advertises `.onion` address (not clearnet IP) in peer discovery
- DNS resolution performed through Tor to prevent DNS leakage
- Per-peer circuit isolation prevents Tor exit correlation

**Latency impact:** Tor adds approximately 200-800ms per hop (3 hops typical), increasing total message latency to 1-3 seconds. This is acceptable for chat.

#### 7.3.2 VPN Fallback

If Tor is unavailable, a VPN provides partial protection:

- Hides UmbraVox peer connections from the ISP
- Does NOT provide anonymity from the VPN provider
- Does NOT protect against traffic correlation by a global adversary

**Configuration:**

```
vpn_transport :: TransportConfig
vpn_transport = TransportConfig
  { tcInterface = "tun0"                    -- VPN tunnel interface
  , tcDNSResolution = ViaVPN               -- DNS through VPN tunnel
  , tcKillSwitch = True                     -- block non-VPN traffic
  }
```

#### 7.3.3 DNS Privacy

Regardless of privacy level, UmbraVox nodes should use encrypted DNS:

- **MEDIUM:** DNS-over-HTTPS (DoH) to a trusted resolver
- **HIGH:** All DNS resolution through Tor

Bootstrap node discovery uses hardcoded IP addresses (no DNS required for initial connection).

---

## 8. Global Passive Adversary (GPA)

### 8.1 Adversary Capability

A nation-state adversary observes all internet traffic simultaneously. The adversary records:

```
GPA_trace = { O(t, s, src, dst) : for all (t, s, src, dst) on the internet }
```

### 8.2 Dandelion++ Limitations Against GPA

**Theorem 8.1 (Dandelion++ GPA Vulnerability).**

Dandelion++ does NOT provide anonymity against a global passive adversary. The GPA can observe the stem path in its entirety.

**Proof.**

The GPA observes every stem-phase relay. The stem path is:

```
Alice -> Node_1 -> Node_2 -> ... -> Node_k -> [fluff]
```

The GPA sees `O(t_0, s, Alice_IP, Node_1_IP)`, `O(t_1, s, Node_1_IP, Node_2_IP)`, etc. By matching transaction hashes (or ciphertext identity across relays), the GPA traces the stem back to Alice with certainty.

Even without transaction hash visibility (encrypted stem relay), the GPA can use timing correlation: `t_0 < t_1 < ... < t_k` with small inter-hop delays (~80-160ms) creates a distinguishable causal chain.

### 8.3 Countermeasures Against GPA

#### 8.3.1 Tor Onion Routing (Required for GPA Resistance)

Tor provides GPA resistance through:

- Encrypted, multi-hop circuits (GPA cannot correlate by content)
- Circuit padding (configurable in Tor 0.4+)
- Guard node pinning (reduces exposure surface)

**Residual GPA risk with Tor:** End-to-end timing correlation remains possible in theory (Murdoch & Danezis 2005). Mitigation: application-layer delay injection (section 1) adds noise on top of Tor's transport.

#### 8.3.2 Mix Network Integration (Future / v2+)

For stronger GPA resistance than Tor provides, a mix network (e.g., Loopix-style) could replace Dandelion++ for the stem phase:

- Messages are batched and delayed at each mix node
- Poisson mix strategy: each node delays messages by `Exp(mu)` with `mu` tuned for latency/anonymity trade-off
- Cover traffic loops through the mix network

This is not implemented in v1. The protocol is designed so that the transport layer (currently Dandelion++ over TCP/TLS) is modular and replaceable.

### 8.4 GPA Observation Bounds (Without Tor)

Without Tor, a GPA can determine:

| Property | Can GPA Determine? | Mitigation |
|----------|-------------------|------------|
| Alice sent a transaction | **Yes** (observes outbound from Alice's IP) | Tor |
| Bob received a transaction | **Yes** (all full nodes receive all blocks) | No (inherent to broadcast) |
| Alice sent to Bob specifically | **No** (recipient is encrypted on-chain) | Encryption |
| Alice is active on UmbraVox | **Yes** (traffic to known node IPs) | Tor, VPN |
| Alice's conversation frequency | **Partially** (mitigated by cover traffic) | Cover traffic + Tor |
| Message content | **No** (Signal + PQ encryption) | Encryption |

---

## 9. Active Traffic Manipulation

### 9.1 Attack Description

An active adversary (e.g., malicious ISP, compromised router) selectively drops, delays, or replays transactions to test hypotheses about sender identity.

#### 9.1.1 Drop-and-Observe Attack

The adversary drops a stem transaction from a suspected sender and observes whether the expected recipient fails to receive a message.

**Detection:**

```
drop_detect :: StemPoolState -> IO ()
drop_detect state = do
  -- Embargo timer (doc/08-dandelion.md line 68) triggers fluff after 5-30s
  -- If stem tx is dropped, originating node fluffs via standard gossip
  -- Adversary must drop ALL paths (stem + embargo fluff) to prevent delivery
  when (embargo_expired tx && not (seen_in_fluff tx)) $
    fluff tx    -- failsafe broadcast
```

**Countermeasure:** Dandelion++ embargo timer (`doc/08-dandelion.md` lines 68-71) already provides resilience. If the stem relay drops the transaction, the originator fluffs after 5-30 seconds. The adversary must:

1. Identify the originator (which Dandelion++ obscures), AND
2. Drop BOTH the stem relay AND the embargo-triggered fluff

For the adversary to suppress the embargo fluff, they must control all of Alice's outbound gossip peers, which requires controlling the majority of her peer set.

#### 9.1.2 Delay-and-Correlate Attack

The adversary delays a specific stem transaction by `delta` milliseconds and observes whether Bob's response is similarly delayed.

**Countermeasure:** Application-layer random delay (section 1) and cover traffic (section 2) prevent clean correlation. Bob's response timing is independent of the received message timing (Bob's own application-layer delay is drawn independently).

**Formal bound:**

```
Corr(T_alice_send, T_bob_respond | delay_injection) <= rho
```

where `rho = Cov(T_a, T_b) / (sigma_a * sigma_b)`. With independent delays:

```
rho = sigma_human^2 / ((sigma_human^2 + sigma_delay^2) * (sigma_human^2 + sigma_delay^2))^{1/2}
```

For `sigma_human ~ 5s` (human response time variance) and `sigma_delay ~ 0.577s` (uniform [0,2] std dev):

```
rho ~ 25 / sqrt(25 + 0.33)^2 ~ 25 / 25.33 ~ 0.987
```

The delay injection alone provides minimal decorrelation against human response time analysis. The primary defense is cover traffic (false positives prevent the adversary from identifying which message triggered the response).

#### 9.1.3 Replay Attack

The adversary replays a previously observed stem transaction.

**Countermeasure:** Transaction deduplication by `tx_hash`. Each node maintains a seen-transaction set. Replayed transactions are dropped at the first receiving node. The `nonce` field in the transaction envelope (`doc/07-message-format.md` line 67) prevents valid replay across sessions.

### 9.2 Active Manipulation Detection

Nodes track stem delivery statistics:

```
data StemStats = StemStats
  { ssEmbargoTriggers  :: !Word64    -- times embargo timer fired (stem drop suspected)
  , ssDeliveryLatency  :: ![Double]  -- rolling window of stem-to-fluff latencies
  , ssPeerFailures     :: !(Map PeerId Word32)  -- per-peer stem drop count
  }
```

**Alert thresholds:**

| Metric | Threshold | Action |
|--------|-----------|--------|
| Embargo trigger rate | > 20% of sent transactions | Log warning, rotate relay peers |
| Per-peer drop rate | > 50% of stems relayed to peer | Deprioritize peer, select alternate relay |
| Latency anomaly | > 3 sigma from rolling mean | Log warning |

---

## 10. Formal Traffic Analysis Model

### 10.1 Adversary Observation Model

**Definition 10.1 (Traffic Observation).** The adversary's view is a trace:

```
T = [(t_1, s_1, src_1, dst_1), (t_2, s_2, src_2, dst_2), ..., (t_n, s_n, src_n, dst_n)]
```

where each tuple represents an observed network packet (after TLS decryption by the adversary's position, e.g., a compromised router sees TLS record metadata but not plaintext).

The adversary's observation depends on their position:

| Position | Observes `t` | Observes `s` | Observes `src` | Observes `dst` | Observes content |
|----------|-------------|-------------|---------------|---------------|-----------------|
| ISP (Alice) | Yes | TLS record size | Alice's IP | Peer IPs | No |
| ISP (Bob) | Yes | TLS record size | Peer IPs | Bob's IP | No |
| Malicious peer | Yes | Application msg size | Peer IP | Own IP | No (encrypted) |
| Global passive | Yes | TLS record size | All IPs | All IPs | No |
| Compromised node | Yes | Plaintext msg size | Sender addr | Recipient addr | No (Signal encrypted) |

### 10.2 What Cannot Be Inferred (Security Claims)

**Theorem 10.1 (Content Confidentiality).** No traffic analysis on `T` reveals message content.

**Proof.** Message content is encrypted under Signal Double Ratchet + PQ wrapper (IND-CCA2, `doc/proof-07-cryptanalysis-resistance.md` section 8). Ciphertext is computationally indistinguishable from random. The adversary's trace contains only `(t, s, src, dst)` -- none of these fields encode content. Content confidentiality follows from the encryption scheme's IND-CCA2 property independently of traffic analysis.

**Theorem 10.2 (Sender-Recipient Unlinkability, Privacy Level HIGH with Tor).**

Under the HIGH privacy configuration (constant-rate traffic, fixed-size messages, Tor transport), for any two honest users Alice and Bob:

```
|Pr[A(T) = "Alice communicates with Bob"] - 1/N^2| <= negl(lambda)
```

where `N` is the number of active users and the probability is over the randomness of cover traffic, Tor circuits, and application-layer delays.

**Proof sketch.**

1. **Fixed-size messages** (section 4): all transactions are `FIXED_MESSAGE_SIZE` blocks. The adversary's `s` observation is constant; `s` carries zero information.

2. **Constant-rate traffic** (section 11, HIGH mode): each node emits transactions at a fixed rate `R` regardless of activity. The adversary's observation of Alice's outbound rate is always `R`. No temporal correlation with conversation activity.

3. **Tor transport** (section 7.3.1): `src` and `dst` in the adversary's trace are Tor relay IPs, not Alice's or Bob's IPs. Per-peer circuit isolation prevents circuit-level correlation.

4. **Composition:** With constant `s`, constant rate, and anonymized `(src, dst)`, the adversary's trace for Alice communicating with Bob is identically distributed to Alice communicating with any other user or being idle. The adversary's advantage reduces to breaking Tor's anonymity, which is `negl(lambda)` against a non-global adversary.

**Caveat:** Against a GPA, Tor's end-to-end timing correlation remains a theoretical vulnerability (section 8.3.1). Full GPA resistance requires mix networking (section 8.3.2, future work).

**Theorem 10.3 (Activity Detection, Privacy Level MEDIUM).**

Under MEDIUM privacy (cover traffic at rate `R_c`, standard padding), the adversary can detect whether Alice is active with advantage:

```
Adv^activity(A) <= TV(Poisson(R_c * W), Poisson((R_c + R_real) * W))
```

where `R_real` is Alice's real message rate and `W` is the observation window in seconds. `TV` denotes total variation distance.

For `R_c = 1/30`, `R_real = 1/30`, `W = 120`:

```
TV(Poisson(4), Poisson(8)) ~ 0.15
```

This is the fundamental limit of MEDIUM privacy: the adversary has a ~15% advantage per epoch in detecting active conversation.

### 10.3 Information-Theoretic Leakage Summary

| Observable | LOW | MEDIUM | HIGH |
|-----------|-----|--------|------|
| Message content | 0 bits | 0 bits | 0 bits |
| Message size class | `log2(blocks)` bits | `~0.5` bits (randomized padding) | 0 bits (fixed size) |
| Conversation activity | Fully visible | ~0.23 bits/epoch | 0 bits (constant rate) |
| Sender IP | Dandelion++ only | Dandelion++ only | Hidden (Tor) |
| Conversation type (chat/file/group) | Distinguishable | Partially masked | Indistinguishable |

---

## 11. User-Configurable Privacy Levels

### 11.1 Privacy Level Definitions

#### 11.1.1 LOW -- Performance Priority

```
data PrivacyLow = PrivacyLow
  { plCoverTraffic     = Disabled
  , plMessagePadding   = StandardBlock       -- 1024-byte blocks, no extra
  , plTimingDelay      = NoDelay             -- no application-layer delay
  , plTransport        = ClearnetTLS         -- direct TLS to peers
  , plFileTransfer     = DirectStream        -- maximum throughput
  , plGroupSend        = Immediate           -- no inter-recipient delay
  , plTLSRecordPad     = Disabled            -- standard TLS records
  , plBidirectionalPad = Disabled
  }
```

**Privacy guarantee:** Dandelion++ IP obfuscation only. Message size classes visible. Conversation activity visible. No protection against ISP-level or GPA observation beyond encryption.

**Bandwidth overhead:** 0%.
**Latency overhead:** 0ms (Dandelion++ stem latency only: ~370-530ms per `doc/08-dandelion.md`).

#### 11.1.2 MEDIUM -- Balanced (Default)

```
data PrivacyMedium = PrivacyMedium
  { pmCoverTraffic     = Enabled (rate = 1/30 Hz)
  , pmMessagePadding   = RandomizedBlock     -- 0-2 extra dummy blocks
  , pmTimingDelay      = UniformDelay 0 2000 -- U[0, 2000ms]
  , pmTransport        = ClearnetTLS         -- direct TLS to peers
  , pmFileTransfer     = RateLimited         -- normalized file transfer
  , pmGroupSend        = StaggeredDelay 0 5  -- U[0, 5s] between recipients
  , pmTLSRecordPad     = Enabled             -- pad to fixed TLS record sizes
  , pmBidirectionalPad = Enabled (timeout = 10s)
  }
```

**Privacy guarantee:** Cover traffic masks conversation activity (~15% adversary advantage per epoch). Randomized block padding obscures message size. Application-layer delays decorrelate timing. Still vulnerable to ISP identifying UmbraVox usage and GPA stem tracing.

**Bandwidth overhead:** ~2-4x (cover traffic + padding).
**Latency overhead:** +0-2000ms (application delay) + Dandelion++ = ~370-2530ms total.

#### 11.1.3 HIGH -- Maximum Privacy

```
data PrivacyHigh = PrivacyHigh
  { phCoverTraffic     = ConstantRate (rate = 1/5 Hz)
  , phMessagePadding   = FixedSize (blocks = 4)
  , phTimingDelay      = ConstantRate         -- messages queued, sent at fixed intervals
  , phTransport        = TorOnion             -- all traffic via Tor
  , phFileTransfer     = FullyNormalized      -- interleaved with cover, fixed-size chunks
  , phGroupSend        = StaggeredDelay 0 10  -- U[0, 10s] between recipients
  , phTLSRecordPad     = Enabled              -- pad to fixed TLS record sizes
  , phBidirectionalPad = Enabled (timeout = 5s)
  }
```

**Constant-rate transmission algorithm:**

```
constant_rate_loop :: ConstantRateConfig -> TQueue Message -> IO ()
constant_rate_loop cfg queue = forever $ do
  threadDelay (round (1_000_000 / crRate cfg))   -- fixed interval: 200ms at 1/5 Hz -> 5s
  msg <- atomically $ tryReadTQueue queue
  case msg of
    Just real_msg -> send_transaction (pad_fixed real_msg)
    Nothing       -> send_transaction (generate_dummy_tx)
```

Real messages are queued and transmitted at the next fixed-rate slot. If no real message is pending, a dummy is sent. The outbound traffic rate is constant at all times.

**Privacy guarantee:** Constant-rate, fixed-size traffic over Tor. Adversary advantage against a non-global adversary is `negl(lambda)` (Theorem 10.2). GPA resistance depends on Tor's properties.

**Bandwidth overhead:** ~10-20x (constant-rate cover + fixed-size padding + Tor overhead).
**Latency overhead:** Up to 5s (queuing for next slot) + 200-800ms (Tor) + Dandelion++ = ~570-6330ms total.

### 11.2 Privacy Level Selection

```
data NodeConfig = NodeConfig
  { ncPrivacyLevel :: PrivacyLevel      -- LOW | MEDIUM | HIGH
  , ncCustomCoverRate :: Maybe Double    -- override cover traffic rate
  , ncCustomFixedSize :: Maybe Word16    -- override fixed message size (blocks)
  , ncTorProxy :: Maybe SockAddr        -- Tor SOCKS5 proxy address
  }
```

The privacy level is set at node startup and can be changed at runtime. Changing from a lower to a higher level takes effect immediately. Changing from a higher to a lower level drains the constant-rate queue before reducing traffic (preventing a sudden traffic drop that signals the mode change).

### 11.3 Privacy Level Negotiation

During PQXDH session establishment, both parties exchange their privacy level in the encrypted first-message payload. The session operates at the **minimum** of the two parties' levels to prevent one side's cover traffic from being distinguishable against the other's silence:

```
session_privacy :: PrivacyLevel -> PrivacyLevel -> PrivacyLevel
session_privacy a b = min a b    -- LOW < MEDIUM < HIGH
```

If a HIGH-privacy user communicates with a LOW-privacy user, the session operates at LOW privacy. The HIGH-privacy user's cover traffic and fixed-size padding remain active (they are per-node, not per-session), but per-session features (bidirectional padding, staggered group send) degrade to match the lower level.

---

## 12. Implementation Requirements

### 12.1 CSPRNG Usage

All random values in this specification (delays, dummy content, padding, shuffle orders) must be generated from the ChaCha20-based CSPRNG specified in `doc/03-cryptography.md` lines 40-45. No use of system `random()` or non-cryptographic PRNGs.

### 12.2 Dummy Transaction Indistinguishability

**Requirement:** Dummy transactions (`msg_type = 0xFF`) must be computationally indistinguishable from real transactions at every observation point except the block producer's mempool filter.

Verification checklist:
- Same TLS record size as real transactions
- Same Dandelion++ stem behavior (full stem traversal, embargo timer)
- Same transaction envelope structure (valid CBOR, valid-looking but random signature)
- Same block size (1024 bytes)
- Random `sender_id` and `recipient_id` (20 bytes each from CSPRNG)
- `msg_type = 0xFF` is inside the encrypted payload, invisible to network observers

**Note on block producer filtering:** Block producers identify dummies by `msg_type = 0xFF` after decryption of the transaction header. Since dummies use ephemeral keys with no real recipient, they cannot be decrypted by anyone except the block producer performing mempool filtering. The block producer filters them by checking for the `0xFF` type byte at offset 1 of the decrypted payload. Since no real recipient exists, the dummy's "encrypted" payload is actually random bytes with the `0xFF` marker at a position that is only meaningful to the mempool filter.

**Correction:** Dummies are NOT encrypted to any real recipient. They are structured as valid-looking transactions with random ciphertext. The mempool filter identifies them by checking the `dandelion_stem` field in the transaction body, which includes a `is_dummy` flag visible only to the receiving node (set during stem relay). This flag is stripped before gossip to prevent downstream identification.

### 12.3 Test Requirements

| Test | Method | Pass Criteria |
|------|--------|--------------|
| Timing delay distribution | Chi-squared test on 100,000 samples | p > 0.01 against `U[0, 2000ms]` |
| Cover traffic rate | Kolmogorov-Smirnov test on inter-arrival times | p > 0.01 against `Exp(rate)` |
| Dummy indistinguishability | Byte-level comparison of dummy vs. real transaction wire format | No distinguishing feature outside encrypted payload |
| Fixed-size padding correctness | All messages produce exactly `FIXED_MESSAGE_SIZE` blocks | 100% pass rate on 10,000 random messages |
| TLS record size distribution | Histogram of observed TLS record sizes | All records match `TLS_RECORD_SIZES` set |
| Constant-rate regularity (HIGH) | Jitter analysis on outbound transmission times | Coefficient of variation < 0.05 |
| Privacy level negotiation | Session establishment between all level pairs | Session privacy = min(alice, bob) |

### 12.4 Module Traceability

| Defense | Implementing Module |
|---------|-------------------|
| Application-layer delay | `UmbraVox.Network.TimingDefense` |
| Cover traffic generation | `UmbraVox.Network.CoverTraffic` |
| Message padding (random/fixed) | `UmbraVox.Message.Padding` |
| Pattern normalization | `UmbraVox.Network.PatternDefense` |
| TLS record padding | `UmbraVox.Network.TLSPadding` |
| Tor integration | `UmbraVox.Network.TorTransport` |
| Active manipulation detection | `UmbraVox.Network.StemMonitor` |
| Privacy level configuration | `UmbraVox.Config.PrivacyLevel` |
| Constant-rate scheduler | `UmbraVox.Network.ConstantRate` |

---

## 13. Standard References

| Standard/Paper | Relevance |
|---------------|-----------|
| Fanti et al. 2018, "Dandelion++" | Stem/fluff anonymity bounds |
| Murdoch & Danezis 2005, "Low-cost traffic analysis of Tor" | GPA timing correlation on Tor |
| Piotrowska et al. 2017, "Loopix" | Mix network cover traffic model |
| RFC 8446 | TLS 1.3 record padding |
| Dingledine et al. 2004, "Tor: The second-generation onion router" | Onion routing transport |
| Back et al. 2001, "Traffic analysis attacks and trade-offs in anonymity providing systems" | Formal traffic analysis framework |
| Danezis & Syverson 2008, "Bridging and fingerprinting" | Network-layer fingerprinting |
| Mathewson & Dingledine 2004, "Practical traffic analysis" | Active traffic manipulation |
