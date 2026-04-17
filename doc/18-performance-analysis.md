# 18. Performance Analysis

This document provides quantitative analysis of UmbraVox's performance characteristics, including throughput, latency, storage, and bandwidth. All figures are derived from the protocol parameters defined in doc/01-overview.md and doc/04-consensus.md.

## Throughput Analysis

### On-Chain Throughput

The chain's block production rate is determined by the active slot coefficient f and the slot duration:

- Active slot coefficient: f = 0.20 (20% of slots produce a block)
- Slot duration: 11 seconds
- Expected block rate: f / slot_duration = 0.20 / 11s = **0.01818 blocks/second**
- Equivalent: **1 block per ~55 seconds**

Each block carries up to 4,444 message transactions (each at 1 KB). Therefore:

- **Global chain throughput: ~80.8 messages/second**
- Per day: 80.8 × 86,400 = **~6,981,120 messages/day**
- Per 11-day cycle: ~6.98M × 11 = **~76.8 million messages/cycle**
- Full block size: 4,444 × 1,024 = 4,550,656 bytes (**~4.44 MB**)
- Compact block size: **~50-130 KB** (with 95%+ mempool hit rate)

This represents an **808x improvement** over the original spec (~0.1 msg/sec).

### Per-User Throughput Implications

The on-chain capacity is shared across all users. Per-user capacity at different network sizes:

| Users | On-chain msgs/user/day | Assessment |
|-------|----------------------|------------|
| 1,000 | ~6,981 | Abundant — very heavy usage supported |
| 10,000 | ~698 | Comfortable for active messaging |
| 100,000 | ~69.8 | Strong for privacy-focused communications |
| 1,000,000 | ~6.98 | Moderate — sharding extends beyond this |

At ~6.98M messages/day, UmbraVox approaches Signal's estimated volume within one order of magnitude — a strong position for a decentralized, privacy-first, censorship-resistant protocol.

### Dual-Mode Architecture

UmbraVox supports two transport modes. On-chain is primary for censorship resistance; direct P2P is preserved for low-latency, high-throughput conversations.

| Mode | Transport | Latency | Throughput | Censorship Resistance | Privacy |
|------|-----------|---------|------------|----------------------|---------|
| **On-chain** | Dandelion++ → gossip → block inclusion | ~370-530ms + ~55s block wait | ~80.8 msg/sec global | **Strong** | Full: stealth addresses, encrypted headers, fixed fees, uniform blocks |
| **Direct P2P** | TCP + Noise_IK → Signal Double Ratchet | 50-150ms | Unlimited (bandwidth-bound) | **Weak** — both peers must be online | Content encrypted; IP exposed to peer without Tor |

### Further Scaling Options (beyond 1M users)

| Improvement | Additional Gain | Resulting msgs/sec | msgs/day |
|---|---|---|---|
| Increase f (0.20→0.40) | 2x | ~161.6 | ~14.0M |
| Sharding (11 shards) | 11x | ~889 | ~76.8M |
| f=0.40 + 11 shards | 22x | ~1,778 | ~153.6M |

With 11 shards + f=0.40: **~153.6M msgs/day**, supporting ~22M+ users at ~7 msgs/user/day.

## Latency Analysis

### Message Propagation Latency (P50)

End-to-end latency from sender submission to recipient receipt, assuming the message is an on-chain transaction:

| Phase | Calculation | Latency |
|-------|-------------|---------|
| Dandelion++ stem phase | 2-4 hops * ~80ms RTT per hop | 160-320ms |
| Fluff gossip propagation | ~3 hops to reach 90% of a 25-peer network * ~65ms per hop | ~200ms |
| Local processing | Deserialization, validation, decryption | ~10ms |
| **Total P50** | | **370-530ms** |

The stem phase dominates variance. With 2 stem hops (best case), total latency is ~370ms. With 4 stem hops (worst case for P50), total latency is ~530ms.

### Tail Latency (P99)

Under adverse network conditions:

| Phase | Worst case | Latency |
|-------|------------|---------|
| Dandelion++ stem phase | 4 hops * 200ms (congested RTT) | 800ms |
| Fluff gossip propagation | 5 hops * 200ms (sparse network) | 1,000ms |
| Local processing | Validation under load | ~50ms |
| **Total P99** | | **~1,850ms** |

Under severe network congestion (packet loss, retransmissions), P99 can reach up to **5 seconds**. This includes TCP retransmission delays and Noise protocol re-handshakes.

### Settlement Latency (Two-Tier Model)

Different operation types have different finality requirements:

| Tier | Operations | k | Settlement Time | Reversal Odds |
|------|-----------|---|----------------|---------------|
| **Message tier** | Encrypted messages, prekey bundles | k=11 | ~10 min | 1 in 2,048 |
| **Value tier** | Token transfers, stake ops, validator registration | k=22 | ~20 min | 1 in 4.2 million |

- Expected time per block: 1/0.01818 ≈ 55 seconds
- Message tier: k=11 × 55s = **~10 minutes**
- Value tier: k=22 × 55s = **~20 minutes**

For messaging purposes, recipients see the message at propagation latency (~400ms) but should not consider it irrevocable until k=11 depth. Token transfers require k=22 depth. Validators cannot spend block rewards until k=22.

### Direct P2P Latency

Messages exchanged through established Signal sessions over direct peer-to-peer connections bypass the chain entirely:

- Direct peer RTT: ~50-150ms (depending on geographic distance)
- Encryption/decryption: ~1ms
- **Off-chain message latency: ~50-150ms**

This is comparable to Signal's latency for direct messages.

## Storage Analysis

### Per-Epoch Chain Data

Each epoch spans 3,927 slots (12 hours at 11s/slot):

- Blocks per epoch: 3,927 × 0.20 = ~785 blocks
- Block size: ~4.44 MB (4,444 × 1,024 = 4,550,656 bytes)
- **Chain data per epoch: 785 × 4,550,656 bytes = ~3.57 GB**

### Per-Cycle Chain Data

Each cycle spans 22 epochs (11 days):

- **Chain data per cycle: 22 × 3.57 GB = ~78.5 GB**

### State Database

The state DB maintains account balances, staking records, and nonces. It persists across truncation:

- Account record: ~64 bytes (public key hash + balance + nonce + stake metadata)
- At 500,000 accounts: **500,000 * 64 bytes = ~32 MB**

### Key Registry

The key registry stores identity keys, signed prekeys, and references to one-time prekey bundles:

- Per-user key data: ~200 bytes (Ed25519 identity key + X25519 signed prekey + ML-KEM-768 prekey + OPK references)
- At 500,000 users: **500,000 * 200 bytes = ~100 MB**

### Write-Ahead Log (WAL)

The WAL buffers writes during normal operation and peaks during truncation when the state snapshot is written atomically:

- **WAL peak during truncation: ~50 MB**
- Normal operation WAL: ~5-10 MB

### Storage Summary

| Component | Size |
|-----------|------|
| Chain data (1 cycle) | ~78.5 GB |
| State DB (500K accounts) | ~32 MB |
| Key registry (500K users) | ~100 MB |
| WAL peak | ~50 MB |
| **Subtotal (operational)** | **~78.7 GB** |
| Indexes, Signal session files, headroom | ~3 GB |
| **Total steady-state estimate** | **~80 GB** |

The ~80 GB estimate is commodity SSD territory. Post-truncation, all chain data from the previous cycle is deleted, bounding disk usage at ~80 GB regardless of node age.

## Bandwidth Analysis

### Baseline (Steady State)

With compact block relay enabled and ~25 gossip peers:

| Traffic type | Calculation | Rate |
|---|---|---|
| Block relay (compact) | ~1 block/55s × ~90 KB avg × relay factor ~3 | ~5 KB/s |
| Transaction relay | ~80.8 tx/s × 1 KB × relay factor ~3 | ~242 KB/s |
| Block headers/advertisements | ~0.018/s × 200 bytes × 25 peers | ~0.09 KB/s |
| Peer management | ~50 bytes/peer/10s × 25 peers | ~0.125 KB/s |
| **Total baseline** | | **~270 KB/s** |

With protocol overhead (Noise encryption, TCP headers): **~400 KB/s minimum** per node.

**Compact block relay is mandatory.** Without it, full ~4.44 MB blocks would require ~11.1 seconds per hop at 400 KB/s — exceeding the 11-second slot. With CBR, compact blocks (~50-130 KB) propagate in ~0.13-0.33s per hop, providing ~10 seconds of margin within the slot.

### Dandelion++ Overhead

Stem-phase relay adds minimal overhead because each node relays a transaction to at most one stem peer:

- Stem relay: ~1 KB per relayed transaction
- Transaction rate: ~0.1 tx/s, but a given node only relays a fraction
- Per-epoch stem traffic: ~100 transactions * ~50% relay probability * 1 KB = **~50 KB/epoch**
- Rate: ~50 KB / 43,200s = **~0.001 KB/s — negligible**

### Cover Traffic

Cover traffic (dummy transactions to mask real transaction timing):

- Rate: 1 dummy transaction per 600 seconds
- Size: 1 KB per dummy
- **Rate: 1 KB / 600s = ~1.7 bytes/s per node — negligible**

### Peak Bandwidth (Initial Sync)

A new node joining the network must download the current cycle's chain data:

- Data to sync: up to ~78.5 GB (full cycle)
- Target sync time: using full blocks from multiple peers
- **Peak bandwidth: ~5 MB/s** (parallel download from 16 peers)

For a partial-cycle sync (node was offline for one epoch):

- Data to sync: ~3.57 GB
- **Bandwidth: ~3.57 GB / 300s = ~11.9 MB/s** (or slower over longer window)


## Early Truncation Performance Impact

When early truncation fires (circulating supply drops below threshold at an epoch boundary), the network enters the snapshot phase immediately:

**Throughput impact:**
- Chat transaction throughput drops to 0 during snapshot phase (~1,100 seconds / ~100 slots)
- Block production continues for snapshot attestation purposes
- Off-chain Signal sessions are unaffected (continue operating normally)

**Latency impact:**
- Pending mempool transactions are held until the new cycle begins
- Maximum delay: snapshot phase (~1,100 seconds) + truncation execution (~100 seconds) = ~20 minutes
- Settlement of in-flight transactions: deferred to new cycle (transactions with old epoch_nonce become invalid; senders must resubmit)

**Frequency:**
- Under normal conditions (network growing steadily), early truncation should fire <1% of cycles
- The adaptive controller reduces burn rate after early truncation, making subsequent early truncations less likely
- Worst case: if early truncation fires every cycle, the adaptive controller drives burn rate toward the 20% floor, eventually stabilizing cycle duration

**Recovery:**
- New cycle begins with full supply restoration and adjusted parameters
- Validators and users resume operations immediately after truncation completes
- No data loss beyond the normal truncation behavior (message ciphertext destroyed, staked balances preserved)

**Network partition interaction:**
- Early truncation requires the same 2/3+ attestation as normal truncation
- If a partition prevents attestation, the same failure handling applies (extend snapshot, carry forward if needed)

## Comparison Table

### Commercial Comparison

| Service | Daily Messages | msgs/sec | vs. UmbraVox |
|---------|---------------|----------|--------------|
| WhatsApp | ~100 billion | ~1,150,000 | 14,300x larger |
| WeChat | ~45 billion | ~520,000 | 6,450x larger |
| iMessage | ~40 billion | ~460,000 | 5,720x larger |
| Telegram | ~15 billion | ~175,000 | 2,150x larger |
| SMS (global) | ~6 billion | ~70,000 | 860x larger |
| Signal (est.) | ~50-100M | ~600-1,200 | 7-14x larger |
| **UmbraVox** | **~6.98M** | **~80.8** | **baseline** |
| UmbraVox (old) | ~8,640 | ~0.1 | 808x smaller |

### Protocol Comparison

| Property | UmbraVox | Signal | Matrix | Session |
|---|---|---|---|---|
| **Throughput** | ~80.8 msgs/s (on-chain) + unlimited (P2P) | ~1,000+ msgs/s (per server) | ~100s msgs/s (per homeserver) | ~100s msgs/s (per swarm) |
| **Propagation latency (P50)** | 370-530ms (on-chain); 50-150ms (P2P) | 50-200ms | 100-500ms | 1-5s |
| **Settlement latency** | ~10 min (messages, k=11) / ~20 min (value, k=22) | Instant (server ACK) | Instant (server ACK) | ~10-30s |
| **Storage per node** | ~80 GB (steady state) | N/A (server: TBs) | Server: 10s-100s GB | Service Node: ~10 GB |
| **Bandwidth per node** | ~400 KB/s baseline | N/A (client: ~1-5 KB/s) | Server: ~100s KB/s | Service Node: ~50-100 KB/s |

### Key Observations

1. **808x throughput improvement over original spec.** The redesign moves UmbraVox from ~0.1 msg/sec to ~80.8 msg/sec, approaching Signal's estimated volume within one order of magnitude.

2. **Compact block relay is mandatory.** Without CBR, ~4.44 MB blocks cannot propagate within the 11-second slot. With CBR (~50-130 KB compact blocks), propagation completes in ~0.4-1.0s across 3 hops — massive headroom.

3. **Two-tier settlement balances latency and security.** Messages (encrypted, low reorder impact) settle at k=11 (~10 min). Value transfers settle at k=22 (~20 min, comparable to Bitcoin 6-conf).

4. **~80 GB storage is commodity SSD territory.** ~40x the original ~2 GB spec, but well within reach of standard hardware.

5. **~400 KB/s bandwidth is standard broadband.** Accessible on mobile connections and comparable to video streaming.

6. **Dual-mode architecture preserves flexibility.** On-chain for censorship resistance, direct P2P for low-latency — users choose based on threat model.
