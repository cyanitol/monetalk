# P2P Network Layer

## Topology

- **Kademlia DHT** for peer discovery (node_id = SHA-256(pubkey))
  - k-bucket size = 20
  - Alpha (parallelism) = 3
  - Refresh interval = 1 hour
  - ID space: SHA-256(Ed25519_pubkey)
  - Record TTL: 24 hours
  - Republish interval: 1 hour
- **Unstructured gossip mesh** for data propagation
- Target: 25 peers (min 8, max 50, min 8 outbound)

## Transport

- TCP with hand-implemented Noise_IK handshake (X25519 + ChaChaPoly)
  - Prologue = `"UmbraVox_v1"`
  - DH function: X25519
  - Cipher: ChaChaPoly
  - Hash: SHA-256
  - Per-session keys derived from Noise handshake output via HKDF
- **Version negotiation**: During the `HANDSHAKE` message (sent immediately after Noise_IK completes), each node announces its software version as a `(major, minor, patch)` tuple and the chain revision number it is currently operating on. A node MUST reject and disconnect any peer whose software version is more than 3 minor releases behind the current release. Chain revision compatibility is enforced separately at the consensus layer (see doc/04-consensus.md) — nodes reject blocks from chain revisions more than 3 behind current. Software versions and chain revisions are independent: a software release may support multiple chain revisions, and a chain revision bump does not require a software update if the node already supports it.
- Multiplexed logical streams: control, blocks, transactions, consensus, Dandelion++ stem

## Peer Discovery

1. **Bootstrap nodes**: Hardcoded seed nodes for initial DHT entry
   - **DNS seed discovery**: Resolve TXT record at `_UmbraVox._tcp.seeds.UmbraVox.network` for dynamic seed list
   - **Bootstrap fallback**: If all hardcoded seed nodes are unreachable after 60 seconds, the node enters **manual bootstrap mode**. The user can provide a peer address via CLI (`--bootstrap-peer <addr>`) or API (`POST /admin/bootstrap`).
2. **Peer exchange (PEX)**: Periodic peer list exchange
   - Max 1 PEX request per peer per 120 seconds
   - Responses capped at 50 addresses
   - Addresses include timestamp; ignore if older than 3 hours
   - Violations (exceeding rate limit): -10 peer score
3. **Outbound-only connections**: Nodes connect outbound to discovered peers. No NAT traversal is performed. Validators with public IPs are recommended for better network health but not required. All nodes participate in gossip via outbound connections.

## Block Relay

V1 uses **compact block relay** (mandatory at 4,444 messages per block). Compact block relay (inspired by Bitcoin's BIP 152) reduces block propagation time by exploiting mempool overlap.

### How Compact Block Relay Works

**Block producer** sends a compact block (~50-130 KB) containing:
- Block header (~200 bytes)
- Short transaction IDs (SipHash-2-4, 6 bytes each × 4,444 = ~26.7 KB)
- Prefilled transactions (only new txns not yet in mempool, typically 0-5%)

**Receiving peer**:
1. Matches short IDs against local mempool (~1ms)
2. Reconstructs full block from mempool transactions
3. If missing any transactions, requests them individually (`GET_DATA`)
4. Validates reconstructed block

### Performance

| Metric | Without CBR | With CBR | Improvement |
|--------|------------|----------|-------------|
| Data per relay hop | ~4.44 MB (4,550,656 bytes) | ~50-130 KB (95%+ mempool hit) | 34-89x smaller |
| Propagation time per hop | ~11.1s at 400 KB/s | ~0.13-0.33s | 34-89x faster |
| Network-wide (3 hops) | ~33.3s (fails!) | ~0.4-1.0s | Fits within slot |

**Critical**: Without CBR, 4,444-message blocks cannot propagate within the 11-second slot. CBR is mandatory.

### Operational Modes

- **High bandwidth mode** (default for validators): Send compact block immediately upon receipt. Minimizes propagation latency.
- **Low bandwidth mode** (optional for light nodes): Send `INV` first; peer requests compact block only if interested. Reduces unsolicited bandwidth.

### Full Block Fallback

New or syncing nodes download full ~4.44 MB blocks. At ~400 KB/s minimum bandwidth, this takes ~11.1 seconds — acceptable for initial sync but not for relay-critical paths.

## Eclipse Attack Prevention

- Min 8 outbound connections (node-initiated)
- Max 2 connections per /16 subnet
- Bucketed address tables (new + tried)
- Anchor connections persisted across restarts
- Node ID bound to public key (prevents cheap Sybil ID generation)

## Peer Scoring

| Event | Score Change |
|-------|-------------|
| Valid block relayed first | +10 |
| Valid tx relayed first | +5 |
| Successful block relay (first seen) | +2 |
| Per hour of sustained connection | +1 |
| Invalid block or transaction | -50 |
| Protocol violation | -20 |
| Request timeout | -10 |
| PEX rate limit violation | -10 |
| Version too old (>3 behind) | immediate disconnect |
| 3+ invalid blocks in 1 hour | -100 (immediate ban) |

**Thresholds**: Below 0 = disconnect + 1h ban. Below -200 = 24h ban. Above 200 = preferred peer, exempt from eviction.

## Wire Protocol Messages

```
Control:     HANDSHAKE, PING/PONG, PEX_REQUEST/RESPONSE, DISCONNECT
Inventory:   INV, GET_DATA, NOT_FOUND
Blocks:      BLOCK_ANNOUNCE, FULL_BLOCK, COMPACT_BLOCK, GET_BLOCK_TXNS, BLOCK_TXNS, GET_HEADERS, HEADERS
Transactions: TX, TX_ANNOUNCE
Consensus:   STAKE_ANNOUNCE, VOTE, EPOCH_BOUNDARY
Dandelion:   DANDELION_TX (stem phase)
Truncation:  TRUNCATION_CHECKPOINT, GET_CHECKPOINT, CHECKPOINT_RESPONSE
```

**Message size limits**:

- Max message size per stream: 5 MB
- `INV` message: array of `(type: uint8, hash: 32 bytes)`, max 500 entries
- `GET_DATA`: same format as `INV`

## Chain Sync Protocol

- `GET_HEADERS(from_hash, count)` → `HEADERS([BlockHeader])`
- Node requests headers from last known hash, validates VRF proofs and signatures, then requests missing blocks via `GET_DATA`
- Parallel download: up to 16 concurrent block requests

## Bandwidth Estimates

UmbraVox bandwidth estimates with compact block relay enabled:

| Traffic type | Calculation | Rate |
|---|---|---|
| Block relay (compact) | ~1 block/55s × ~90 KB avg × relay factor ~3 | ~5 KB/s |
| Transaction relay | ~80.8 tx/s × 1 KB × relay factor ~3 | ~242 KB/s |
| Block headers/advertisements | ~0.018/s × 200 bytes × 25 peers | ~0.09 KB/s |
| Peer management | ~50 bytes/peer/10s × 25 peers | ~0.125 KB/s |
| Slot/epoch protocol messages | ~100 bytes/slot × 1/11s | ~0.009 KB/s |
| **Total baseline** | | **~270 KB/s** |

With protocol overhead (Noise encryption framing, TCP headers): approximately **~400 KB/s** minimum per node.

- Spikes during sync or high-traffic periods: up to **~5 MB/s**
- Block propagation (compact) to 95% of network: < 1 second
- Full block propagation for syncing nodes: ~11 seconds at minimum bandwidth

## Connection Model

All nodes connect **outbound only**. No NAT traversal (UPnP, STUN, hole punching, relay) is performed in v1.

- Nodes behind NAT can fully participate by maintaining outbound connections to peers discovered via DHT and PEX.
- Validators with public IPs are recommended for better network health (they can accept inbound connections from NATed peers), but public reachability is not required.
- A node that cannot establish at least 8 outbound connections after 5 minutes logs a warning and retries bootstrap discovery.

## Dual-Mode Transport

UmbraVox supports two transport modes. On-chain is primary; direct P2P is preserved for low-latency use.

| Mode | Transport | Latency | Throughput | Censorship Resistance |
|------|-----------|---------|------------|----------------------|
| **On-chain** | Dandelion++ → gossip → block inclusion | ~370-530ms + ~55s block wait | ~80.8 msg/sec global | **Strong** — no single point of censorship |
| **Direct P2P** | TCP + Noise_IK → Signal Double Ratchet | 50-150ms | Unlimited (bandwidth-bound) | **Weak** — requires both peers online, IP visible to peer |

### Direct P2P Protocol

Direct peer-to-peer connections use the same Noise_IK transport as gossip connections but carry Signal Double Ratchet messages directly between peers:

- Noise_IK handshake establishes encrypted channel (X25519 + ChaChaPoly)
- Per-session rekeying every 1,000 messages or 10 minutes
- Content encrypted via Signal Double Ratchet (same as on-chain messages)
- IP address visible to direct peer (unavoidable without relay)
- Optional Tor: route through SOCKS5 → .onion for IP hiding

## Multiplexing Priority

Stream priority (highest first):

1. **Consensus** (VOTE, EPOCH_BOUNDARY, STAKE_ANNOUNCE)
2. **Blocks** (BLOCK_ANNOUNCE, FULL_BLOCK)
3. **Dandelion stem** (DANDELION_TX)
4. **Transactions** (TX, TX_ANNOUNCE)
5. **Control** (HANDSHAKE, PING/PONG, PEX, DISCONNECT)

Implementation: weighted fair queuing with strict priority for consensus.
Starvation prevention: lower-priority streams guaranteed 10% bandwidth minimum.

## Noise_IK Forward Secrecy

- Handshake provides initial forward secrecy (ephemeral X25519)
- Per-session rekeying: every 1,000 messages OR every 10 minutes, whichever comes first
- Rekeying uses fresh ephemeral DH (not derived from prior keys)
- Old session keys zeroized after rekey (secure deletion)
- **Rekeying failure**: If rekey handshake fails 3 times, terminate connection and reconnect with fresh handshake

## Peer Scoring Validation (DO-178C DAL A)

- Scoring thresholds must be validated via network simulation
- False positive rate target: <0.1% honest nodes incorrectly banned per epoch
- Simulation: 1000 nodes, 10% adversarial, 100 epochs
- Score values calibrated from simulation results, not hardcoded assumptions

## References

- Noise Protocol Framework (Perrin, 2018)
- Kademlia (Maymounkov & Mazieres, 2002)
- BIP 152 (Compact Block Relay) — enabled in V1
