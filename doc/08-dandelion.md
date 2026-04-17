# Dandelion++ IP Obfuscation

## Parameters

| Parameter | Value |
|-----------|-------|
| Epoch duration | 600 seconds |
| Fluff probability | 0.10 per hop |
| Embargo min/max | 5s / 30s |
| Relay peers | 4 (outbound only) |
| Node mode probability | 50% relayer, 50% diffuser |
| Stem pool max size | 2,000 transactions |
| Cover traffic | 1 dummy stem per 600s per node (configurable up to 1/5 Hz) |

## Relay Peer Selection Algorithm

At each Dandelion epoch (600s), a node selects 4 relay peers uniformly at random from current outbound connections. Minimum 8 outbound connections required.

- Selection uses ChaCha20-based CSPRNG seeded with `epoch_nonce || node_privkey`.
- If fewer than 4 outbound connections are available, use all outbound peers as relays.
- The 5th peer in the selection order serves as the backup relay (see Failsafe Mechanisms).

## Algorithm

```
on_create_local_tx(tx):
  wrap as STEM_TX
  forward to relay_peers[random_selection()]  -- randomized, not deterministic
  set embargo timer (5-30s random)

on_receive_stem_tx(tx, from_peer):
  if self.mode == Diffuser:
    fluff(tx)  -- standard gossip broadcast
  else:
    forward to own relay peer (avoiding from_peer)
    set embargo timer

on_embargo_expired(tx):
  if tx not yet seen as fluffed:
    fluff(tx)  -- failsafe
```

## Formal Anonymity Bound

Citing Fanti et al. 2018 ("Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees"):

For a network with fraction `f` adversarial nodes using 4 relay peers with geometric stem length (`p_fluff` = 0.10), deanonymization probability is bounded by:

- **Passive adversaries**: O(f^2)
- **Active adversaries**: O(f)

With f = 0.10 (10% adversarial nodes): passive deanonymization probability <= 1%, active <= 15%.

## Block Propagation

Blocks NEVER use Dandelion++ stem -- always standard gossip. Only individual chat transactions use the stem phase. This ensures block propagation latency is not affected by anonymization.

## Epoch Lifecycle

Every 600 seconds (+/- 15s jitter to desynchronize nodes):
1. Select 4 new relay peers from outbound connections (see Relay Peer Selection Algorithm)
2. Flip coin for node mode (relayer vs diffuser)
3. Flush any remaining stempool entries to fluff
4. Install new epoch state

## Failsafe Mechanisms

- **Embargo timer**: If stem relay drops the tx, originating node fluffs after 5-30s. Timer drawn uniformly at random in [5, 30] seconds, independently per transaction from ChaCha20 CSPRNG.
- **Per-hop timeout**: 2s per stem hop; if peer unreachable, try alternate relay
- **Backup relay**: After 1.5x expected stem hop time (1.5 * 2s = 3s), if transaction has not appeared in fluff gossip, send to backup relay (5th peer in selection). Node detects fluff appearance by monitoring gossip layer for matching transaction hash.
- **Epoch boundary flush**: All stempool entries fluffed at epoch transition

## Stem Pool Eviction

When the stem pool reaches its 2,000 transaction cap, evict the oldest-received transaction first (FIFO). Evicted transactions are fluffed immediately (broadcast to gossip). This preserves delivery while sacrificing some anonymity for the evicted transaction.

## Expected Latency

| Component | Expected |
|-----------|----------|
| Stem traversal (2-4 hops) | 160-320ms |
| Fluff propagation | ~200ms |
| **Total send-to-display** | **~370-530ms** |

## Formal Anonymity Quantification (DO-178C DAL A)

- Anonymity set size must be measured under adversarial simulation
- Target: deanonymization probability < 15% with 10% adversarial nodes
- Simulation: 1000-node network, 100 adversarial, 10,000 messages
- Deliverable: statistical bounds in `test/evidence/dandelion-anonymity/`

## Cover Traffic

- Each node sends 1 dummy stem transaction per 600 seconds (configurable: operators may increase rate up to 1 per 5 seconds for higher anonymity at increased bandwidth cost)
- Dummy transactions use `msg_type` 0xFF (DUMMY). Not included in blocks by producers (filtered at mempool entry). Cost: 0 MTK (no fee, not on-chain).
- Indistinguishable from real stem transactions to relay peers (encrypted with ephemeral key, same size as real 1K block, random recipient)
- Prevents traffic analysis distinguishing active from silent nodes
- Can be disabled via config for resource-constrained nodes

## IP Obfuscation by Transport Mode

### On-Chain Messages

On-chain messages benefit from multiple layers of IP obfuscation:

1. **Application-layer random delay**: U[0, 2000ms] before Dandelion++ entry
2. **Dandelion++ stem**: 2-4 hops through relay peers, ~160-320ms
3. **Fluff gossip**: Standard broadcast, origin indistinguishable from relay nodes
4. **Cover traffic**: 1 dummy stem per 600s (configurable up to 1/5 Hz)
5. **Optional Tor**: All peer connections routable via SOCKS5 → .onion addresses

**Result**: An observer sees the transaction appear from a random gossip node, not the originator.

### Direct P2P Connections

Direct peer-to-peer connections (for low-latency messaging over established Signal sessions) have different IP properties:

1. **Noise_IK** encrypts all traffic (X25519 + ChaChaPoly)
2. **Per-session rekeying** every 1,000 messages or 10 minutes
3. **IP address IS visible** to the direct peer (unavoidable without relay)
4. **Optional Tor**: Route P2P connections through Tor circuits for IP hiding

**Result**: Content is fully hidden, but the peer knows your IP unless using Tor.

## Interaction with 11-Day Truncation

Dandelion++ operates within epochs (600s), independent of chain cycles (11 days). At chain truncation boundary, the stem pool is flushed to fluff (all pending stems broadcast). A new Dandelion epoch begins with fresh relay selection.

## Security

- Relay peers selected from outbound connections only (prevents forced-inbound Sybil)
- Randomized relay selection provides stronger anonymity than deterministic hash-based selection
- With 4 relay peers, the anonymity graph approaches quasi-8-regular connectivity
- Adversary controlling fraction `f` of network cannot deanonymize source with probability better than `O(f)` (active) or `O(f^2)` (passive)

## Standard References

- Fanti et al. "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees" (ACM SIGMETRICS 2018)
- Bojja Venkatakrishnan et al. "Dandelion: Redesigning the Bitcoin Network for Anonymity" (ACM SIGMETRICS 2017)
