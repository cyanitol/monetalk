# Security Model

## Formal Threat Model

Adversary controls up to **f < 1/3 of total stake** (consensus attacks) and up to **f' < 0.5 of network nodes** (network-layer attacks — different thresholds). Adversary is computationally bounded (PPT). Quantum adversary assumed for harvest-now-decrypt-later scenarios (PQ wrapper addresses this).

## Threat Summary

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Passive eavesdropper | Signal Double Ratchet + PQ wrapper | Low |
| Harvest-now-decrypt-later (quantum) | ML-KEM-768 outer wrapper | Medium |
| Key compromise | Forward secrecy (ratchet), post-compromise security | Medium |
| IP deanonymization | Dandelion++ | Medium |
| On-chain metadata (sender/recipient) | Stealth addresses (DKSAP), encrypted headers, fixed fees, uniform blocks, address rotation | **LOW** (V1 mitigated) |
| Spam/DoS | Token economics, punitive multipliers | Low |
| 51% stake attack | PoS economic design, minimum stake | Low-Medium |
| Eclipse attack | Peer diversity, outbound minimums | Medium |
| Loss of deniability | No content signatures, symmetric MACs only, 11-day truncation | Medium |
| Chain splits across truncation | 2/3+ validator attestation, accumulated hash | Low |
| Archival node (persistent data retention) | Stealth addresses + encrypted headers make archived data opaque; archival observer sees only uniform encrypted blocks with one-time addresses | **MEDIUM** |
| Validator collusion (1/3 stake) | Selective censorship; timeout + forced inclusion | Medium |
| Session state compromise (disk access) | Encrypted key store + passphrase-derived HKDF | Medium |
| Clock desynchronization | NTP + peer-median + ±1s tolerance | Medium |
| Crypto timing side-channels | FFI to constant-time C for production; pure Haskell for verification only | Medium |
| Transaction ordering / MEV | Deterministic per-block ordering by tx hash | Low |
| Supply depletion attack (force early truncation) | Adaptive controller + cost exceeds benefit | Low |
| Adaptive parameter manipulation | Parameters set via software/chain revision; not runtime-adjustable | Low |

## Adversary Classes

| Class | Capability |
|-------|-----------|
| Passive eavesdropper | Observes network traffic at ISP/backbone level |
| Active network attacker | Can inject, drop, delay, or modify packets |
| Malicious node operator | Runs full nodes; sees all on-chain data and gossip |
| State-level adversary | Combines all above; harvest-now-decrypt-later |
| Sybil attacker | Creates many fake node identities |
| Economic attacker | Manipulates token flows and stake accumulation |
| Archival adversary | Runs permanent full node, never deletes data; correlates metadata across cycles |

## Deniability Architecture

UmbraVox provides **message content deniability** and **partial communication deniability**:

- Blockchain Ed25519 signature covers `SHA-256(encrypted_blob || epoch_nonce)` — the signed data does NOT contain `sender_id` in plaintext. The `sender_id` is inside the encrypted blob.
- On-chain transactions use one-time stealth addresses (DKSAP) for recipients and rotating sender addresses, preventing linkage of messages to persistent identities.
- Signal uses only HMAC (symmetric) for message authentication
- PQ wrapper uses only AES-GCM (symmetric)
- No asymmetric signatures on message content anywhere in the stack
- 11-day truncation destroys chain records (but archivers remain a threat)
- Wallet resets with new addresses sever cross-epoch identity links

**Summary**: An adversary cannot produce a cryptographic proof of *what was said* (content deniability holds), and on-chain metadata protections (stealth addresses, address rotation, uniform transactions) prevent construction of a communication graph from on-chain data alone. Network-level observers with auxiliary information may still achieve partial deanonymization.

### On-Chain Metadata Protection (V1)

All privacy mitigations are included in V1. No metadata leakage is accepted at launch.

| Field | Without Protection | V1 Protection |
|-------|-------------------|---------------|
| `recipient_id` | Cleartext hash — links all msgs to same recipient | **Stealth addresses (DKSAP)** — fresh one-time address per message |
| `sender_addr` | Cleartext hash — links all msgs from same sender | **Address rotation** per epoch or per message |
| `msg_type` | Cleartext byte — reveals TEXT vs KEY_EXCHANGE | **Encrypted inside payload** — all blocks look identical externally |
| `fee` | Cleartext uint64 — correlates with message size | **Fixed fees** — all transactions pay identical amount |
| `total_blocks` | Cleartext — reveals message size class | **Uniform size** — all messages padded to fixed block count |
| `timestamp` | ms precision — timing correlation | **Inside encrypted payload** — only slot-level timing (11s granularity) visible |
| `msg_number` | Cleartext — reveals per-session frequency | **Inside encrypted payload** |
| `signal_ratchet_pubkey` | Cleartext — links msgs in same ratchet epoch | **Inside encrypted payload** |

**Result**: A blockchain observer sees only uniform-sized, uniform-fee, encrypted blocks with one-time stealth addresses and rotating sender addresses. No communication graph is constructible from on-chain data alone.

## PQ Cryptographic Security Levels

- **ML-KEM-768**: NIST PQC Category 3 security (equivalent to AES-192)
- **AES-256-GCM**: Category 5 (classical) and Category 1 (quantum, Grover's)
- **Combined system**: Category 3 quantum security

## Transaction Ordering Attacks

Validators can observe and reorder mempool transactions. Impact on UmbraVox is **LOW** because:

1. Messages are encrypted, so content-based ordering provides no advantage
2. Token transfers use account nonces preventing replay
3. No DeFi-style arbitrage opportunities

**Residual risk**: Timing-based correlation (validator sees Alice's message to Bob, includes own message to Bob in same block).

**Mitigation**: Per-block transaction ordering is deterministic by transaction hash (not validator-chosen).

### Supply Depletion Attack

**Threat**: An attacker burns tokens rapidly by sending high volumes of messages, attempting to force early truncation and disrupt the network.

**Analysis**: To deplete circulating supply from 100% to 15% (triggering early truncation), the attacker must burn 85% of the initially distributed spendable tokens. With a 65% burn rate, this requires spending approximately `0.85 * distributed_supply / 0.65` MTK in fees — far exceeding any individual actor's holdings.

At minimum fee (10 MTK, 65% burn = 6.5 MTK burned per message):
- To burn 1B MTK: ~154M messages required, costing ~1.54B MTK
- Network fee escalation via EMA makes sustained spam exponentially more expensive

**Mitigation**:
- Early truncation is a **graceful degradation**, not a failure — the network snapshots, restores supply, and continues
- The adaptive controller reduces burn rate for the next cycle, making repeat attacks harder
- The attacker loses real MTK with no economic return
- EMA fee escalation dramatically increases cost of sustained spam

**Residual Risk**: Low. The cost of forcing early truncation exceeds any achievable benefit. Each cycle resets, so the attacker's damage is limited to one shortened cycle.

### Adaptive Parameter Manipulation

**Threat**: A sophisticated attacker attempts to influence economic parameters (burn rate, fee floor, etc.) to create favorable conditions for spam or supply depletion.

**Analysis**: Treasury and economic parameters (burn rate, fee schedule, cycle duration targets) are set via software or chain revision, not via on-chain governance or runtime adjustment. There is no voting mechanism or governance contract to exploit. Parameter changes require a new software release accepted by the validator set.

**Mitigation**:
- No on-chain governance or voting mechanism exists; parameters are compile-time or chain-revision constants
- Hard parameter bounds are enforced in code (burn rate cannot go below 20%)
- Parameter changes require validator supermajority to adopt the new chain revision
- No runtime API or transaction type can alter economic parameters

**Residual Risk**: Low. An attacker would need to compromise the software supply chain or convince a supermajority of validators to adopt a malicious revision.

## Security Properties Achieved

| Property | Mechanism | Confidence |
|----------|-----------|------------|
| Confidentiality | Signal Double Ratchet + PQ wrapper | High |
| Integrity | Signal MAC + blockchain consensus | High |
| Authentication | Signal identity keys + initial key verification | High |
| Forward secrecy | Signal DH ratchet + PQ ratchet | High |
| Post-compromise security | Signal DH ratchet healing | High |
| Sender anonymity (network) | Dandelion++ | Medium |
| Receiver anonymity (network) | All nodes receive all blocks | High |
| Message content deniability | Symmetric MACs only, no content signatures | High |
| Communication deniability | Stealth addresses + address rotation + uniform transactions | Medium-High |
| Anti-spam | Token economics | Medium-High |
| Economic resilience | Universe Cycle + adaptive controller | High |

## On-Chain Metadata: Resolved in V1

All on-chain metadata protections — stealth addresses (DKSAP), encrypted header fields, fixed fees, uniform transaction sizing, and sender address rotation — are included in V1. The communication graph is not constructible from on-chain data. See `doc/hardening/03-stealth-addresses.md` and `doc/hardening/14-metadata-minimization.md` for full specifications.

## DO-178C DAL A Threat Analysis

All threats in the matrix must have:

- **Formal threat description with attack preconditions**: Each threat entry must specify the adversary class, required capabilities, and environmental conditions that enable the attack.
- **Mitigation with traceability to specific code module**: Each mitigation must reference the exact source module (e.g., `UmbraVox.Crypto.Signal.Ratchet`, `UmbraVox.Consensus.VRF`) that implements the defense.
- **Residual risk quantification (probability + impact)**: Each residual risk rating must be decomposed into probability (likelihood of successful exploitation) and impact (consequence severity), using a 5-level scale for each.
- **Test case verifying mitigation effectiveness**: Each mitigation must have at least one test case ID that demonstrates the defense works under adversarial conditions.

Deliverable: full threat-mitigation traceability matrix in `doc/requirements-trace.md`

## Formal Methods Requirement

DO-333 supplement applies to all DAL A components.

Required formal proofs:

1. **Signal + PQ wrapper composition security** (Coq or TLA+): Prove that the composed encryption scheme preserves confidentiality, integrity, forward secrecy, and post-compromise security when Signal Double Ratchet is wrapped with the PQ outer layer.
2. **Consensus safety/liveness** (TLA+): Prove that the PoS consensus protocol satisfies safety (no two honest validators finalize conflicting blocks) and liveness (transactions are eventually included) under the assumption of <1/3 Byzantine stake.
3. **Token conservation invariant** (QuickCheck + formal proof): Prove that total token supply is conserved within each cycle. Supply is fully restored at cycle boundaries. Adaptive controller converges to target cycle duration under bounded growth.
4. **VRF leader election fairness** (statistical proof): Prove that VRF-based leader election is proportional to stake weight within statistical bounds over any 100-epoch window.

Deliverables stored in `test/evidence/formal-proofs/`

## References

- OTR (Borisov, Goldberg, Brewer 2004)
- Post-Compromise Security (Cohn-Gordon et al. 2016)
- Signal Protocol specification (signal.org/docs)
- CWE Top 25
