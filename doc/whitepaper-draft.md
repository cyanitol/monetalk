# UmbraVox: A Blockchain-Based Secure Messaging System with Post-Quantum Cryptography and Ephemeral Economics

**Draft Whitepaper v0.1**

---

## Abstract

UmbraVox is a decentralized messaging system that uses a blockchain as its
message transport layer instead of centralized servers. Every participant
runs a full node, eliminating single points of failure, surveillance, and
censorship. Messages are encrypted using a hybrid of the Signal Protocol
and post-quantum cryptography, ensuring confidentiality even against future
quantum computers. The blockchain operates on 11-day cycles: at the end of
each cycle, all message data is permanently destroyed and the token supply
is fully restored, creating a self-renewing economic system that prevents
long-term data accumulation while sustaining network operation indefinitely.

---

## 1. Introduction

### 1.1 The Problem

Today's encrypted messaging applications --- Signal, WhatsApp, Telegram ---
rely on centralized servers to route messages between users. Even when
messages themselves are encrypted end-to-end, the servers still know *who*
is talking to *whom*, *when*, and *how often*. A government subpoena, a
data breach, or a corporate policy change can expose this metadata or shut
down the service entirely.

These systems also face a looming threat: quantum computers. Current
encryption methods based on mathematical problems like the discrete
logarithm (used in Diffie-Hellman key exchange) will be breakable by
sufficiently powerful quantum computers running Shor's algorithm. An
adversary recording encrypted traffic today could decrypt it years from now
when quantum computers mature --- a strategy known as "harvest now, decrypt
later."

### 1.2 The UmbraVox Approach

UmbraVox addresses these problems with three core ideas:

1. **No servers.** The blockchain *is* the message transport. Every user
   runs a full node that stores, validates, and relays messages. There is
   no company, no server farm, and no single entity that can read metadata
   or shut down the network.

2. **Quantum-resistant encryption.** Every message is protected by two
   independent layers of encryption: the well-studied Signal Protocol
   (used by Signal and WhatsApp) and an outer wrapper using ML-KEM-768, a
   post-quantum algorithm standardized by NIST. Security holds as long as
   *either* layer remains unbroken.

3. **Built-in ephemerality.** Every 11 days, the entire blockchain is
   truncated. Message data is permanently destroyed at the protocol level
   --- not by a user pressing "delete," but by the network itself. Only
   staked balances, validator registrations, and cryptographic key
   material carry forward into the next cycle. Validators receive fresh
   spendable balances based on their participation in the previous cycle.

A native token (MTK) pays for message transmission and rewards the
validators who operate the network. The total supply is fixed at 11 billion
MTK and is fully restored at each cycle boundary, creating a renewable
economic model with no long-term inflation or deflation.

---

## 2. System Architecture

### 2.1 Overview

UmbraVox's architecture is a vertical stack where each layer serves a
specific purpose:

```
+--------------------------------------------------+
|  Chat Interface  (JSON-RPC API / WebSocket)      |
+--------------------------------------------------+
|  Crypto Engine   (Signal sessions, PQ wrapper)   |
+--------------------------------------------------+
|  Mempool         (transaction validation & queue) |
+--------------------------------------------------+
|  Consensus       (VRF leader election, blocks)   |
+--------------------------------------------------+
|  Chain Storage   (append-only blocks, state DB)  |
+--------------------------------------------------+
|  Network Layer   (TCP/Noise, gossip, Dandelion++)|
+--------------------------------------------------+
```

When Alice sends a message to Bob:

1. The **Crypto Engine** encrypts the plaintext using Alice and Bob's
   shared Signal session, then wraps the ciphertext in the post-quantum
   outer layer.
2. The encrypted message is packaged into a **transaction** with a fee
   and placed in the local **mempool**.
3. The transaction is broadcast to the network using **Dandelion++**, a
   protocol that obscures Alice's IP address by routing the transaction
   through several random intermediate nodes before broadcasting it
   widely.
4. A **slot leader** (a validator selected by a verifiable random
   function) includes the transaction in a block.
5. Bob's node receives the block, recognizes a message addressed to him,
   decrypts it through the PQ wrapper and Signal layers, and displays the
   plaintext.

End-to-end latency from send to display is approximately 370--530
milliseconds.

### 2.2 Implementation

UmbraVox is implemented in Haskell, chosen for its strong type system that
can encode protocol invariants at compile time. All cryptographic
primitives are implemented from scratch using only the language's standard
library --- no external dependencies. Two implementations are maintained in
parallel: a pure Haskell version for formal verification and testing, and
an FFI (Foreign Function Interface) version calling constant-time C code
for production use, ensuring resistance to timing side-channel attacks.

The project targets DO-178C Design Assurance Level A, the highest
certification standard used in avionics software. This requires 100%
modified condition/decision coverage (MC/DC) in testing, full bidirectional
traceability from requirements to code to tests, and formal mathematical
proofs of critical security properties.

---

## 3. Cryptographic Design

### 3.1 Primitives

UmbraVox uses the following cryptographic building blocks, all implemented
from their respective standards without external libraries:

| Primitive | Standard | Role |
|-----------|----------|------|
| SHA-256, SHA-512 | FIPS 180-4 | Hashing (blocks, transactions, keys) |
| HMAC (SHA-256/SHA-512) | RFC 2104 | Message authentication |
| HKDF | RFC 5869 | Key derivation |
| AES-256-GCM | FIPS 197 + SP 800-38D | Authenticated encryption |
| X25519 | RFC 7748 | Diffie-Hellman key exchange |
| Ed25519 | RFC 8032 | Digital signatures |
| ML-KEM-768 | FIPS 203 | Post-quantum key encapsulation |
| ECVRF | RFC 9381 | Verifiable random function (consensus) |
| ChaCha20 | RFC 8439 | Pseudorandom number generation |

### 3.2 Signal Protocol with Post-Quantum Extension (PQXDH)

When two users communicate for the first time, they perform a key exchange
called PQXDH (Post-Quantum Extended Diffie-Hellman). This combines four
classical Diffie-Hellman exchanges with one post-quantum key encapsulation:

```
Classical component (X25519):
  dh1 = DH(Alice_identity, Bob_signed_prekey)
  dh2 = DH(Alice_ephemeral, Bob_identity)
  dh3 = DH(Alice_ephemeral, Bob_signed_prekey)
  dh4 = DH(Alice_ephemeral, Bob_one_time_prekey)

Post-quantum component (ML-KEM-768):
  (ciphertext, shared_secret) = Encapsulate(Bob_PQ_prekey)

Combined master secret:
  MS = HKDF(dh1 || dh2 || dh3 || dh4 || shared_secret)
```

The hybrid design provides a critical property: **security holds if either
the classical or the post-quantum assumption holds.** If a quantum computer
breaks the Diffie-Hellman exchanges, the ML-KEM shared secret still
protects the session. If ML-KEM is somehow broken, the four DH values still
provide security. An attacker must break *both* simultaneously.

After the initial key exchange, the **Double Ratchet** algorithm derives
new encryption keys for every message. Each time a message is sent, the
keys used to encrypt it are immediately deleted. This provides:

- **Forward secrecy:** Compromising a device today cannot decrypt messages
  sent in the past.
- **Post-compromise security:** After a temporary compromise, security is
  automatically restored when new key material is exchanged.

### 3.3 Post-Quantum Outer Wrapper

An independent encryption layer wraps all Signal ciphertext using ML-KEM-768
and AES-256-GCM. This layer maintains its own ratchet: every 50 messages
per direction, a fresh ML-KEM key encapsulation generates new symmetric
keys, restoring post-quantum forward secrecy. Even if the Signal layer's classical
Diffie-Hellman is broken by a quantum computer, this outer wrapper keeps
messages confidential.

### 3.4 Message Format

Each message occupies one or more 1,024-byte blocks:

| Component | Size | Purpose |
|-----------|------|---------|
| Header | 140 bytes | Sender/recipient IDs, timestamps, ratchet keys |
| Encrypted payload | 798 bytes | Signal-encrypted, PQ-wrapped content |
| HMAC | 32 bytes | Authentication tag |
| Padding | 54 bytes | Random bytes (prevents length analysis) |
| **Overhead** | **226 bytes** | Per block |
| **Usable plaintext** | **~782 bytes** | Per block (after 16-byte GCM tag) |

All messages --- regardless of actual content length --- are padded to full
1,024-byte blocks. This prevents an observer from inferring message content
from its size.

### 3.5 Deniability

UmbraVox preserves off-the-record (OTR) deniability: message content is
authenticated using only symmetric-key MACs derived from shared secrets,
never asymmetric signatures. This means a recipient can verify that a
message came from the sender, but cannot prove this to a third party.

---

## 4. Consensus Mechanism

### 4.1 Proof of Stake with VRF Leader Election

UmbraVox uses a simplified version of Ouroboros Praos, a proof-of-stake
consensus protocol. Time is divided into 11-second **slots**. In each slot,
validators privately evaluate a **Verifiable Random Function (VRF)** to
determine if they are the slot leader:

```
input  = epoch_nonce || slot_number
output = VRF(validator_secret_key, input)

threshold = 1 - (1 - 0.20) ^ (validator_stake / total_stake)

if output < threshold:
    validator produces a block
```

The active slot coefficient *f* = 0.20 means roughly 20% of slots produce
blocks, yielding approximately one block every 55 seconds. The VRF is
crucial: it allows anyone to *verify* that a leader was legitimately
elected, but no one can *predict* who the next leader will be. This
prevents targeted denial-of-service attacks against upcoming leaders.

### 4.2 Time Structure

| Unit | Duration | Composition |
|------|----------|-------------|
| Slot | 11 seconds | Atomic time unit |
| Epoch | 12 hours | 3,927 slots |
| Cycle | 11 days | 22 epochs |

### 4.3 Stake and Rewards

Validators stake MTK tokens to participate in consensus. Their effective
stake is weighted by an uptime score (measured via periodic heartbeat
challenges) and a punitive factor (reduced for misbehavior):

```
Effective_Stake = Token_Balance * (0.5 + 0.3 * Uptime_Ratio) * Punitive_Factor
```

Even a completely offline validator retains 50% of its stake weight (the
0.5 base), incentivizing honest validators to stay online without harshly
penalizing temporary outages.

### 4.4 Finality

UmbraVox uses a two-tier settlement model. **Message transactions** are considered final at depth k=11 (approximately 10 minutes), with reversal probability less than 1 in 2,048. **Value transactions** (token transfers, stake operations) require depth k=22 (approximately 20 minutes), with reversal probability less than 1 in 4.2 million. This separation reflects the different security needs: encrypted message reordering has low impact, while financial operations need stronger guarantees.

### 4.5 Fork Choice

When validators see two competing chain tips, they select the one with
higher **density** (more blocks per slot range). Ties are broken by VRF
output hash. This rule is deterministic: given the same information, all
honest validators make the same choice.

---

## 5. Network Layer and Privacy

### 5.1 Peer-to-Peer Network

Nodes discover each other using a Kademlia distributed hash table (DHT) and
maintain connections to approximately 25 peers. All peer-to-peer
communication is encrypted using the Noise_IK handshake protocol with
X25519 key exchange.

### 5.2 Dandelion++ IP Anonymity

When a user creates a transaction, it is not immediately broadcast to all
peers. Instead, Dandelion++ routes it through a short random path (the
**stem phase**) before broadcasting it widely (the **fluff phase**):

```
Alice --> Relay A --> Relay B --> [broadcast to all peers]
          (stem)     (stem)       (fluff)
```

Each node randomly acts as either a **relayer** (forwards the stem to the
next hop) or a **diffuser** (immediately broadcasts to all peers). At
each relayer hop, there is a 10% chance the transaction transitions to
the fluff phase on its own. Since roughly half of nodes are diffusers,
the effective stem length is shorter than it would be with relayers alone.
This makes it extremely difficult for a network observer to determine
which node originated a transaction.

Every 600 seconds, each node randomly selects new relay peers and randomly
decides whether to act as a relayer (forward stems) or a diffuser
(immediately broadcast). This periodic reshuffling prevents long-term
traffic analysis.

### 5.3 Cover Traffic

Nodes optionally generate one dummy message per Dandelion++ epoch (every
600 seconds). These dummy messages are encrypted, padded to standard size,
and indistinguishable from real messages during the stem phase. They are
discarded before block inclusion. This prevents an observer from
distinguishing active users from idle ones based on traffic patterns.

---

## 6. The Universe Cycle: Ephemeral Economics

### 6.1 The Core Idea

UmbraVox's most distinctive feature is its **Universe Cycle** economic
model. Every 11 days, the blockchain undergoes a controlled reset:

1. All message data is permanently deleted.
2. All spendable balances are zeroed out.
3. The burned token counter resets to zero.
4. The reward pool is fully restored.
5. Validators receive fresh balances based on their participation.

This creates an economy that is **scarce within each cycle** (fees burn
tokens, creating deflationary pressure) but **sustainable across cycles**
(the full supply is restored every 11 days). There is no long-term
inflation, no token minting, and no permanent deflation.

### 6.2 Token Supply

The total supply is fixed at **11 billion MTK**, allocated at genesis as:

| Pool | Amount | Share | Purpose |
|------|--------|-------|---------|
| Reward Pool | 9.35B | 85% | Validator rewards each cycle |
| Onboarding Reserve | 1.1B | 10% | New user grants |
| Treasury | 550M | 5% | Protocol development (capped at 10%) |

### 6.3 Message Fees

Sending a message costs a fee denominated in MTK. The fee is dynamically
adjusted based on network utilization:

- **Low usage** (below 50% of target): fees decrease by 10%.
- **High usage** (above 150% of target): fees increase by 10%.
- **Normal range**: fees remain stable.

Fees are always clamped between a floor (initially 10 MTK) and a ceiling
(initially 10,000 MTK). The cost of a message scales linearly with its
size: `fee = base_fee * ceil(message_bytes / 1024)`.

### 6.4 Fee Distribution

Each fee is split into two portions: a burned portion and a non-burned
portion. The burn rate is adaptive (initially 65%, range 20--80%). The
non-burned remainder is divided in fixed 20:10:5 ratios among the block
producer, treasury, and user rebate pool.

At the default 65% burn rate, the effective split of each fee is:

```
65%  --> Burned (permanently removed from circulation within the cycle)
20%  --> Block producer (the validator who included the transaction)
10%  --> Protocol treasury
 5%  --> User rebate pool (returned to active users at cycle end)
```

If the burn rate changes, the non-burn percentages scale proportionally
(e.g., at 40% burn: 34.3% producer, 17.1% treasury, 8.6% rebate).

The burn rate adapts across cycles. If a cycle runs
longer than the 11-day target (indicating low activity), the burn rate
increases to accelerate scarcity. If a cycle runs short (high activity),
the burn rate decreases to preserve circulating supply.

### 6.5 Cycle Boundary

At the end of each cycle, the network performs an atomic transition:

1. **Snapshot:** Validators compute a terminal state snapshot including
   all account balances, the validator set, and the key registry.
2. **Attestation:** At least two-thirds of validators (by stake weight)
   sign the snapshot.
3. **Reset:** All spendable balances go to zero. Burned tokens reset to
   zero. The reward pool is restored:
   `pool = 11B - staked_balances - onboarding_reserve - treasury`
4. **Rewards:** Each active validator receives a share of 85% of the pool,
   proportional to their effective stake. Minimum reward: 5,000 MTK.
5. **Truncation:** All blocks from the previous cycle are deleted. The new
   cycle begins with a genesis block containing the signed snapshot.

Staked balances, the validator set, cryptographic key registries, and
adaptive parameters all persist across boundaries. Signal Protocol sessions
(stored locally, never on-chain) are unaffected.

### 6.6 Adaptive Controller

Four economic parameters automatically adjust at each cycle boundary based
on how the previous cycle performed:

| Parameter | Initial | Range | Adjusts When |
|-----------|---------|-------|--------------|
| Burn rate | 65% | 20--80% | Cycle duration deviates from 11 days |
| Fee floor | 10 MTK | 5--100 | Cycle ran too long or short |
| Fee ceiling | 10,000 MTK | 5,000--50,000 | Cycle ran too long or short |
| Target messages/epoch | 10,000 | 1,000--100,000,000 | Cycle ran too long or short |

Each adjustment is damped by 50% to prevent oscillation: the parameter
moves only halfway toward the computed target. Mathematical analysis shows
this controller converges to within 1% of equilibrium in 7 cycles (~77
days) and never overshoots.

### 6.7 Early Truncation

If circulating supply drops below a threshold (initially 15% of total
supply) at any epoch boundary, the cycle ends early. This prevents the
network from running out of spendable tokens during periods of very high
activity. The minimum cycle duration is one epoch (12 hours).

---

## 7. Security Model

### 7.1 Threat Model

UmbraVox is designed to resist the following adversaries:

- **Network observers** who can monitor all traffic between nodes.
- **Compromised validators** controlling up to one-third of total stake.
- **Quantum computers** capable of running Shor's algorithm.
- **Temporary device compromise** (security self-heals via ratcheting).

### 7.2 What Is Protected

| Property | Mechanism |
|----------|-----------|
| Message confidentiality | Signal + PQ wrapper (dual encryption) |
| Forward secrecy | Double Ratchet key deletion |
| Post-compromise security | Fresh DH + ML-KEM ratchet refreshes |
| Sender anonymity (IP) | Dandelion++ stem routing |
| Message ephemerality | 11-day chain truncation |
| Consensus safety | VRF + honest majority (> 2/3 stake) |
| Spam prevention | Token fees + adaptive burn |
| Sybil resistance | Quadratic staking + PoW onboarding |

### 7.3 Known Limitations (v1)

- **Metadata protection overhead:** V1 includes stealth addresses (DKSAP),
  encrypted headers, fixed fees, and uniform block sizing to prevent
  communication graph construction. These protections add computational
  overhead and constrain fee flexibility.
- **No NAT traversal:** Nodes behind NAT can connect outbound but cannot
  accept inbound connections. Validators should have public IPs.
- **11-day offline limit:** Users offline for more than one cycle lose any
  pending messages from the prior cycle. Signal sessions survive (they are
  local), but on-chain key exchanges must be repeated.

### 7.4 Formal Verification

Seven formal proof documents totaling over 4,000 lines establish:

1. **Primitive security:** Reduction proofs for all 9 cryptographic
   primitives to standard hardness assumptions.
2. **Protocol security:** Hybrid game proofs that the Signal + PQ
   composition is IND-CCA2 secure if either CDH or Module-LWE holds.
3. **Consensus safety and liveness:** TLA+ state machine verification
   that no two honest nodes disagree on finalized blocks, and all valid
   transactions are eventually included.
4. **Token conservation:** Coq-style proofs that the total supply equals
   11 billion MTK at all times, across all 12 economic invariants.
5. **VRF fairness:** Statistical proof (chi-squared test design) that
   leader election is proportional to stake.
6. **Controller convergence:** Lyapunov stability analysis showing the
   adaptive controller converges geometrically with no oscillation.
7. **Cryptanalysis resistance:** Systematic analysis of resistance to
   all known attack classes (differential, algebraic, quantum, side-channel,
   traffic analysis).

---

## 8. Validator Onboarding and Anti-Abuse

### 8.1 New Users

New users obtain initial tokens through one of two mechanisms:

- **Proof-of-work faucet:** Solve an Argon2id puzzle requiring ~10 minutes
  of CPU time and 256 MB of memory. Grants up to 10,000 MTK. Rate-limited
  to one claim per public key per cycle.
- **Vouching:** An existing user transfers up to 10% of their balance to
  the new user. The voucher takes a 10% sympathetic penalty if the new
  user misbehaves.

### 8.2 Sybil Resistance

Creating fake identities (Sybil attacks) is discouraged through multiple
mechanisms:

- **Quadratic bonding:** The minimum stake for the *n*th validator from the
  same subnet is 50,000 * n^2 MTK. A second validator from the same /16
  subnet requires 200,000 MTK; a third requires 450,000 MTK.
- **Self-referral is unprofitable:** The onboarding bonus (10% of referred
  users' fees) never exceeds the fees spent to generate that activity. Net
  loss: at least 90% of fees plus PoW costs.

### 8.3 Abuse Detection and Penalties

Validators who abuse the network face tiered penalties applied to their
punitive factor (a multiplier on effective stake):

| Tier | Trigger | Penalty | Recovery |
|------|---------|---------|----------|
| 1 (Minor) | Traffic > 2x median | 10% effective stake reduction | ~2 cycles (22 days) |
| 2 (Moderate) | Traffic > 5x median | 50% effective stake reduction | ~22 cycles (242 days) |
| 3 (Severe) | Traffic > 10x median | Zero effective stake for 10 cycles + 25% slashed | Re-registration required |

Slashed tokens are added to the burned total within the current cycle and
restored to the reward pool at the next cycle boundary. The conservation
invariant (total supply = 11B) is always maintained.

---

## 9. Comparison with Existing Systems

| Feature | Signal | Telegram | UmbraVox |
|---------|--------|----------|----------|
| End-to-end encryption | Yes | Optional | Yes (dual-layer) |
| Post-quantum protection | Partial (PQXDH, 2023) | No | Yes (dual-layer PQ wrapper) |
| Decentralized | No (servers) | No (servers) | Yes (blockchain) |
| Message ephemerality | Manual delete | Manual delete | Automatic (11 days) |
| IP anonymity | No | No | Dandelion++ |
| Censorship resistant | No | Partial | Yes |
| Metadata privacy | Limited | No | Strong (stealth addresses, encrypted headers, fixed fees, uniform blocks) |
| Deniability | Yes | No | Yes |
| Spam prevention | Phone number | Phone number | Token fees |

---

## 10. Conclusion

UmbraVox demonstrates that it is possible to build a messaging system that
is simultaneously decentralized, quantum-resistant, ephemeral, and
economically self-sustaining. By using a blockchain as the message transport
layer, it eliminates centralized servers entirely. By combining the Signal
Protocol with post-quantum cryptography, it provides security against both
current and future threats. By operating in 11-day cycles with full supply
restoration, it creates a renewable economic model that funds network
operation without inflation.

The system makes explicit trade-offs: metadata protection adds computational overhead,
messages have a minimum cost, and data retention is limited to 11 days. These are
deliberate design choices that prioritize privacy and sustainability over
convenience. V1 includes comprehensive metadata protection through stealth addresses,
encrypted headers, fixed fees, and uniform blocks, providing
a solid foundation for censorship-resistant, quantum-safe communication.

---

## References

1. Bernstein, D.J. "Curve25519: New Diffie-Hellman Speed Records." PKC 2006.
2. Bindel, N., et al. "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange." PQCrypto 2019.
3. David, B., et al. "Ouroboros Praos: An Adaptively-Secure, Semi-Synchronous Proof-of-Stake Blockchain." Eurocrypt 2018.
4. Fanti, G., et al. "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees." SIGMETRICS 2018.
5. Krawczyk, H. "Cryptographic Extraction and Key Derivation: The HKDF Scheme." CRYPTO 2010.
6. Marlinspike, M. and Perrin, T. "The X3DH Key Agreement Protocol." Signal Foundation, 2016.
7. Marlinspike, M. and Perrin, T. "The Double Ratchet Algorithm." Signal Foundation, 2016.
8. NIST. "FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard." 2024.
9. Perrin, T. "The Noise Protocol Framework." 2018.
