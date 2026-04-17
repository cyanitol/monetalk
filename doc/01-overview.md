# UmbraVox: System Overview

UmbraVox is a blockchain-based secure communications system. Existing chat platforms rely on centralized servers that can be compelled to hand over metadata, shut down, or compromised. UmbraVox eliminates central points of failure by using a blockchain as the message transport layer, combining multiple cryptographic protocols for defense-in-depth, and using token economics to prevent spam while incentivizing network participation. The 11-day chain truncation enforces ephemeral messaging at the protocol level -- messages are destroyed by design, not policy.

## Core Principles

- **No central servers**: Every participant runs a full node
- **Defense in depth**: Signal Protocol + post-quantum wrapper + Dandelion++ IP obfuscation
- **Ephemeral by design**: Chain truncates every 11 days, destroying message records at the protocol level
- **Economic spam prevention**: Token costs per message, rewards for honest participation, adaptive parameters self-tune to network growth
- **Cyclical renewal**: Each 11-day cycle is a self-contained economic universe — full supply restores at cycle boundary, with adaptive parameters ensuring sustainability as the network grows
- **Deniability**: OTR properties preserved -- no asymmetric signatures on message content
- **No external libraries**: Pure Haskell reference implementations for verification + FFI to constant-time C for production, both produced by TQL-1 qualified code generators. No third-party library dependencies

## Software Assurance (DO-178C DAL A)

All core features of UmbraVox are designated DAL A (Design Assurance Level A), the highest assurance level defined by DO-178C. This designation reflects the system's role as critical communications infrastructure where failure could result in loss of confidentiality, integrity, or availability of private messages.

DAL A designation requires:

- **100% MC/DC structural coverage**: Every condition in every decision must be shown to independently affect the decision outcome. All source code paths must be exercised by requirements-based tests.
- **Full bidirectional requirements traceability**: Every high-level requirement traces to low-level requirements, source code, and test cases. Every line of code traces back to a requirement. No dead code, no untraceable functionality.
- **Formal methods (DO-333 supplement)**: Consensus logic and cryptographic composition proofs require formal verification per the DO-333 Formal Methods supplement. This includes model checking of protocol state machines and mathematical proof of crypto primitive correctness.
- **Independent verification**: All verification activities require external audit by an independent party with no involvement in the development process.
- **TQL-1 qualified code generators**: Any tool whose output is not verified by downstream testing must itself be qualified to Tool Qualification Level 1 (TQL-1), the most rigorous tool qualification level.

## Architecture at a Glance

```
Chat API (JSON-RPC over WebSocket)
    |
Crypto Engine (Signal sessions, PQ wrapper, key management)
    |
Mempool (validate, prioritize, evict)
    |
Consensus Engine (slot clock, VRF leader election, block production/validation)
    |
Chain Storage (append-only blocks, state DB, indexes)
    |
Network Layer (TCP transport, Noise encryption, gossip, Dandelion++)
```

## Known Limitations (v1)

- **Offline message loss**: 11-day message ephemerality means users who are offline for a full cycle will lose messages. There is no off-chain store-and-forward mechanism in v1.
- **Archival node threat**: Nodes that retain pre-truncation chain data are not fully mitigated until truncation enforcement is hardened in later phases.
- **Steady-state storage**: ~80 GB steady-state disk requirement (40x original spec) is commodity SSD territory but may challenge resource-constrained devices
- **Compression deferred**: Wire-level DEFLATE compression of block and transaction payloads is deferred to v2. All data is transmitted uncompressed.

## Code Generation Strategy

Critical subsystems use generated code rather than hand-written implementations to reduce human error and enable formal-methods-backed correctness guarantees. All generators are qualified to TQL-1 per DO-178C.

- **Crypto primitives**: Generated from FIPS/RFC specifications via a TQL-1 qualified Haskell meta-program. The generator ingests formal algorithm definitions (FIPS 197 for AES, RFC 7748 for X25519, FIPS 203 for ML-KEM, etc.) and emits constant-time Haskell implementations with no branching on secret data.
- **Protocol state machines**: Generated from typed finite state machine (FSM) definitions. Each protocol (Signal handshake, consensus rounds, Dandelion++ routing) is specified as a typed FSM, and the generator produces exhaustive state transition code with compile-time guarantees that no invalid transitions exist.
- **CBOR serialization**: Generated from declarative schemas. Message formats, block structures, and wire protocols are defined in a schema language, and the generator emits serialization/deserialization code with round-trip correctness proofs.
- **Consensus logic**: Generated from formal models written in TLA+ and Alloy. The generator translates verified specifications into executable code, preserving the safety and liveness properties proven in the formal models.
- **Embedded test harnesses**: All generated code includes embedded test harnesses that exercise every code path. These harnesses provide the MC/DC coverage evidence required by DAL A and are themselves traceable to requirements.

## Encryption Pipeline (per message)

```
Plaintext
  |-> Signal Double Ratchet encrypt (AES-256-GCM + HMAC-SHA256)
  |-> PQ Outer Wrapper encrypt (ML-KEM-768 derived key -> AES-256-GCM)
  |-> Serialize into message blocks (CBOR encoding, up to 4,444 per block)
  |-> Blockchain transaction (Ed25519 signed)
  |-> Dandelion++ stem/fluff broadcast
```

## Key Parameters

| Parameter | Value |
|-----------|-------|
| Slot duration | 11 seconds |
| Epochs per cycle | 22 (12-hour epochs) |
| Cycle length | 11 days |
| Message base size | 1,024 bytes per message; 4,444 messages per block |
| Message base cost | Dynamic (10 to 10,000 MTK, EMA-adjusted) |
| Total token supply | 11,000,000,000 MTK |
| Settlement depth | k=11 (messages, ~10 min) / k=22 (value, ~20 min) |
| Send-to-display latency | ~370-530ms |
| Fee split | Adaptive burn (20-80%, initial 65%) / proportional producer-reserve-rebate (20:10:5 ratio) |
| Economic model | Universe Cycle (full supply restoration each cycle) |
| Early truncation threshold | 15% of supply (adaptive, range 5-25%) |
| Node hardware minimum | 4 cores, 4 GB RAM, 100 GB SSD, 5 Mbps symmetric (400 KB/s minimum) |
| Assurance level | DO-178C DAL A (all core features) |
| Compact block relay | Enabled (mandatory at 4,444 msgs/block) |
| Global throughput | ~80.8 msg/sec (~6.98M/day) |
| Full block size | ~4.44 MB (4,550,656 bytes) |
| Compact block size | ~50-130 KB (95%+ mempool hit rate) |
| Timeline | 53-67 weeks |

## Documentation Index

- [Language and Project Structure](02-language-and-structure.md)
- [Cryptographic Architecture](03-cryptography.md)
- [Consensus Mechanism](04-consensus.md)
- [Chain Truncation](05-truncation.md)
- [Token Economics](06-economics.md)
- [Message Format](07-message-format.md)
- [Dandelion++ IP Obfuscation](08-dandelion.md)
- [P2P Network Layer](09-network.md)
- [Security Model](10-security.md)
- [Node Architecture](11-node-architecture.md)
- [Development Phases](12-development-phases.md)
- [DO-178C Assurance Plan](13-do178c-assurance.md)
- [Code Generation Strategy](14-code-generation.md)
- [Economic Model v3 (Universe Cycle)](15-economic-model-v3.md)
- [Verification Plan](16-verification-plan.md)
- [Related Work and Comparative Analysis](17-related-work.md)
- [Performance Analysis](18-performance-analysis.md)
- [Game-Theoretic Analysis](19-game-theory.md)
- [Economic Analysis](20-economic-analysis.md)
- [Requirements Traceability Matrix](requirements-trace.md)
