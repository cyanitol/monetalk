# Development Phases (DO-178C DAL A + Code Generation)

## Revised Timeline: 53-67 Weeks

Code generation reduces hand-coding burden by ~15 weeks compared to pure hand-implementation (63-81 weeks). DO-178C adds formal verification and traceability overhead.

## Phase 0: Cryptographic Primitives + Code Generator (Weeks 1-10)

### 0a: Code Generator Bootstrap (Weeks 1-3)
1. Build TQL-1 qualified code generator framework (Template Haskell)
   - TQL-1 (Tool Qualification Level 1, per DO-178C Section 12.2): highest qualification level, required when tool output is part of airborne software and tool errors could go undetected. Requires: Tool Operational Requirements document, Tool Qualification Plan, Tool Qualification Results.
2. Define structured spec format for FIPS/RFC algorithms
3. Generator self-tests (MC/DC coverage of generator logic)
4. Generator correctness verified via:
   - (a) Reference output comparison against known-good implementations (e.g., NIST CAVP test vectors)
   - (b) Self-test suite achieving >95% MC/DC on generator code itself
   - (c) Independent review of generator source by second developer
5. Quality gate: generator produces valid Haskell from test spec

### 0b: Generated Crypto Primitives (Weeks 4-10)
1. SHA-256, SHA-512 (generated from FIPS 180-4 spec)
2. HMAC, HKDF (generated from RFC 2104/5869 specs)
3. AES-256, GCM mode (generated from FIPS 197 + SP 800-38D)
4. Modular arithmetic for Curve25519 field (generated field ops)
5. X25519 ECDH (generated from RFC 7748)
6. Ed25519 signatures (generated from RFC 8032)
7. ChaCha20 CSPRNG (generated from RFC 8439)
8. All NIST/RFC test vectors embedded in generated test harness
9. MC/DC coverage analysis for all generated code
10. Quality gate: 100% NIST/RFC test vectors pass; MC/DC coverage > 95%

## Phase 1: Signal Protocol (Weeks 11-16)

1. X3DH key agreement (state machine generated from FSM spec) — classical Signal only, no PQ
2. Double Ratchet (state machine generated; encrypt, decrypt, out-of-order)
3. Session management, key store (encrypted-at-rest)
4. Property tests: encrypt N msgs, decrypt any order, recover plaintext
5. Quality gate: all Signal test vectors pass; ratchet properties verified; X3DH complete by week 15

## Phase 2: Post-Quantum (Weeks 11-16, parallel with Phase 1)

1. ML-KEM-768 (NTT + polynomial arithmetic generated from FIPS 203)
2. PQ outer wrapper (AES-256-GCM with ML-KEM-derived keys)
3. PQ ratchet (every 50 messages, state machine generated)
4. PQ ciphertext transmission format (2-block KEY_EXCHANGE)
5. PQXDH integration (combining Phase 1 X3DH + Phase 2 ML-KEM) — merge step in week 16. Dependency: Phase 1 must complete X3DH by week 15.
6. Quality gate: FIPS 203 test vectors pass; PQ ratchet property tests pass; PQXDH composition verified

## Phase 3: Consensus + Economics (Weeks 17-26)

1. ECVRF-ED25519-SHA512 (generated from RFC 9381)
2. Slot clock, epoch management, clock synchronization
3. Block production and validation
4. Ledger state (balances, nonces, stakes) with WAL crash recovery
5. Fork choice rule (generated from TLA+ model)
6. Token economics v3 (Universe Cycle Model): adaptive controller, early truncation, cycle-scoped burn, supply restoration, dynamic fees, recycling pool, quadratic bonding
7. Reward formula with validator floor + user rebates
8. Tiered punitive multipliers
9. Adaptive parameter controller implementation and convergence testing
10. Early truncation trigger and supply monitoring
11. Treasury cap enforcement
12. Mempool with eviction policy (50K tx cap, fee-priority)
13. Formal BFT proof (TLA+ model checking)
14. Quality gate: token conservation invariant holds for 100K random sequences; adaptive controller converges within 5 cycles for 95% of runs; TLA+ model checked

## Phase 4: Chain Truncation (Weeks 27-31)

1. Snapshot computation (Merkle roots)
2. Epoch genesis block construction
3. WAL-based truncation execution with crash recovery
4. Cross-epoch validator set transition
5. Attestation failure handling (extend + emergency carry-forward)
6. Cross-epoch replay prevention (epoch_nonce in signed data)
7. Chain revision system (increment revision counter at each truncation, embed in genesis block, maintain revision->genesis-hash history for bootstrap verification)
8. Quality gate: simulated truncation with fault injection at every step; all recover; chain revision continuity verified across truncation boundaries

## Phase 5: P2P Networking (Weeks 32-41)

1. TCP transport with Noise_IK handshake (per-session rekeying)
2. Wire protocol (CBOR generated from schema)
3. Peer discovery (Kademlia DHT)
4. Gossip protocol with multiplexing priority
5. Dandelion++ (4 relay peers, randomized selection, 5-30s embargo, cover traffic)
6. Chain sync protocol
7. Version negotiation (peers exchange protocol version on handshake; reject incompatible versions, negotiate common feature set for compatible versions)
8. Peer scoring (validated via simulation)
9. Quality gate: 10-node network converges; Dandelion++ anonymity simulation passes

## Phase 6: Chat Application (Weeks 42-47)

1. Message format (1K block layout, 8-byte message_id, generated CBOR)
2. Multi-block chunking/reassembly
3. On-chain key registry
4. Stealth addresses (DKSAP one-time addresses)
5. Chat session management
6. JSON-RPC API with authentication
7. CLI interface
8. Quality gate: end-to-end encrypted message delivery across 3+ nodes

## Phase 7: Integration + Hardening + DO-178C V&V (Weeks 48-62)

### 7a: Integration Testing (Weeks 48-53)
1. Multi-node test network (5-10 nodes)
2. End-to-end message flow testing
3. 11-day truncation simulation (accelerated)
4. Economic model simulation: Monte Carlo with 100,000 cycles. Parameters sampled from distributions: user count ~ LogNormal(mu=8, sigma=1.5), message rate ~ Poisson(lambda=100/hour), validator count ~ Uniform(100, 10000). Attacker strategies modeled as adversarial policies. Success criterion: all 7 invariants hold for >99.9% of runs.

### 7b: Adversarial Testing (Weeks 54-57)
1. Spam flood simulation
2. Sybil attack simulation
3. Eclipse attack simulation
4. Dandelion++ traffic analysis
5. CBOR fuzzing (10,000+ random inputs per parser)
6. Fault injection (crash at every write point)

### 7c: DO-178C V&V Evidence (Weeks 58-62)
1. MC/DC structural coverage analysis (all DAL A modules)
2. Requirements traceability matrix completion
3. Formal proof evidence packaging (TLA+, composition proofs)
4. External security audit preparation
5. Configuration index + quality assurance records

### 7d: External Security Audit (Weeks 60-65)
1. Scope: all DAL A components
2. Duration: 4-6 weeks overlap with V&V evidence collection
3. Findings remediation: 2-3 weeks

## Quality Gates Summary

| Phase | Gate Criteria |
|-------|--------------|
| 0 | 100% NIST/RFC test vectors pass; MC/DC > 95%; generator TQL-1 qualified; generator correctness verified (CAVP, MC/DC, independent review) |
| 1 | Signal test vectors pass; ratchet properties verified; X3DH complete by week 15; MC/DC > 95% |
| 2 | FIPS 203 vectors pass; PQ composition tests pass; PQXDH integration verified; MC/DC > 95% |
| 3 | Token conservation for 100K sequences; adaptive controller converges within 5 cycles for 95% of runs; TLA+ model checked; MC/DC > 95% |
| 4 | Truncation survives fault injection at every step |
| 5 | 10-node convergence; Dandelion++ anonymity < 15% deanon with 10% adversary |
| 6 | E2E encrypted delivery across 3+ nodes; stealth address unlinkability |
| 7 | Full MC/DC coverage; traceability complete; audit findings remediated; Monte Carlo 100K cycles >99.9% invariant hold |

## Formal Proof Timeline

| Proof | Weeks | Parallel With |
|-------|-------|---------------|
| Coq crypto composition proof | 14-20 | Phase 1-2 |
| VRF statistical fairness | 17-22 | Phase 2-3 |
| TLA+ consensus model | 20-26 | Phase 3 implementation |
| Token conservation (QuickCheck + Coq) | 27-31 | Phase 4 |
| All proofs reviewed | Phase 7 V&V | Weeks 58-62 |

## Verification Strategy (DO-178C DAL A)

### Test Vectors
- All crypto primitives: NIST/RFC official KAT vectors (generated into test harness)
- Signal protocol: libsignal published test vectors
- ML-KEM: FIPS 203 official test vectors

### Property-Based Testing (MC/DC)
- Ratchet: encrypt N messages, decrypt in any order, always recover plaintext
- Consensus: token conservation (supply invariant), proportional rewards, VRF fairness
- Truncation: chain continuity, bootstrap validity, replay prevention
- Economics: fee bounds, reward floor, conservation invariant

### Formal Methods (DO-333)
- TLA+ consensus model (safety + liveness)
- Crypto composition proof (Signal + PQ wrapper)
- VRF fairness proof (statistical)

### Continuous Pipeline
```
Every commit:   unit tests + property tests + coverage analysis      (~25 min)
Nightly:        extended properties + 3-node integration + economic sim (~4 hours)
Weekly:         truncation sim + adversarial suite + coverage report   (~9 hours)
```

### Integration Testing
- 5-10 node test network, verify chain convergence
- Accelerated 11-day truncation simulation
- Spam + Sybil + eclipse attack simulation

### External Audit
- Week 60-65: independent security review of all DAL A components
- Scope: crypto, consensus, truncation, economics, storage, networking

## Future Work (v2)

The following features are deferred to a post-v1 release:

- **DEFLATE compression**: Wire-level compression of CBOR-encoded messages. Requires version negotiation (v1 peers must not receive compressed payloads).
- **NAT traversal**: Full NAT traversal stack (UPnP, hole punching, relay fallback). v1 assumes publicly reachable nodes or manual port forwarding.
