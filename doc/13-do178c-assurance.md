# DO-178C Software Assurance Plan

## Overview

UmbraVox applies DO-178C (Software Considerations in Airborne Systems and Equipment Certification) methodology to achieve the highest practical software assurance for a blockchain-based secure messaging system. While not seeking aviation certification, the DO-178C framework provides rigorous, proven processes for developing safety-critical software.

## Design Assurance Level Assignments

All core features are designated **DAL A** (highest assurance). Only the local JSON-RPC API, CLI interface, and logging are DAL D.

| Component | DAL | Failure Impact |
|-----------|-----|----------------|
| Cryptographic primitives (SHA, AES, Ed25519, ML-KEM) | **A** | Total confidentiality loss, key recovery by adversary |
| Signal Double Ratchet + PQXDH composition | **A** | All messages decryptable, forward secrecy broken |
| Consensus (VRF, fork choice, finality) | **A** | Chain fork, double-spend, token theft, consensus corruption |
| Token economics (rewards, fees, penalties) | **A** | Economic collapse, validator exodus, spam flood |
| Chain truncation (snapshots, epoch genesis) | **A** | State loss, privacy breach, chain corruption |
| Storage engine (blocks, state DB, WAL) | **A** | Data corruption, consensus divergence, unrecoverable state |
| Dandelion++ anonymization | **A** | Sender deanonymization, privacy model collapse |
| P2P networking (DHT, gossip, Noise_IK) | **A** | Eclipse attacks, network partition, consensus isolation |
| Chat application (message format, key registry) | **A** | Message corruption, key registry poisoning |
| JSON-RPC API | D | Local interface issues only |
| CLI interface | D | Local usability issues only |
| Logging | D | Diagnostic output only |

### Explicit DAL A Component List

**Crypto**: Signal Double Ratchet, PQXDH, ML-KEM-768, AES-256-GCM, SHA-256, Ed25519, X25519, HKDF, VRF (ECVRF).

**Consensus**: leader election (VRF threshold), fork choice rule, slot assignment, stake calculation.

**Economics**: reward distribution, fee calculation (EMA adjustment, adaptive controller), conservation enforcement (cycle-scoped burn, supply restoration), penalty system (3-tier punitive factor), early truncation trigger, supply monitoring, adaptive parameter controller.

**Truncation**: snapshot creation, attestation collection, epoch genesis creation, WAL recovery.

**Storage**: state DB (custom append-only flat file + in-memory index), key store (encrypted flat files), block store (epoch-partitioned files).

**Dandelion++**: stem routing, embargo timer, relay selection.

**Networking**: Noise_IK handshake, peer scoring.

**DAL D** (non-safety): JSON-RPC API, CLI interface, logging.

## DAL A Objectives

### Requirements
- All requirements documented, complete, and verifiable
- Full bidirectional traceability: requirements <-> design <-> code <-> tests

### Development
- Code implements approved requirements only (no undocumented features)
- Code generated from formal specs where possible (TQL-1 qualified generators)
- All code reviewed (independent verification for DAL A)

### Verification
- 100% MC/DC structural coverage on all DAL A code
- All requirements have corresponding test cases
- Property-based testing for all invariants
- Formal methods (DO-333) for consensus and crypto composition
- Early truncation trigger correctness: verified via supply depletion simulation
- Independent verification (external audit)

### Configuration Management
- All artifacts version-controlled (git)
- Change impact analysis for all modifications
- Baseline management at each phase gate

### Quality Assurance
- Coding standards enforced (Haskell style guide + strictness requirements)
- Quality gates at each development phase
- Defect tracking with root cause analysis

## DO-333 Formal Methods Supplement

Required formal proofs:
1. **Consensus safety/liveness** (TLA+): No two honest nodes disagree on finalized blocks; all valid transactions eventually included
2. **Crypto composition** (Coq/TLA+): Signal + PQ wrapper composition does not weaken either layer's guarantees
3. **Token conservation** (QuickCheck + formal): Total supply exactly 11B within each cycle. Supply fully restored at cycle boundaries. `burned_total` resets to 0 at each boundary.
4. **VRF fairness** (statistical): Leader election frequency proportional to stake
5. **Adaptive controller convergence** (control theory + simulation): Prove that the proportional controller with 50% damping converges to parameters producing 11-day cycles under bounded network growth (up to 10x per 100 cycles).

Deliverables stored in `test/evidence/formal-proofs/`.

## Process Artifacts

| Artifact | Location | Purpose |
|----------|----------|---------|
| Software Assurance Plan | `doc/13-do178c-assurance.md` (this file) | DAL assignments, objectives |
| Requirements Trace | `doc/requirements-trace.md` | Bidirectional traceability |
| Design Description | Architecture docs (`doc/01` through `doc/14`) | System design |
| Verification Plan | `doc/16-verification-plan.md` | Test strategy |
| Coverage Reports | `test/coverage/` | MC/DC analysis |
| Verification Evidence | `test/evidence/` | Test results, formal proofs |
| Configuration Index | `doc/configuration-index.md` (created Phase 7) | Baselines, versions |
| Quality Assurance Records | `doc/quality-assurance.md` (created Phase 7) | Reviews, audits |

## Tool Qualification

### TQL-1: Code Generator

The Haskell meta-program generating crypto/protocol code is a DAL A artifact. TQL-1 qualification requires the following three criteria, all stored in `test/evidence/tool-qualification/`:

1. **Tool Operational Requirements (TOR)**: formal document specifying generator inputs (`.spec`, `.fsm`, `.schema` files), outputs (Haskell modules, test harnesses, FFI stubs), and behavioral requirements (determinism, completeness, correctness).
2. **Tool Qualification Plan**: test strategy covering MC/DC of generator logic, coverage requirements for all code paths, and independent review process.
3. **Tool Qualification Results**: evidence that the TOR is met, including test results (all NIST/RFC vectors pass through generated code), coverage analysis (100% MC/DC of generator), and review sign-off.

### TQL-3: Test Tools
- QuickCheck (property-based testing): validated via known-answer checks
- HPC (Haskell Program Coverage): validated via known-coverage programs
- UmbraVox.Coverage module (MC/DC instrumentation): qualified TQL-3 as a verification tool
- No additional qualification needed for TQL-3 tools

## MC/DC Measurement Methodology for Haskell

Standard HPC provides line and branch coverage but not MC/DC. UmbraVox uses a custom approach:

1. **Cost center annotations**: All DAL A decision points annotated with `{-# SCC "decision_name" #-}` cost centers. Strict evaluation enforced at decision sites via `BangPatterns` and `seq` to prevent lazy evaluation from obscuring coverage.
2. **Template Haskell instrumentation**: At compile time, Template Haskell splices insert boolean condition tracking into every compound decision expression (e.g., `a && b || c` becomes individually tracked conditions `a`, `b`, `c`).
3. **Custom coverage aggregation**: The `UmbraVox.Coverage` module aggregates HPC line/branch data with the condition-level tracking data to produce a full MC/DC report. Output: per-module MC/DC percentage and list of uncovered condition combinations.
4. **Manual review for lazy paths**: Decision points involving lazily-evaluated thunks that cannot be reliably instrumented are identified and manually reviewed. These are documented in `test/evidence/mcdc-manual-review/`.

Tool: `UmbraVox.Coverage` module (itself qualified TQL-3 as a verification tool).

## Software Safety Assessment

Per DO-178C Section 11.1, the safety assessment feeds into system-level safety analysis. For UmbraVox, "safety" maps to message confidentiality, integrity, and availability.

| Failure Condition | Severity | DAL | Example |
|-------------------|----------|-----|---------|
| Key compromise (adversary recovers private keys) | Catastrophic | A | Broken PQXDH, weak RNG, side-channel leak |
| Consensus failure (chain forks, double-spend) | Major | A | Byzantine quorum exceeded, VRF bias |
| Message loss (messages not delivered/recoverable) | Major | A | Truncation error, WAL corruption |

The safety assessment is maintained in `doc/safety-assessment.md` (created Phase 7) and reviewed at each phase gate.

## Industry-Standard Security Practices

The following practices supplement (not replace) the DAL A requirements above, providing defense-in-depth aligned with industry norms for cryptographic and protocol software.

### Fuzzing

Continuous fuzzing campaigns using AFL and libFuzzer targeting:
- **Crypto primitives**: All generated C and Haskell implementations fuzzed with random inputs to detect crashes, hangs, and memory errors. Minimum 10^9 executions per primitive before release.
- **CBOR parser**: Grammar-aware fuzzing of the CBOR decoder with malformed, truncated, and oversized inputs. Must produce graceful errors (never crash or allocate unbounded memory).
- **Network message handling**: Fuzz all Noise_IK handshake and gossip message parsers with arbitrary byte sequences.

Fuzz corpora and crash reproducers stored in `test/evidence/fuzzing/`.

### NIST Known Answer Tests (KATs)

All cryptographic primitives are validated against the complete NIST CAVP / RFC test vector suites:
- SHA-256, SHA-512: CAVP Byte/Monte Carlo vectors
- AES-256-GCM: CAVP GCM encrypt/decrypt vectors
- ML-KEM-768: FIPS 203 KAT vectors
- Ed25519, X25519: RFC 8032 / RFC 7748 vectors
- HKDF, HMAC: RFC 5869 / RFC 2104 vectors
- ECVRF: RFC 9381 vectors

KAT results are generated on every commit and stored in `test/evidence/kat-results/`.

### Property-Based Testing

QuickCheck property tests verify algebraic and domain-specific invariants:
- Round-trip encode/decode for all serialization formats
- Crypto composition properties (encrypt then decrypt recovers plaintext)
- Token conservation across all state transitions
- State machine invariant preservation across all reachable states

Minimum 1,000 cases per property (100,000 in nightly runs) with fixed seeds for reproducibility.

### External Security Audit

An independent security audit covers all DAL A components:
- **Scope**: Crypto primitives, protocol composition, consensus logic, token economics, constant-time C code
- **Timing**: After integration testing, during V&V evidence collection
- **Duration**: 4-6 weeks, followed by 2-3 weeks remediation
- **Deliverable**: Audit report and remediation evidence in `test/evidence/external-audit/`

## FFI C Code Verification

C code produced by code generators (for constant-time cryptographic operations) is also classified DAL A. Total C codebase is minimal: <2,000 LOC across all primitives. Verification approach:

1. **Equivalence testing**: Each C function is tested against the pure Haskell reference implementation with 10,000+ random inputs. All outputs must be byte-identical.
2. **Constant-time verification**: C code is verified for constant-time execution using ctgrind/dudect methodology. No secret-dependent branches or memory accesses.
3. **Independent review**: All C source is reviewed independently by a reviewer who did not write the generator. Review evidence stored in `test/evidence/ffi-review/`.
