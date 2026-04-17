# Verification Plan (DO-178C DAL A)

## Test Pyramid

```
                          /\
                         /  \  Acceptance Tests (11-day accelerated truncation cycle)
                        /    \   -- DAL A: full lifecycle validation
                       /------\
                      /        \  System Tests (5-10 node network simulation)
                     /          \   -- DAL A: adversarial scenarios, MC/DC
                    /------------\
                   /              \  Integration Tests (multi-module, e.g., Signal+PQ end-to-end)
                  /                \   -- DAL A: full state transition MC/DC
                 /------------------\
                /                    \  Unit Tests (generated KAT + property tests)
               /                      \   -- DAL A: NIST/RFC KAT vectors + MC/DC
              /________________________\
```

Economic simulation is a specialized System test (not a separate pyramid layer).

## Coverage Requirements

All DAL A modules: 100% MC/DC (Modified Condition/Decision Coverage)
- Every entry and exit point exercised
- Every decision outcome exercised independently
- Every condition shown to independently affect its decision

MC/DC coverage measured using the `UmbraVox.Coverage` instrumentation module (see `doc/13-do178c-assurance.md` "MC/DC Measurement Methodology for Haskell"). HPC provides line/branch baseline; custom condition tracking provides MC/DC. Target: 100% MC/DC for all DAL A modules.

## Continuous Pipeline

```
Every commit (~25 min):
  1. NIST KAT test suites (all CAVP/RFC vectors for every crypto primitive)
  2. Generated property tests (1,000 cases per property, QuickCheck)
  3. Generated state machine tests (all transition paths)
  4. MC/DC structural coverage analysis
  5. Token conservation invariant check

Nightly (~4 hours):
  6. Extended property tests (100,000 cases per property)
  7. 3-node integration (1-hour simulated cycle)
  8. Economic simulation (1,000 cycles, 100 validators): track cycle_duration distribution, early_truncation_count, adaptive parameter convergence, treasury trajectory
  9. Fuzzing campaigns:
     a. Crypto primitives: AFL + libFuzzer, minimum 10^8 executions per primitive per night
     b. CBOR parser: grammar-aware fuzzing with malformed/truncated/oversized inputs
     c. Network message handling: fuzz Noise_IK handshake and gossip message parsers

Weekly (~9 hours):
  10. Full 11-day truncation simulation (accelerated)
  11. Adversarial testing suite (spam, Sybil, eclipse)
  12. Coverage report generation + gap analysis
  13. Dandelion++ anonymity simulation (1,000 nodes)
  14. Fuzzing corpus review: triage new crash/hang findings, update corpora
```

## Industry-Standard Verification Practices

### NIST KAT Test Suites

All cryptographic primitives are validated against the complete NIST CAVP and RFC test vector suites on every commit:
- SHA-256, SHA-512: CAVP short message, long message, and Monte Carlo vectors
- AES-256-GCM: CAVP GCM encrypt/decrypt vectors (400+ vectors)
- ML-KEM-768: FIPS 203 KAT vectors (100 vectors)
- Ed25519: RFC 8032 test vectors
- X25519: RFC 7748 test vectors
- HKDF: RFC 5869 test vectors
- HMAC: RFC 2104 test vectors
- ECVRF: RFC 9381 test vectors
- ChaCha20: RFC 8439 test vectors

Both pure Haskell and FFI (C) paths are independently tested against these vectors. Results stored in `test/evidence/kat-results/`.

### Fuzzing Campaigns

Continuous fuzzing provides coverage beyond structured test vectors:
- **Crypto primitives**: AFL and libFuzzer targeting all generated C and Haskell implementations. Minimum 10^9 executions per primitive before release; 10^8 per nightly run.
- **CBOR parser**: Grammar-aware fuzzing of the decoder with malformed, truncated, and oversized inputs. Must produce graceful errors (never crash or allocate unbounded memory).
- **Network message handling**: Fuzz all Noise_IK handshake and gossip message parsers with arbitrary byte sequences.

Fuzz corpora, crash reproducers, and triage logs stored in `test/evidence/fuzzing/`.

### Property-Based Testing

QuickCheck property tests run alongside MC/DC structural coverage:
- 1,000 cases per property on every commit; 100,000 cases in nightly runs
- Fixed seed (`seed=42`) for reproducibility; additional random seeds in nightly runs
- Properties include: round-trip encode/decode, crypto composition (encrypt-then-decrypt), token conservation, state machine invariant preservation, VRF output distribution
- Property test results feed into MC/DC gap analysis to identify untested condition combinations

### External Audit Schedule

| Phase | Timing | Duration | Scope |
|-------|--------|----------|-------|
| Crypto audit | Weeks 60-62 | 3 weeks | All crypto primitives, constant-time C code, key management |
| Protocol audit | Weeks 62-65 | 3 weeks | Signal+PQ composition, consensus, Dandelion++ |
| Remediation | Weeks 65-68 | 3 weeks | Address all findings, re-verify affected modules |
| Re-audit (critical findings only) | Weeks 68-69 | 1 week | Verify remediation of critical/high findings |

Audit reports and remediation evidence stored in `test/evidence/external-audit/`.

## Formal Proofs

| Proof | Method | Target |
|-------|--------|--------|
| Consensus safety | TLA+ model checking | No disagreement on finalized blocks |
| Consensus liveness | TLA+ model checking | All valid TX eventually included |
| Crypto composition | Coq/TLA+ | Signal + PQ wrapper mutual independence |
| Token conservation | QuickCheck + proof | sum == 11B at all state transitions |
| VRF fairness | Statistical analysis | Leader frequency proportional to stake |
| Adaptive controller convergence | Control theory + simulation | Parameters converge within 5 cycles under bounded growth |
| Supply restoration correctness | QuickCheck + proof | pool(N+1) = INITIAL_SUPPLY - staked - reserve - treasury |
| Two-tier settlement | TLA+ + simulation | k=11 reversal ≤ 1/2,048; k=22 reversal ≤ 1/4.2M |
| Compact block relay | Integration test | Propagation within 11s slot for 4,444-txn blocks |
| Stealth address unlinkability | Statistical test | No distinguisher at p < 0.01 over 10,000 addresses |

### Universe Cycle Model Test Scenarios

```
Early truncation tests:
  - Early truncation fires correctly when supply drops below threshold
  - Early truncation does NOT fire when supply is above threshold
  - Early truncation does NOT fire during first epoch (minimum cycle duration)
  - Adaptive controller reduces burn rate after early truncation
  - Multiple consecutive early truncations converge burn rate toward floor

Supply restoration tests:
  - pool(N+1) = INITIAL_SUPPLY - staked - reserve - treasury (exact)
  - burned_total resets to 0 at every cycle boundary
  - Staked balances unchanged across cycle boundary
  - Treasury capped at 10% of INITIAL_SUPPLY; excess flows to pool

Adaptive controller tests:
  - Controller stabilizes within 5 cycles after 10x growth shock
  - All parameters remain within hard bounds at all times
  - 50% damping prevents oscillation (no parameter flip-flops between cycles)
  - Cycle duration within [0.5, 1.5] * target for >99% of simulated cycles

Supply depletion attack simulation:
  - Attacker spending maximum MTK triggers early truncation (graceful)
  - Adaptive controller compensates in next cycle
  - Network resumes normal operation within 2 cycles of attack

Two-tier settlement tests:
  - Message tier (k=11) settles within ~10 minutes under normal conditions
  - Value tier (k=22) settles within ~20 minutes under normal conditions
  - Block validation correctly marks transaction tier based on type field
  - Wallet UI correctly distinguishes "delivered" (k=11) vs "settled" (k=22)
  - Validators cannot spend block rewards before k=22 depth
  - Fee burns are immediate (no settlement delay)
  - Reversal probability at k=11: verify ~1/2,048 via simulation
  - Reversal probability at k=22: verify ~1/4,194,304 via simulation

Compact block relay tests:
  - Compact block creation with correct SipHash short IDs
  - Block reconstruction from mempool with 95%+ hit rate
  - Missing transaction request/response (GET_BLOCK_TXNS / BLOCK_TXNS)
  - Compact block propagation within 11-second slot boundary
  - Full block fallback for syncing/new nodes
  - High bandwidth mode: immediate compact block send on receipt
  - Low bandwidth mode: INV-first protocol
  - Compact block size verification: ~50-130 KB for 4,444-txn blocks

Stealth address V1 tests:
  - DKSAP round-trip: derive → scan → recover sk_stealth (10,000 cases)
  - PQ hybrid round-trip: derive_PQ → scan_PQ → recover (10,000 cases)
  - View tag filtering: 255/256 rejection rate over 100,000 trials
  - Stealth address scanning at 4,444 msgs/block: < 2s per block (single-threaded)
  - Parallel scanning: < 500ms per block on 4 cores
  - All transaction types use stealth addresses from genesis
  - No plaintext sender_address or recipient_address in V1 blocks

Metadata minimization V1 tests:
  - All transactions uniform 2-block size on-chain
  - msg_type encrypted inside payload (not visible on-chain)
  - Fixed fees: all transactions pay identical amount
  - Timestamp inside encrypted payload (only slot-level timing visible)
  - Signal ratchet pubkey inside encrypted payload
  - No communication graph constructible from on-chain data alone
  - Statistical indistinguishability test: observer cannot distinguish message types
```

### Formal Proof Specifications

**(a) Consensus TLA+**: Prove Safety (no two honest nodes finalize conflicting blocks) and Liveness (if <1/3 Byzantine, transactions eventually finalize). State space: up to 10^6 states explored using the TLC model checker. Timeout: 48 hours per run. Model parameters: 4-7 nodes, 3 rounds, two-tier finality (k_msg=11, k_val=22).

**(b) Crypto Coq**: Prove IND-CCA2 security of the Signal+PQ composition under the hybrid assumption (classical + post-quantum). Builds on existing Coq formalizations of X25519 (fiat-crypto) and HKDF. Deliverable: machine-checked proof in `test/evidence/formal-proofs/crypto-composition.v`.

**(c) Token conservation Coq**: Prove that all state transitions preserve `sum(tokens) = INITIAL_SUPPLY - burned`. This covers reward distribution, fee collection, burn, rebate, and wallet reset. Deliverable: `test/evidence/formal-proofs/token-conservation.v`.

**(d) VRF fairness**: Chi-squared test on 10^6 simulated leader elections. Null hypothesis: leader frequency is proportional to stake. Required: p-value > 0.01 (fail to reject fairness). Test repeated with 10 different seeds.

## Traceability

Full bidirectional traceability maintained in `doc/requirements-trace.md`:
```
Requirement → Design Document → Code Module → Test Case → Coverage Result
     ↑              ↑              ↑             ↑              ↑
     └──────────────└──────────────└─────────────└──────────────┘
```

The `doc/requirements-trace.md` file is generated from code annotations and test mappings. Each entry follows the format:

```
requirement_id → source_module:line → test_id → coverage_report
```

Example:
```
CRYPTO-001 → UmbraVox.Crypto.SHA256:45 → test_sha256_kat_001 → coverage/sha256.html
```

This file is populated incrementally during each development phase. Generation tool: `scripts/gen-trace.hs` (reads `{-# REQ "requirement_id" #-}` annotations from source and maps to test IDs via naming convention).
