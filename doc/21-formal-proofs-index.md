# 21. Formal Proofs — Index (DO-178C DAL A, DO-333)

## Purpose and Scope

This document indexes all formal proofs required by DO-333 (Formal Methods
Supplement to DO-178C) for UmbraVox DAL A certification.  Each proof is
self-contained in its own file with a preamble, assumptions, and full
derivation.  Together they satisfy the four formal-methods requirements
enumerated in `doc/10-security.md` lines 145–156 and the verification targets
in `doc/16-verification-plan.md` lines 104–152.

---

## Global Notation Conventions

| Symbol | Meaning |
|--------|---------|
| λ | Security parameter (λ = 128 for UmbraVox) |
| PPT | Probabilistic polynomial-time (adversary class) |
| Adv^X_Y(t,q) | Advantage of adversary Y against game X with time t, q queries |
| negl(λ) | Any function negligible in λ: ∀c, ∃N: f(n) < n^{-c} for n > N |
| ⊕ | Bitwise XOR |
| \|\| | Byte-string concatenation |
| ← | Deterministic assignment |
| ←$ | Uniform random sampling |
| [n] | The set {1, 2, …, n} |
| ℤ_q | Integers modulo q |

**Style guide.**  Theorems are stated with full quantifiers.  Proofs proceed
by reduction or hybrid game sequence.  TLA+ fragments use standard TLA+
syntax (Lamport 2002).  Coq-style fragments use `Theorem`/`Proof`/`Qed`
markers with Haskell-like pseudocode for readability.

---

## Global Assumptions Registry

Every proof file references assumptions by identifier (A1–A11 and A7').

| ID | Assumption | Formal Statement | Used In |
|----|-----------|------------------|---------|
| A1 | CDH on Curve25519 | For PPT A: Adv^CDH_{Curve25519}(A) ≤ negl(λ) | Proof-01 §3,§5, Proof-02 §1–§2,§4,§6, Proof-07 §2 |
| A2 | Module-LWE (k=3, q=3329) | For PPT A: Adv^MLWE_{3,3329}(A) ≤ negl(λ) | Proof-01 §3,§7, Proof-02 §1,§3–§6, Proof-07 §2 |
| A3 | AES-256 is a PRP | For PPT A: Adv^PRP_{AES-256}(A) ≤ negl(λ) | Proof-01 §4, Proof-02 §4,§6, Proof-07 §1 |
| A4 | SHA-512 compression function is a PRF | For PPT A: Adv^PRF_{SHA-512-cf}(A) ≤ negl(λ) | Proof-01 §2–§3,§9, Proof-02 §2,§4,§6 |
| A5 | DDH on Ed25519 curve | For PPT A: Adv^DDH_{Ed25519}(A) ≤ negl(λ) | Proof-01 §6,§8, Proof-02 §1, Proof-03 §6, Proof-05 §2, Proof-07 §2 |
| A6 | ChaCha20 core is a PRF | For PPT A: Adv^PRF_{ChaCha20}(A) ≤ negl(λ) | Proof-01 §9, Proof-07 §1.2 |
| A7 | Semi-synchronous network | Messages delivered within Δ slots (Δ bounded) | Proof-03 §2,§3 |
| A8 | Honest majority | Honest validators hold > 2/3 of total stake | Proof-03, Proof-05 |
| A9 | Bounded growth | Network grows at most 10× per 100 cycles | Proof-04, Proof-06 |
| A7' | Dandelion++ topology bound | Adversary controls fraction p < 0.5 of network nodes by count | Proof-07 §6.4 |
| A10 | HKDF in ROM | HKDF modelled as random oracle for extract; PRF for expand | Proof-01 §3,§9, Proof-02 §1–§6 |
| A11 | Reward floor threshold | Threshold uses pool_allocation/V where pool_allocation = pool × 0.85 | Proof-04 §Inv-5 |

---

## Proof Index

| # | Document | Scope | Method | DO-333 Req |
|---|----------|-------|--------|------------|
| 1 | [proof-01-primitive-security.md](proof-01-primitive-security.md) | 9 cryptographic primitives | Reduction proofs | REQ-CRYPTO-009 |
| 2 | [proof-02-protocol-security.md](proof-02-protocol-security.md) | X3DH, Double Ratchet, PQ wrapper, composition, E2E | Hybrid games, Coq-style | REQ-CRYPTO-009 |
| 3 | [proof-03-consensus.md](proof-03-consensus.md) | Safety, liveness, fork choice | TLA+ model | 10-security §145 line 152 |
| 4 | [proof-04-token-conservation.md](proof-04-token-conservation.md) | 12 economic invariants | Coq-style + QuickCheck | 10-security §145 lines 153–154 |
| 5 | [proof-05-vrf-fairness.md](proof-05-vrf-fairness.md) | Leader election proportionality | Statistical (χ²) | 10-security §145 line 154 |
| 6 | [proof-06-controller-convergence.md](proof-06-controller-convergence.md) | Adaptive parameter convergence | Control theory, Lyapunov | 10-security §145 line 153 |
| 7 | [proof-07-cryptanalysis-resistance.md](proof-07-cryptanalysis-resistance.md) | Resistance to all known attack classes | Attack taxonomy + bounds | REQ-CRYPTO-009, 10-security |

---

## Cross-Reference to Specification Documents

| Proof File | Primary Source | Secondary Sources |
|-----------|---------------|-------------------|
| proof-01 | doc/03-cryptography.md lines 5–199 | doc/10-security.md |
| proof-02 | doc/03-cryptography.md lines 87–228 | doc/10-security.md lines 145–148 |
| proof-03 | doc/04-consensus.md lines 11–163 | doc/10-security.md lines 149–152 |
| proof-04 | doc/15-economic-model-v3.md lines 15–32 | doc/06-economics.md lines 49–421, doc/20-economic-analysis.md lines 42–88 |
| proof-05 | doc/04-consensus.md lines 54–92 | doc/16-verification-plan.md lines 151–152 |
| proof-06 | doc/20-economic-analysis.md lines 186–258 | doc/06-economics.md lines 138–178 |
| proof-07 | doc/03-cryptography.md, doc/10-security.md | All primitive and protocol specs |

---

## Deliverable Locations

All proof artefacts will be stored under `test/evidence/formal-proofs/` (to be
generated during implementation phase):

```
test/evidence/formal-proofs/
├── crypto-composition.v          -- Coq source (Proof-02)
├── token-conservation.v          -- Coq source (Proof-04)
├── consensus-safety.tla          -- TLA+ spec  (Proof-03)
├── consensus-liveness.tla        -- TLA+ spec  (Proof-03)
├── vrf-fairness-sim.hs           -- Haskell simulation (Proof-05)
├── controller-convergence-sim.hs -- Haskell simulation (Proof-06)
├── cryptanalysis-test-vectors/   -- Attack resistance tests (Proof-07)
└── reports/
    ├── tlc-model-check.log       -- TLC output
    ├── chi-squared-results.csv   -- VRF fairness data
    └── convergence-plots.csv     -- Controller convergence data
```

---

## Version History

| Date | Change |
|------|--------|
| 2026-04-14 | Initial release — all 7 proof documents |
