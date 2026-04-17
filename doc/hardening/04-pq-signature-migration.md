# Hardening-04: Post-Quantum Signature Migration

**Status:** Draft
**Supersedes:** Ed25519-only authentication (`doc/03-cryptography.md` line 14)
**Depends on:** `doc/04-consensus.md` (chain revision mechanism, lines 270-289)
**References:** FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), RFC 8032 (Ed25519), RFC 9381 (ECVRF)

---

## 1. Motivation

Ed25519 (RFC 8032) relies on the hardness of the Elliptic Curve Discrete Logarithm Problem (ECDLP) on Curve25519. Shor's algorithm solves ECDLP in polynomial time on a cryptographically relevant quantum computer (CRQC), reducing Ed25519's effective authentication security to zero bits against a quantum adversary (`doc/proof-07-cryptanalysis-resistance.md` Section 4.2).

UmbraVox's message confidentiality is already quantum-resistant via the ML-KEM-768 outer wrapper. However, the following remain vulnerable:

- **Transaction signatures** (block headers, all transaction types)
- **Signed prekey (SPK) signatures** in the Signal key bundle
- **ECVRF-ED25519-SHA512** used for PoS slot leader election
- **Heartbeat challenge responses** signed by validators

This document specifies the complete migration path from Ed25519 to post-quantum signatures.

---

## 2. Replacement Candidates

### 2.1 Comparison Table

| Property | Ed25519 (current) | ML-DSA-65 (FIPS 204) | SLH-DSA-128s (FIPS 205) |
|----------|-------------------|----------------------|-------------------------|
| **Standard** | RFC 8032 | FIPS 204 (Dilithium3) | FIPS 205 (SPHINCS+-128s) |
| **Security basis** | ECDLP | Module-LWE + SelfTargetMSIS | Hash (second preimage) |
| **NIST PQ category** | N/A (broken by Shor) | Category 3 | Category 1 |
| **Classical security** | ~128 bits | ~192 bits | ~128 bits |
| **Quantum security** | 0 bits | ~128 bits | ~128 bits |
| **Public key size** | 32 bytes | 1,952 bytes | 32 bytes |
| **Signature size** | 64 bytes | 3,293 bytes | 7,856 bytes |
| **Key pair size (sk)** | 64 bytes | 4,032 bytes | 64 bytes |
| **Sign time** | ~50 us | ~200 us | ~3,000 ms |
| **Verify time** | ~120 us | ~100 us | ~5 ms |
| **Deterministic** | Yes | Yes (hedged) | Yes |
| **Hash-only security** | No | No (lattice) | Yes |
| **Standardised** | RFC 8032 | FIPS 204 (2024) | FIPS 205 (2024) |

### 2.2 ML-DSA-65 (Dilithium3, FIPS 204)

**Structure:** Lattice-based signature over Module-LWE/SelfTargetMSIS. Security derives from the hardness of finding short vectors in structured lattices.

**Strengths:**
- Compact signatures (3,293 bytes) relative to hash-based alternatives
- Fast verification (~100 us), faster than Ed25519
- NIST Category 3 (equivalent to AES-192 quantum resistance)
- Deterministic signing with hedged randomness (fault resistance)

**Weaknesses:**
- Large public keys (1,952 bytes)
- Security depends on lattice assumptions (newer, less studied than hash functions)
- Signing ~4x slower than Ed25519

### 2.3 SLH-DSA-128s (SPHINCS+-128s, FIPS 205)

**Structure:** Stateless hash-based signature scheme. Security relies only on the second-preimage resistance of the underlying hash function (SHA-256 or SHAKE-256).

**Strengths:**
- Security assumption is minimal: hash function second-preimage resistance
- Small public keys (32 bytes)
- Small secret keys (64 bytes)
- Conservative "known good" assumption family (decades of hash function analysis)

**Weaknesses:**
- Very large signatures (7,856 bytes)
- Extremely slow signing (~3 seconds)
- Slower verification (~5 ms)
- NIST Category 1 (equivalent to AES-128 quantum resistance)

---

## 3. Recommended Choice

**Primary: ML-DSA-65** -- Used for all routine signing operations (transactions, block headers, heartbeat responses, SPK signatures). The compact signature size (3,293 bytes vs. 7,856 bytes) is critical for blockchain bandwidth. Verification is fast enough for block validation at the 11-second slot interval.

**Conservative fallback: SLH-DSA-128s** -- Available as an alternative if a cryptanalytic advance weakens Module-LWE. Hash-based security is the most conservative assumption available. Activation via a subsequent chain revision if needed.

**Rationale:** ML-DSA-65 at Category 3 exceeds UmbraVox's 128-bit quantum security target. SLH-DSA-128s is retained as a fallback because its security assumption (hash second-preimage resistance) is fundamentally different from and better understood than lattice assumptions. If Module-LWE is unexpectedly broken, hash-based signatures remain secure.

---

## 4. Hybrid Signature Scheme

During the transition period, all signatures use a hybrid construction: Ed25519 + ML-DSA-65.

### 4.1 Hybrid Signature Construction

```
HybridSign(sk_ed, sk_ml, message):
  sig_ed  = Ed25519_Sign(sk_ed, message)
  sig_ml  = ML_DSA_65_Sign(sk_ml, message)
  return HybridSig { hsEdSig = sig_ed, hsMlSig = sig_ml }

HybridVerify(pk_ed, pk_ml, message, hybrid_sig):
  ed_valid = Ed25519_Verify(pk_ed, message, hybrid_sig.hsEdSig)
  ml_valid = ML_DSA_65_Verify(pk_ml, message, hybrid_sig.hsMlSig)
  return ed_valid OR ml_valid    -- either sufficient for acceptance
```

### 4.2 Signing and Verification Policy

| Phase | Signing requirement | Verification acceptance |
|-------|--------------------|-----------------------|
| Pre-migration (current) | Ed25519 only | Ed25519 only |
| Transition (chain rev N+1) | MUST produce both Ed25519 + ML-DSA-65 | Accept if EITHER is valid |
| Post-transition (chain rev N+2) | ML-DSA-65 only (Ed25519 optional) | ML-DSA-65 required |
| Emergency fallback (chain rev N+3, if needed) | SLH-DSA-128s | SLH-DSA-128s required |

### 4.3 Defense-in-Depth Rationale

During transition, both signatures are REQUIRED for signing but EITHER is sufficient for verification. This provides:

1. **Forward security:** If Ed25519 is broken (Shor), the ML-DSA-65 signature remains valid. Verification succeeds via the PQ path.
2. **Conservative security:** If ML-DSA-65 is broken (unexpected lattice attack), the Ed25519 signature remains valid. Verification succeeds via the classical path.
3. **Smooth upgrade:** Nodes that have upgraded produce hybrid signatures. Old nodes (within the 3-revision compatibility window) can still verify the Ed25519 component.

---

## 5. Transaction Format Changes

### 5.1 Current Signature Field (Chain Revision N)

```haskell
data TxSigned = TxSigned
  { txBody      :: !TxBody
  , txSignature :: !Ed25519Sig       -- 64 bytes
  , txPubKey    :: !Ed25519PubKey    -- 32 bytes
  }
-- Total signature overhead: 96 bytes
```

### 5.2 Hybrid Signature Field (Chain Revision N+1)

```haskell
data HybridSig = HybridSig
  { hsEdSig :: !Ed25519Sig           -- 64 bytes
  , hsMlSig :: !MlDsa65Sig          -- 3,293 bytes
  }

data HybridPubKey = HybridPubKey
  { hpEdPk :: !Ed25519PubKey         -- 32 bytes
  , hpMlPk :: !MlDsa65PubKey        -- 1,952 bytes
  }

data TxSigned = TxSigned
  { txBody      :: !TxBody
  , txSignature :: !HybridSig        -- 3,357 bytes
  , txPubKey    :: !HybridPubKey     -- 1,984 bytes
  }
-- Total signature overhead: 5,341 bytes
```

### 5.3 Post-Transition Signature Field (Chain Revision N+2)

```haskell
data TxSigned = TxSigned
  { txBody      :: !TxBody
  , txSignature :: !MlDsa65Sig       -- 3,293 bytes
  , txPubKey    :: !MlDsa65PubKey    -- 1,952 bytes
  }
-- Total signature overhead: 5,245 bytes
```

### 5.4 Block Header Changes

```haskell
-- Chain Revision N+1 (transition)
data BlockHeader = BlockHeader
  { bhSlotNo      :: !Word64
  , bhBlockNo     :: !Word64
  , bhPrevHash    :: !ByteString         -- 32 bytes, SHA-256
  , bhBodyHash    :: !ByteString         -- 32 bytes
  , bhIssuerVK    :: !HybridPubKey       -- 1,984 bytes (was 32 bytes)
  , bhVRFProof    :: !ByteString         -- see Section 9 (VRF migration)
  , bhVRFOutput   :: !ByteString
  , bhSignature   :: !HybridSig          -- 3,357 bytes (was 64 bytes)
  , bhHeartbeat   :: !(Maybe HeartbeatChallenge)
  }
```

### 5.5 Backward Compatibility via Chain Revision

Per `doc/04-consensus.md` lines 270-289, the `EpochGenesis` block carries `egChainRevision :: Word32`. Software must support the current revision plus 3 prior revisions.

**Compatibility matrix:**

| Software version | Supports revisions | Produces | Accepts |
|-----------------|-------------------|----------|---------|
| Pre-upgrade | N, N-1, N-2, N-3 | Rev N (Ed25519) | Rev N only |
| Transition | N+1, N, N-1, N-2 | Rev N+1 (hybrid) | Rev N and N+1 |
| Post-transition | N+2, N+1, N, N-1 | Rev N+2 (ML-DSA) | Rev N+1 and N+2 |

Nodes running pre-upgrade software that have not updated within the 3-revision window will reject blocks at revision N+2 and must upgrade. This is the intended forcing function.

### 5.6 Serialisation Format

All hybrid signature fields are serialised with explicit length prefixes to allow forward-compatible parsing:

```
HybridSig wire format:
  [1 byte]  sig_type   = 0x02 (hybrid)
  [2 bytes] ed_len     = 64 (big-endian uint16)
  [64 bytes] ed_sig
  [2 bytes] ml_len     = 3293 (big-endian uint16)
  [3293 bytes] ml_sig
  Total: 3,362 bytes

HybridPubKey wire format:
  [1 byte]  key_type   = 0x02 (hybrid)
  [2 bytes] ed_len     = 32 (big-endian uint16)
  [32 bytes] ed_pk
  [2 bytes] ml_len     = 1952 (big-endian uint16)
  [1952 bytes] ml_pk
  Total: 1,989 bytes
```

Type byte values:

| Value | Meaning |
|-------|---------|
| 0x01 | Ed25519 only (legacy) |
| 0x02 | Hybrid Ed25519 + ML-DSA-65 |
| 0x03 | ML-DSA-65 only |
| 0x04 | SLH-DSA-128s only (emergency) |

---

## 6. Key Management

### 6.1 PQ Key Pair Generation

ML-DSA-65 key generation follows FIPS 204 Section 6:

```
ML_DSA_65_KeyGen():
  seed = CSPRNG(32)              -- from ChaCha20-based CSPRNG (doc/03-cryptography.md line 40)
  (pk, sk) = ML_DSA_65_KeyGen_Internal(seed)
  -- pk: 1,952 bytes
  -- sk: 4,032 bytes
  return (pk, sk)
```

Both the pure Haskell reference implementation and the constant-time C FFI implementation are generated from the FIPS 204 specification, following the dual-output code generation model (`doc/03-cryptography.md` lines 52-58).

### 6.2 Key Storage Size Impact

| Key type | Current (Ed25519) | Hybrid (Ed25519 + ML-DSA-65) | ML-DSA-65 only |
|----------|-------------------|------------------------------|----------------|
| Public key | 32 bytes | 1,984 bytes | 1,952 bytes |
| Secret key | 64 bytes | 4,096 bytes | 4,032 bytes |
| Total per identity | 96 bytes | 6,080 bytes | 5,984 bytes |
| **Size multiplier** | 1x | ~63x | ~62x |

### 6.3 Key Storage Encryption

PQ secret keys are stored encrypted at rest using the same mechanism as current Ed25519 keys: AES-256-GCM with a key derived via HKDF from an Argon2id-processed passphrase. The increased key size (4,032 bytes vs. 64 bytes) has no impact on the storage encryption scheme itself, only on the encrypted blob size.

### 6.4 Prekey Bundle Size Impact on PQXDH

The on-chain prekey bundle published via `KEY_REGISTER` transactions includes the identity public key. Size impact:

| Bundle component | Current size | Hybrid size | Delta |
|-----------------|-------------|-------------|-------|
| Identity key (IK) | 32 bytes | 1,984 bytes | +1,952 bytes |
| Signed prekey (SPK) | 32 bytes | 32 bytes | 0 (X25519, unchanged) |
| SPK signature | 64 bytes | 3,362 bytes | +3,298 bytes (see Section 7) |
| 100 OPKs | 3,200 bytes | 3,200 bytes | 0 (X25519, unchanged) |
| PQPK (ML-KEM-768) | 1,184 bytes | 1,184 bytes | 0 (unchanged) |
| **Total bundle** | **4,512 bytes** | **9,762 bytes** | **+5,250 bytes** |

The `KEY_REGISTER` transaction grows by ~5.2 KB. This is a one-time cost per identity registration. The `KEY_REPLENISH` transaction (50 OPKs) is unaffected since OPKs remain X25519.

---

## 7. SPK (Signed PreKey) Migration

### 7.1 Current SPK Signing

The SPK is an X25519 public key signed by the identity key:

```
Current:
  spk_sig = Ed25519_Sign(ik_secret, spk_public)
  -- 64-byte signature
```

### 7.2 Hybrid SPK Signing (Transition)

During the transition phase, the SPK is signed with both keys:

```
Transition:
  spk_sig = HybridSign(ik_ed_secret, ik_ml_secret, spk_public)
  -- 3,362-byte hybrid signature
```

Session establishment (PQXDH step 2, `doc/03-cryptography.md` line 98) changes:

```
Current:
  Verify SPK signature (Ed25519)

Transition:
  Verify SPK signature (HybridVerify -- accept if either component valid)
```

### 7.3 Bundle Verification During Mixed-Version Period

When Alice fetches Bob's prekey bundle:
- If Bob is on Rev N+1: bundle contains `HybridPubKey` + `HybridSig` on SPK. Alice verifies using `HybridVerify`.
- If Bob is on Rev N (legacy): bundle contains `Ed25519PubKey` + `Ed25519Sig` on SPK. Alice verifies using `Ed25519_Verify`. Alice proceeds with classical-only session establishment but logs a security downgrade event.

### 7.4 SPK Rotation Continuity

SPK rotation (every ~48 hours, `doc/03-cryptography.md` line 82) continues unchanged. The rotation transaction (`KEY_ROTATE`) carries the new SPK and its signature. During transition, the signature field uses the hybrid format.

---

## 8. VRF Migration

### 8.1 Current VRF

ECVRF-ED25519-SHA512-ELL2 (RFC 9381) is used for slot leader election (`doc/04-consensus.md` lines 55-67). Shor's algorithm breaks the ECDLP underlying this VRF, allowing a quantum adversary to:

1. Forge VRF proofs for arbitrary inputs
2. Predict slot leadership for any validator whose public key is known
3. Manipulate leader election to control block production

### 8.2 Replacement: Hash-Based VRF (ECVRF-MLDSA-SHA512)

A post-quantum VRF is constructed from ML-DSA-65 and SHA-512:

```
PQ_VRF_Prove(sk_ml, alpha):
  -- alpha = epoch_nonce || slot_number
  hash_input = SHA-512("UmbraVox_PQVRF_v1" || alpha)
  proof      = ML_DSA_65_Sign(sk_ml, hash_input)
  output     = SHA-512(proof)        -- deterministic output from proof
  return (proof, output)

PQ_VRF_Verify(pk_ml, alpha, proof, output):
  hash_input = SHA-512("UmbraVox_PQVRF_v1" || alpha)
  valid_sig  = ML_DSA_65_Verify(pk_ml, hash_input, proof)
  valid_out  = (output == SHA-512(proof))
  return valid_sig AND valid_out
```

**Security properties preserved:**

| Property | ECVRF-ED25519 | PQ-VRF (ML-DSA-65 based) |
|----------|---------------|--------------------------|
| Uniqueness | DLP-based | Module-LWE + SelfTargetMSIS |
| Pseudorandomness | DDH | PRF from SHA-512 |
| Verifiability | Signature verification | ML-DSA-65 verification |
| Collision resistance | SHA-512 | SHA-512 |
| Quantum resistance | No | Yes (Category 3) |

**Important caveat:** This construction provides verifiable pseudorandomness but does NOT satisfy the strict "unique output" property of a classical VRF (where each input maps to exactly one output under a given key). ML-DSA-65 uses hedged randomness, so `ML_DSA_65_Sign(sk, m)` may produce different signatures for the same `(sk, m)` across invocations. To enforce uniqueness:

```
PQ_VRF_Prove(sk_ml, alpha):
  hash_input = SHA-512("UmbraVox_PQVRF_v1" || alpha)
  -- Derandomise: use deterministic signing with explicit seed
  seed       = HMAC-SHA-512(sk_ml[0..31], hash_input)
  proof      = ML_DSA_65_Sign_Deterministic(sk_ml, hash_input, seed)
  output     = SHA-512(proof)
  return (proof, output)
```

The `ML_DSA_65_Sign_Deterministic` variant fixes the internal randomness to the derived seed, ensuring the same `(sk, alpha)` always produces the same `(proof, output)`. This is analogous to Ed25519's deterministic nonce generation.

### 8.3 VRF Output and Threshold

VRF output remains 64 bytes (SHA-512). The threshold computation (`doc/04-consensus.md` lines 69-92) is unchanged. Only the proof generation and verification functions change.

### 8.4 VRF Proof Size Impact

| Field | Current (ECVRF) | PQ-VRF (ML-DSA-65) | Delta |
|-------|----------------|---------------------|-------|
| `bhVRFProof` | 80 bytes | 3,293 bytes | +3,213 bytes |
| `bhVRFOutput` | 64 bytes | 64 bytes | 0 |

Block header grows by ~3.2 KB due to larger VRF proof.

### 8.5 Impact on Consensus

- **Leader election fairness:** Unchanged. VRF output distribution remains uniform (SHA-512 of a valid signature is indistinguishable from random).
- **Verification cost:** ML-DSA-65 verification (~100 us) is faster than ECVRF verification (~200 us). Block validation throughput improves.
- **Proof generation cost:** ML-DSA-65 signing (~200 us) is slower than ECVRF proving (~100 us). Slot leaders have a slightly longer proof computation, but well within the 11-second slot window.

---

## 9. Heartbeat Challenge Migration

### 9.1 Current Heartbeat Response

```
response = Ed25519_Sign(challenge || validator_pubkey, validator_secret_key)
-- 64 bytes
```

Per `doc/04-consensus.md` lines 186-209.

### 9.2 Hybrid Heartbeat Response (Transition)

```
response = HybridSign(
  validator_ed_sk,
  validator_ml_sk,
  challenge || validator_hybrid_pubkey
)
-- 3,362 bytes
```

### 9.3 Post-Transition Heartbeat Response

```
response = ML_DSA_65_Sign(
  validator_ml_sk,
  challenge || validator_ml_pubkey
)
-- 3,293 bytes
```

### 9.4 Bandwidth Impact

Heartbeat frequency: 1 challenge per 100 slots (~18.3 minutes). With ~100 active validators, each challenge cycle produces ~100 responses.

| Phase | Response size | Per-challenge total | Per-epoch total (~39 challenges) |
|-------|-------------|--------------------|---------------------------------|
| Current | 64 bytes | 6.4 KB | 0.25 MB |
| Hybrid | 3,362 bytes | 336 KB | 13.1 MB |
| Post-transition | 3,293 bytes | 329 KB | 12.8 MB |

The ~50x increase in heartbeat bandwidth is significant but manageable within modern network capacity. At one challenge per 18.3 minutes, the sustained heartbeat bandwidth is ~0.3 KB/s (hybrid) vs. ~6 B/s (current).

---

## 10. Chain Revision Plan

### 10.1 Revision Schedule

| Revision | Content | Minimum software version |
|----------|---------|------------------------|
| N (current) | Ed25519 only | v1.x |
| **N+1** | **Hybrid Ed25519 + ML-DSA-65** | **v2.0** |
| **N+2** | **ML-DSA-65 only (Ed25519 dropped)** | **v2.1** |
| N+3 (contingency) | SLH-DSA-128s fallback | v2.2 |

### 10.2 Activation Mechanism

1. **Software release:** v2.0 is released containing hybrid signature support. Validators upgrade at their discretion.
2. **Signaling:** Once upgraded, validators include a `PQ_READY` flag in blocks they produce. This flag is an informational bit in the block header; it has no consensus effect.
3. **Activation threshold:** When 80% of blocks in the most recent epoch carry the `PQ_READY` flag, the next epoch genesis block increments `egChainRevision` to N+1.
4. **Enforcement:** From the activation epoch onward, all new transactions and block headers MUST use hybrid signatures. Transactions with Ed25519-only signatures are rejected by validators running v2.0+.
5. **Grace period:** Nodes running pre-upgrade software can still validate blocks for 3 more revisions (the compatibility window from `doc/04-consensus.md` line 285). They verify the Ed25519 component of hybrid signatures and ignore the ML-DSA-65 component.

### 10.3 Rev N+1 to N+2 Transition

After Rev N+1 has been active for a minimum of 4 full cycles (~44 days):

1. Validators signal `PQ_ONLY_READY` in block headers.
2. At 80% signaling threshold, the next epoch genesis increments to Rev N+2.
3. From N+2 onward, Ed25519 signatures are no longer required or verified.
4. Nodes still on Rev N (3 revisions behind N+2 = outside compatibility window) are excluded from the network.

### 10.4 Rollback Safety

**Rev N+1 rollback to N:** Safe. If a critical bug is found in the ML-DSA-65 implementation during the hybrid phase, validators can release v2.0.1 that produces Ed25519-only signatures and sets `egChainRevision` back to N. The Ed25519 component of all hybrid signatures remains valid. No chain history is invalidated.

**Rev N+2 rollback to N+1:** Safe. Re-enable hybrid signing. All Rev N+2 blocks contain valid ML-DSA-65 signatures, which remain valid under Rev N+1 verification rules (either component sufficient).

**Rev N+2 rollback to N:** NOT safe. Rev N+2 blocks do not contain Ed25519 signatures. A rollback to N would invalidate all blocks produced under Rev N+2. This rollback is prohibited; it would require a coordinated hard fork.

### 10.5 Emergency SLH-DSA Activation (Rev N+3)

If a practical attack on Module-LWE is published:

1. Emergency software release v2.2 with SLH-DSA-128s support.
2. Immediate activation: no 80% signaling threshold. A special `EMERGENCY_REVISION` transaction signed by 2/3+ of the current validator set (by stake weight) triggers immediate revision increment.
3. SLH-DSA-128s replaces ML-DSA-65 for all signatures.
4. Block time tolerance may need adjustment: SLH-DSA signing takes ~3 seconds, which consumes a significant fraction of the 11-second slot window. Mitigation: pre-compute signatures for anticipated slot leadership (VRF is evaluated before the slot begins).

---

## 11. Timeline Triggers

Migration is triggered by external cryptographic milestones, not by a fixed calendar date.

### 11.1 Proactive Triggers (Recommended)

| Trigger | Action |
|---------|--------|
| NIST finalises FIPS 204 and FIPS 205 (completed August 2024) | Begin implementation of ML-DSA-65 and SLH-DSA-128s |
| UmbraVox v2.0 implementation complete and tested | Release v2.0 to validators |
| 80% validator adoption of v2.0 | Activate Rev N+1 (hybrid) |
| Rev N+1 stable for 4 cycles (~44 days) | Begin Rev N+2 signaling |
| 80% validator signaling for PQ_ONLY | Activate Rev N+2 (ML-DSA only) |

### 11.2 Reactive Triggers (Emergency)

| Trigger | Action |
|---------|--------|
| CRQC demonstrated breaking 256-bit ECDLP | Immediate Rev N+1 activation (skip signaling) |
| Credible CRQC timeline < 5 years (e.g., NIST/NSA advisory) | Accelerate Rev N+1 to N+2 transition (reduce 44-day wait) |
| Published attack on Module-LWE below 100-bit security | Activate Rev N+3 (SLH-DSA fallback) |

### 11.3 Quantum Threat Assessment Criteria

The decision to accelerate migration is based on:

1. **Logical qubit count demonstrated:** Current CRQC estimates require ~4,000 logical qubits for 256-bit ECDLP. Monitor published results.
2. **Error correction overhead reduction:** Track improvements in surface code and other QEC schemes.
3. **Government advisories:** NSA CNSA 2.0, NIST PQC timeline guidance, EU Quantum Flagship assessments.
4. **Published pre-prints:** Peer-reviewed advances in Shor variants or fault-tolerant quantum architectures.

---

## 12. Performance Impact

### 12.1 Signing and Verification Time

All benchmarks assume constant-time C FFI implementations on commodity hardware (x86-64, 3 GHz, single core).

| Operation | Ed25519 | ML-DSA-65 | Hybrid (both) | SLH-DSA-128s |
|-----------|---------|-----------|---------------|--------------|
| Key generation | 30 us | 150 us | 180 us | 15 ms |
| Sign | 50 us | 200 us | 250 us | 3,000 ms |
| Verify | 120 us | 100 us | 220 us | 5 ms |

### 12.2 Block Validation Throughput

Per block with ~20 transactions:

| Phase | Signature verification time | Within slot window? |
|-------|---------------------------|-------------------|
| Current (Ed25519) | 20 * 120 us = 2.4 ms | Yes (11s slot) |
| Hybrid | 20 * 220 us = 4.4 ms | Yes |
| ML-DSA-65 only | 20 * 100 us = 2.0 ms | Yes (faster than current) |
| SLH-DSA-128s | 20 * 5 ms = 100 ms | Yes, but tight at scale |

### 12.3 Bandwidth Increase

| Component | Current size | Hybrid size | ML-DSA only | Increase factor |
|-----------|-------------|-------------|-------------|-----------------|
| Transaction sig + pk | 96 bytes | 5,351 bytes | 5,245 bytes | ~55x |
| Block header sig + pk + VRF | 176 bytes | 8,694 bytes | 7,309 bytes | ~42x |
| Heartbeat response | 64 bytes | 3,362 bytes | 3,293 bytes | ~51x |
| KEY_REGISTER bundle | 4,512 bytes | 9,762 bytes | 9,698 bytes | ~2.2x |

### 12.4 Block Size Impact

Assuming 20 transactions per block:

| Phase | Block overhead (headers + sigs) | Estimated block size |
|-------|-------------------------------|---------------------|
| Current | ~2.1 KB | ~22 KB |
| Hybrid | ~115 KB | ~135 KB |
| ML-DSA-65 only | ~112 KB | ~132 KB |

Block size increases by approximately 6x. This is within the capacity of modern networks (132 KB every ~55 seconds = ~2.4 KB/s sustained block bandwidth). The 11-day truncation cycle bounds total chain growth.

---

## 13. Formal Security Proof: Hybrid Signature EUF-CMA

### 13.1 Definitions

Let `SIG_ed = (KeyGen_ed, Sign_ed, Verify_ed)` be the Ed25519 signature scheme and `SIG_ml = (KeyGen_ml, Sign_ml, Verify_ml)` be the ML-DSA-65 signature scheme.

The hybrid scheme `SIG_hyb = (KeyGen_hyb, Sign_hyb, Verify_hyb)` is defined as:

```
KeyGen_hyb():
  (pk_ed, sk_ed) = KeyGen_ed()
  (pk_ml, sk_ml) = KeyGen_ml()
  pk = (pk_ed, pk_ml)
  sk = (sk_ed, sk_ml)
  return (pk, sk)

Sign_hyb(sk, m):
  sig_ed = Sign_ed(sk_ed, m)
  sig_ml = Sign_ml(sk_ml, m)
  return (sig_ed, sig_ml)

Verify_hyb(pk, m, (sig_ed, sig_ml)):
  return Verify_ed(pk_ed, m, sig_ed) OR Verify_ml(pk_ml, m, sig_ml)
```

### 13.2 Security Claim

**Theorem 13.1 (Hybrid EUF-CMA).** The hybrid signature scheme `SIG_hyb` is EUF-CMA secure if EITHER `SIG_ed` is EUF-CMA secure under the DLP assumption on Curve25519 OR `SIG_ml` is EUF-CMA secure under the Module-LWE and SelfTargetMSIS assumptions.

Formally:

```
Adv^{EUF-CMA}_{SIG_hyb}(A) <= Adv^{EUF-CMA}_{SIG_ed}(A') + Adv^{EUF-CMA}_{SIG_ml}(A'')
```

where A' and A'' are efficient adversaries derived from A.

### 13.3 Proof

**Proof.** Assume toward contradiction that an adversary A can forge a hybrid signature with non-negligible advantage. That is, A outputs `(m*, (sig_ed*, sig_ml*))` such that:

1. `m*` was never queried to the signing oracle.
2. `Verify_hyb(pk, m*, (sig_ed*, sig_ml*)) = true`.

By the verification rule, condition (2) means:

```
Verify_ed(pk_ed, m*, sig_ed*) = true  OR  Verify_ml(pk_ml, m*, sig_ml*) = true
```

**Case 1:** `Verify_ed(pk_ed, m*, sig_ed*) = true`.

Construct adversary A' against `SIG_ed`: A' receives `pk_ed` from its EUF-CMA challenger, generates `(pk_ml, sk_ml)` independently, provides `pk = (pk_ed, pk_ml)` to A. When A queries the hybrid signing oracle on message m, A' queries its own Ed25519 signing oracle to get `sig_ed` and computes `sig_ml = Sign_ml(sk_ml, m)` directly. When A outputs a forgery where the Ed25519 component verifies, A' outputs `(m*, sig_ed*)` as its Ed25519 forgery.

A' has the same advantage as A in this case, contradicting the EUF-CMA security of Ed25519 under DLP.

**Case 2:** `Verify_ml(pk_ml, m*, sig_ml*) = true`.

Construct adversary A'' against `SIG_ml` symmetrically: A'' receives `pk_ml` from its ML-DSA challenger, generates `(pk_ed, sk_ed)` independently, and simulates the hybrid oracle. When A outputs a forgery where the ML-DSA component verifies, A'' outputs `(m*, sig_ml*)` as its ML-DSA forgery.

A'' has the same advantage as A in this case, contradicting the EUF-CMA security of ML-DSA-65 under Module-LWE and SelfTargetMSIS.

Since both cases lead to contradiction under their respective assumptions, it suffices that at least one assumption holds. Therefore:

```
Adv^{EUF-CMA}_{SIG_hyb}(A) <= Adv^{EUF-CMA}_{SIG_ed}(A') + Adv^{EUF-CMA}_{SIG_ml}(A'')
```

If either `Adv^{EUF-CMA}_{SIG_ed}` or `Adv^{EUF-CMA}_{SIG_ml}` is negligible, then the hybrid scheme is EUF-CMA secure. The hybrid scheme is secure if EITHER the DLP on Curve25519 is hard (classical assumption) OR Module-LWE is hard (post-quantum assumption). This is the desired "defense in depth" property.  []

### 13.4 Formal Verification Requirement

Per DO-178C DAL A / DO-333 requirements (`doc/10-security.md` lines 146-156), the above proof must be formalised in Coq as a machine-checkable artifact.

**Deliverable:** `test/evidence/formal-proofs/hybrid-sig-euf-cma.v`

The Coq proof must:
1. Define the hybrid signature game explicitly.
2. Construct the reductions A' and A'' as concrete Coq functions.
3. Prove the advantage bound as a Coq theorem.
4. State all assumptions (DLP hardness, Module-LWE hardness) as axioms with explicit documentation.

---

## 14. Implementation Checklist

| Task | Module | Dependency |
|------|--------|------------|
| Implement ML-DSA-65 (pure Haskell + FFI C) | `UmbraVox.Crypto.MlDsa65` | FIPS 204 spec |
| Implement SLH-DSA-128s (pure Haskell + FFI C) | `UmbraVox.Crypto.SlhDsa128s` | FIPS 205 spec |
| Cross-validate ML-DSA-65: 10,000+ random inputs, Haskell vs FFI | `test/UmbraVox/Crypto/MlDsa65Test` | ML-DSA impl |
| Cross-validate SLH-DSA-128s: 10,000+ random inputs | `test/UmbraVox/Crypto/SlhDsa128sTest` | SLH-DSA impl |
| NIST KAT vectors for ML-DSA-65 | `test/vectors/ml-dsa-65/` | NIST ACVP |
| NIST KAT vectors for SLH-DSA-128s | `test/vectors/slh-dsa-128s/` | NIST ACVP |
| Implement HybridSig / HybridPubKey types | `UmbraVox.Crypto.Hybrid` | ML-DSA impl |
| Update transaction serialisation for type-tagged sigs | `UmbraVox.Chain.Tx` | HybridSig types |
| Update block header serialisation | `UmbraVox.Chain.Block` | HybridSig types |
| Implement PQ-VRF (deterministic ML-DSA based) | `UmbraVox.Consensus.PqVrf` | ML-DSA impl |
| Update VRF leader election to use PQ-VRF | `UmbraVox.Consensus.SlotLeader` | PQ-VRF impl |
| Update heartbeat response signing/verification | `UmbraVox.Consensus.Heartbeat` | HybridSig types |
| Update SPK signing in prekey bundle | `UmbraVox.Signal.PrekeyBundle` | HybridSig types |
| Update KEY_REGISTER / KEY_ROTATE tx handling | `UmbraVox.Chain.KeyRegistry` | Bundle format |
| Chain revision N+1 activation logic | `UmbraVox.Chain.Revision` | Block header changes |
| PQ_READY signaling in block production | `UmbraVox.Consensus.BlockProd` | Revision logic |
| Constant-time C implementation: timing test (Dudect) | `test/evidence/timing/` | FFI impls |
| Formal proof: hybrid EUF-CMA (Coq) | `test/evidence/formal-proofs/` | Proof artifact |
| Performance benchmarks: sign/verify/block validation | `test/bench/` | All impls |

---

## 15. Open Questions

1. **ML-DSA-65 hedged randomness vs. deterministic:** FIPS 204 specifies hedged signing (internal randomness mixed with secret key). For VRF uniqueness, we require deterministic signing. Confirm that the deterministic variant (setting `rnd = 0x00*32` per FIPS 204 Section 3.2, ML-DSA.Sign with hedging disabled) is acceptable for VRF construction.

2. **SLH-DSA-128s slot timing:** SLH-DSA signing at ~3 seconds consumes ~27% of the 11-second slot duration. If SLH-DSA is activated as emergency fallback, either the slot duration must increase or validators must pre-sign for anticipated slots. Quantify the pre-signing window required.

3. **Aggregate signatures:** ML-DSA-65 does not natively support signature aggregation. For blocks with many transactions, the ~5 KB per-transaction signature overhead is substantial. Investigate whether Boneh-Lynn-Shacham (BLS) style aggregation can be adapted for lattice-based signatures in a future revision.
