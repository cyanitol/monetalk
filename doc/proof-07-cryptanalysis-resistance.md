# Proof-07: Cryptanalysis Resistance

**DO-333 Requirement:** REQ-CRYPTO-009, `doc/10-security.md` lines 134–156
**Source:** `doc/03-cryptography.md`, `doc/10-security.md`
**Assumptions used:** A1, A2, A3, A5, A6, A7' (see `doc/21-formal-proofs-index.md`).
A7' (Dandelion++ topology): adversary controls < 50% of network nodes by count.
Note: A4 (HMAC-SHA-512 PRF) is not directly invoked; HMAC resistance is
covered transitively via Proof-01 §2.
**Depends on:** Proof-01 (primitive reductions), Proof-02 (protocol security)

---

## Preamble

This document systematically analyses UmbraVox's resistance to known
cryptanalytic attack classes.  For each attack class, we identify which
primitives and protocol layers are targeted, state the resistance claim,
and prove or bound the adversary's advantage.  The goal is to demonstrate
that no known cryptanalytic technique reduces the effective security below
the λ = 128 target.

The analysis covers:
1. Classical algebraic/structural attacks on each primitive
2. Side-channel attacks (timing, power, cache)
3. Quantum cryptanalysis (Grover, Shor, lattice)
4. Protocol-level attacks (key reuse, nonce misuse, related-key)
5. Implementation-level attacks (fault injection, state recovery)
6. Traffic analysis and metadata inference

---

## 1. Differential and Linear Cryptanalysis

### 1.1 AES-256

**Attack class:** Differential cryptanalysis (Biham & Shamir 1991),
linear cryptanalysis (Matsui 1993).

**Resistance claim:** AES-256 with 14 rounds is immune to both attacks (A3).

**Analysis:**

The AES wide-trail design strategy guarantees that any 4-round
differential characteristic has at least 25 active S-boxes (Daemen &
Rijmen 2002).  Each active S-box contributes a maximum differential
probability of 2^{-6}, giving:

```
Pr[4-round differential] ≤ (2^{-6})^{25} = 2^{-150}
```

For the full 14 rounds (≥ 3 independent 4-round groups), the best
known differential characteristic has probability bounded well below
2^{-128}.  Data complexity for any differential attack exceeds the
codebook size (2^{128}), making the attack infeasible.

By the same wide-trail argument, with 25 active S-boxes and maximum
per-S-box linear correlation 2^{-3} (equivalently, bias 2^{-4}, since
bias = correlation/2 per the piling-up lemma convention), the maximum
linear correlation over 4 rounds is at most (2^{-3})^{25} = 2^{-75},
requiring data complexity 1/correlation² = 2^{150} known plaintexts.  Linear cryptanalysis of 14
rounds requires ≥ 2^{150} known plaintexts, exceeding the codebook.

**UmbraVox context:** Each AES-256-GCM key encrypts at most ~1000 messages
(ratchet chain length) before re-keying.  An adversary sees at most ~1000
ciphertexts per key, far below the 2^{128} minimum for any structural
attack.  **Immune.**

### 1.2 ChaCha20

**Attack class:** Differential cryptanalysis of ARX (addition-rotation-XOR)
ciphers.

**Resistance claim:** No known differential with useful probability
exists for the full 20-round ChaCha20 (A6).

**Analysis:**

The best attack on reduced-round ChaCha covers 7.5 of 20 rounds
(Coutinho & Neto 2023, ~2^{206}; earlier: 7 rounds at ~2^{218},
Shi et al. 2022).  The full 20-round
cipher has no known attack faster than brute force (2^{256}).

ChaCha20's quarter-round function achieves full diffusion in 4 rounds.
After 20 rounds, every output bit depends on every input bit through
at least 5 complete diffusion layers.

**UmbraVox context:** ChaCha20 is used as CSPRNG with 256-bit keys and
periodic reseeding.  **Immune.**

### 1.3 SHA-256 / SHA-512

**Attack class:** Differential path attacks (Wang et al. 2005 for MD5/SHA-1).

**Resistance claim:** No collision attack on full SHA-256 or SHA-512
faster than birthday bound.

**Analysis:**

The best known attack reaches 38 of 64 rounds for SHA-256 (Eichlseder,
Mendel & Schläffer 2020) with impractical complexity.  SHA-512 (80 rounds) has even larger
margin.  The Merkle-Damgård structure with Davies-Meyer compression
provides collision resistance reducible to compression function resistance.

**UmbraVox context:** SHA-256 used for block hashing and Merkle trees;
SHA-512 used within Ed25519 and HMAC.  Birthday-bound collision resistance
(128 bits for SHA-256, 256 bits for SHA-512).  **Immune.**

---

## 2. Algebraic and Structural Attacks

### 2.1 Curve25519 — Rho and Index Calculus

**Attack class:** Pollard's rho (generic ECDLP), index calculus.

**Resistance claim:** Best attack requires O(2^{126}) group operations (A1).

**Analysis:**

Pollard's rho algorithm solves ECDLP in O(√q) ≈ O(2^{126}) operations
for Curve25519 (group order q ≈ 2^{252}).  Index calculus methods do not
apply to prime-order elliptic curves over large prime fields (no
subexponential factorisation structure).

Special attacks on Montgomery curves:
- **Twist attacks:** Curve25519 is twist-secure (twist has near-prime order).
  X25519 maps invalid points to the twist, which has comparable DLP
  hardness.  No security loss.
- **Small subgroup attacks:** Curve25519 has cofactor 8.  X25519
  applies scalar clamping (RFC 7748: clearing the three lowest bits),
  forcing the scalar to be a multiple of 8 and annihilating any
  small-subgroup component.  No information leakage.

**UmbraVox context:** X25519 used for DH in PQXDH and ratchet steps.
~126-bit classical security (Pollard's rho: √q ≈ 2^{126}).  **Immune to classical algebraic attacks.**

### 2.2 Ed25519 — Signature Forgery

**Attack class:** Lattice-based forgery, fault attacks on nonce generation.

**Resistance claim:** EUF-CMA under DLP (A5; Proof-01 §6).

**Critical implementation requirement:** Ed25519 nonce is deterministic:
r = SHA-512(prefix || m), where prefix = bytes 32..63 of SHA-512(sk)
(the upper half of the expanded key; the lower 32 bytes are clamped to
form the scalar).  This eliminates the catastrophic failure mode
of ECDSA (nonce reuse → private key recovery, as in the PlayStation 3
hack).

**Lattice attack on biased nonces:** If the nonce generation were biased
(leaking even 2–3 bits per signature), the Howgrave-Graham & Smart (2001)
lattice attack could recover the private key from ~100 signatures.
UmbraVox's deterministic nonce (RFC 8032) produces no bias — the nonce
is a full SHA-512 hash output, computationally indistinguishable from
uniform.

**Verification:**
- Deterministic nonces: confirmed (PureEd25519, `doc/03-cryptography.md` line 23).
- No nonce reuse possible: nonce is a deterministic function of (sk, m).
- No nonce bias: SHA-512 output is computationally uniform.

**Immune to nonce-based signature forgery.**

### 2.3 ML-KEM-768 — Lattice Attacks

**Attack class:** BKZ lattice reduction, primal/dual attacks on Module-LWE.

**Resistance claim:** NIST Category 3 — ~182-bit classical, ~128-bit
quantum security (A2).

**Analysis:**

The best known classical attack uses the BKZ algorithm with block size
β to solve the underlying SVP:

```
Time ≈ 2^{0.292β}    (classical BKZ, Becker et al. 2016)
Time ≈ 2^{0.265β}    (quantum BKZ, Laarhoven 2015)
```

For ML-KEM-768 (n=256, k=3, q=3329):

```
Required β ≈ 625     (NIST estimate)
Classical: 2^{0.292 × 625} ≈ 2^{182}
Quantum:   2^{0.265 × 625} ≈ 2^{166}
```

Conservative (core-SVP) quantum estimate: ~128 bits.  The gap between the full BKZ estimate (~166 bits) and the core-SVP estimate (~128 bits) reflects that core-SVP counts only the cost of the innermost SVP oracle call, not the full BKZ enumeration cost; NIST uses the conservative core-SVP metric for its Category designations.

**Known attack variants:**
- **Hybrid attack (Howgrave-Graham 2007):** Combines lattice reduction with
  meet-in-the-middle.  Not faster than pure BKZ for ML-KEM-768 parameters.
- **Algebraic attacks on module structure:** Module-LWE → LWE reduction
  (Langlois & Stehlé 2015) loses at most a polynomial factor.  No known
  attack exploits the module structure to gain more than this.
- **Side-channel on decapsulation:** Implicit rejection in ML-KEM
  (FIPS 203) prevents chosen-ciphertext side channels.  Decapsulation
  timing must be constant-time (see §3).

**UmbraVox context:** ML-KEM-768 used in PQXDH and PQ ratchet refreshes.
**Immune to known lattice attacks at 128+ quantum bits.**

### 2.4 GHASH — Algebraic Forgery

**Attack class:** Polynomial evaluation forgery over GF(2^{128}).

**Resistance claim:** Forgery probability ≤ d/2^{128} per attempt, where
d is the number of authenticated blocks (d ≤ 2^{36} for maximum GCM size).

**Analysis:**

GHASH authenticates by evaluating a polynomial over GF(2^{128}) at a
secret point H = AES(k, 0).  The adversary must guess the evaluation of a
degree-d polynomial at an unknown point.  By the Schwartz-Zippel lemma:

```
Pr[forgery] ≤ d / 2^{128}
```

For messages up to 2^{36} blocks (maximum GCM size): d ≤ 2^{36}, so:

```
Pr[forgery] ≤ 2^{36} / 2^{128} = 2^{-92}
```

**Nonce reuse catastrophe:** If a GCM nonce is reused with the same key,
the adversary can recover H via polynomial GCD and forge arbitrary messages.
This is the single most critical implementation requirement for GCM.

**UmbraVox mitigation:** Nonces are derived from the ratchet state's
monotonic message counter (Proof-01 §4.5).  Each ratchet chain uses a
unique key, and the counter never repeats within a chain.  Nonce reuse
is structurally impossible unless the ratchet state is corrupted.

**Immune, conditional on ratchet state integrity.**

---

## 3. Side-Channel Attacks

### 3.1 Timing Attacks

**Attack class:** Cache-timing (Bernstein 2005), remote timing
(Brumley & Tuveri 2011).

**Vulnerable operations and mitigations:**

| Operation | Timing Risk | Mitigation |
|-----------|------------|------------|
| AES S-box lookup | Table-indexed: cache-line dependent | Constant-time bitsliced or AES-NI; FFI to C for production (`doc/10-security.md`) |
| X25519 scalar multiply | Conditional branches on secret scalar bits | Montgomery ladder is inherently constant-time (no branching on secret) |
| Ed25519 signing | Nonce-dependent scalar multiply | Fixed-window scalar multiplication; constant-time reduction |
| ML-KEM decaps | Rejection branch | Implicit rejection: both paths compute same-cost operations |
| GHASH multiply | GF(2^128) operand-dependent | Carryless multiply instruction (PCLMULQDQ) or constant-time schoolbook |
| HMAC | Message length | Length leaked is acceptable (not secret in UmbraVox's usage) |
| VRF evaluation | Secret key bits | Same as Ed25519 scalar multiply |

**Requirement 3.1 (Constant-Time Implementation).**

All cryptographic operations must be implemented in constant time (no
secret-dependent branches or memory accesses).  Under this requirement,
timing observations provide zero additional advantage:

```
Adv^timing(A) = 0
```

**Justification.**  A constant-time implementation, by definition, has
execution time independent of secret inputs.  The timing channel carries
zero Shannon information about secrets, so the adversary's view is
identical regardless of the secret value.  This is a security requirement,
not a proven property of the current implementation — it must be verified
via testing (Dudect methodology, §3.3) and enforced by using FFI to
constant-time C implementations for production deployment.

**Implementation note:** The pure Haskell implementation may not be
constant-time (GHC runtime makes no such guarantees).  Production
deployment requires FFI to constant-time C implementations
(`doc/10-security.md` threat matrix: "Crypto timing side-channels").
The formal security claim applies to the constant-time C path.  □

### 3.2 Power Analysis

**Attack class:** Simple power analysis (SPA), differential power analysis
(DPA, Kocher et al. 1999).

**Resistance claim:** Relevant only for hardware/embedded deployment.

**Analysis:**

SPA can recover secret scalar bits from a single power trace of scalar
multiplication if the implementation uses non-constant-time algorithms
(e.g., double-and-add with branching).

**UmbraVox mitigations:**
- Montgomery ladder for X25519: inherently SPA-resistant (same operations
  regardless of scalar bits).
- Fixed-window scalar multiplication for Ed25519: uniform operation sequence.
- ML-KEM: NTT operations are data-independent (same butterfly pattern
  regardless of coefficients).

DPA requires many traces with the same key.  UmbraVox's frequent re-keying
(ratchet steps, PQ refreshes every 50 messages) limits the adversary to
~50 encryptions per key, far below the ~10,000 traces typically needed for
DPA on AES.

**Immune under constant-time implementation and ratchet re-keying.**

### 3.3 Cache Attacks

**Attack class:** Flush+Reload (Yarom & Falkner 2014), Prime+Probe
(Liu et al. 2015).

**Resistance claim:** Eliminated by constant-time implementation with no
secret-dependent memory accesses.

**Critical primitive:** AES with lookup tables is vulnerable.  Mitigations:
1. AES-NI hardware instructions (no table lookups).
2. Bitsliced software AES (no data-dependent memory access).
3. UmbraVox's hand-implemented AES (`doc/03-cryptography.md` line 5) must
   use one of these approaches for production.

**Verification requirement:** The `test/evidence/timing/` test suite must
verify that execution time is statistically independent of secret inputs
(Dudect methodology, Reparaz et al. 2017).

---

## 4. Quantum Cryptanalysis

### 4.1 Grover's Algorithm

**Attack class:** Quadratic speedup on unstructured search.

**Impact on symmetric primitives:**

| Primitive | Classical | Grover | Post-Grover Security |
|-----------|-----------|--------|---------------------|
| AES-256 | 2^{256} | 2^{128} | 128 bits ✓ |
| SHA-256 (preimage) | 2^{256} | 2^{128} | 128 bits ✓ |
| SHA-256 (collision) | 2^{128} | 2^{85} (BHT) | 85 bits ⚠ |
| HMAC-SHA-512 | 2^{256} | 2^{128} | 128 bits ✓ |
| ChaCha20 | 2^{256} | 2^{128} | 128 bits ✓ |

**SHA-256 collision under quantum (BHT algorithm):**

The Brassard-Hoyer-Tapp (BHT) algorithm finds collisions in O(2^{n/3})
quantum queries for an n-bit hash.  For SHA-256: 2^{256/3} ≈ 2^{85}.

**UmbraVox impact:** Block hash collisions at 85-bit quantum security.
This is a concern for long-term security but does not affect message
confidentiality (which relies on AES-256 and ML-KEM, both at 128 quantum
bits).

**Mitigation:** If quantum collision attacks become practical, the block
hashing algorithm can be upgraded to SHA-512 (170-bit quantum collision
resistance) or SHA-3 via chain revision (`doc/04-consensus.md` lines
270–289).

### 4.2 Shor's Algorithm

**Attack class:** Polynomial-time factoring and discrete logarithm.

**Impact on asymmetric primitives:**

| Primitive | Classical | Shor | UmbraVox Impact |
|-----------|-----------|------|-----------------|
| X25519 (CDH) | 2^{126} | Poly | DH ratchet broken |
| Ed25519 (DLP) | 2^{126} | Poly | Signatures forgeable |
| ECVRF (DDH) | 2^{126} | Poly | Leader election manipulable |

**UmbraVox's post-quantum strategy:**

1. **Message confidentiality (PROTECTED):** The PQ outer wrapper
   (ML-KEM-768) provides 128-bit quantum security.  Even if X25519 is
   broken, the inner Signal ciphertext is still wrapped in a
   quantum-resistant layer (Proof-02 §4, hybrid security argument).

2. **Harvest-now-decrypt-later (PROTECTED):** An adversary recording
   ciphertexts today cannot decrypt them with a future quantum computer
   because the ML-KEM layer is quantum-resistant.

3. **Authentication (VULNERABLE):** Ed25519 signatures on prekeys and
   transactions are broken by Shor.  A quantum adversary could forge
   prekey signatures to mount MITM attacks on future key agreements.
   **Mitigation path:** Upgrade to a PQ signature scheme (e.g., ML-DSA,
   SLH-DSA) via chain revision.

4. **Consensus (VULNERABLE):** ECVRF is broken by Shor, allowing
   leader election manipulation.  **Mitigation path:** Replace with a
   lattice-based or hash-based VRF via chain revision.

**Theorem 4.1 (Quantum Confidentiality).**

Against a quantum adversary with a cryptographically relevant quantum
computer (CRQC), message confidentiality is maintained at 128-bit security:

```
Adv^{quantum-conf}(A) ≤ Adv^{quantum-CCA}_{ML-KEM-768}(A')
                       + Adv^{quantum-PRP}_{AES-256}(A'')
                       ≤ negl(128)
```

**Proof.**  The adversary can break the Signal layer (X25519 CDH broken
by Shor), reducing the composed encryption to the PQ wrapper alone.  By
Proof-02 §4 (hybrid security), the PQ wrapper independently provides
IND-CCA2 under Module-LWE.  Module-LWE at ML-KEM-768 parameters provides
128-bit quantum security.  AES-256-GCM provides 128-bit security under
Grover.  □

### 4.3 Lattice Quantum Attacks

**Attack class:** Quantum lattice sieving (Laarhoven 2015), quantum BKZ.

**Impact on ML-KEM-768:**

```
Quantum BKZ time ≈ 2^{0.265β}
For β ≈ 625: 2^{0.265 × 625} ≈ 2^{166}
Conservative (core-SVP): ~128 bits
```

The NIST Category 3 designation means ML-KEM-768 is at least as hard to
break as performing a key search on AES-192 (~192 bits classical security).
The quantum security estimate depends on the cost model: the full quantum
BKZ estimate gives ~166 bits, while the conservative core-SVP metric
(counting only the dominant SVP oracle call) gives ~128 bits.  UmbraVox
uses the conservative core-SVP figure of 128 bits as the quantum security
target, aligning with λ = 128.

**No known quantum algorithm breaks Module-LWE faster than quantum BKZ.**

---

## 5. Protocol-Level Cryptanalytic Attacks

### 5.1 Key Reuse Across Contexts

**Attack class:** Cross-protocol attacks from key reuse (Bhargavan &
Leurent 2016).

**UmbraVox analysis:**

| Key | Contexts Used | Domain Separation |
|-----|--------------|-------------------|
| Identity key (IK) | PQXDH DH, SPK signing | DH vs. signature use different algorithms (X25519 vs. Ed25519 on birationally equivalent curve representations) |
| Ephemeral key (EK) | Single PQXDH session | Fresh per session, never reused |
| Root key (RK) | HKDF input for chain keys | Domain-separated by info string "UmbraVox_Ratchet_v1" |
| PQ chain key | HKDF input for message keys | Domain-separated; per-message counter |
| VRF key | ECVRF evaluation | Dedicated Ed25519 keypair distinct from message signing identity key; no cross-context use between VRF evaluation and message signing |

**Theorem 5.1 (No Cross-Context Key Leakage).**

UmbraVox's key hierarchy uses domain-separated HKDF derivation at every
branch point.  No key is used in two different cryptographic operations
without domain separation.

**Proof.**

1. **IK (identity key):** Used as X25519 private key (Curve25519,
   Montgomery form) and Ed25519 signing key (twisted Edwards form).
   These are birationally equivalent curves, but the operations are
   algebraically distinct (ECDH vs. Schnorr signing) with different
   base points under each representation; the same scalar produces
   public keys related by the birational map, but no known attack
   relates X25519 DH output to Ed25519 signature forgery.

2. **HKDF domain separation:** All HKDF calls use distinct info strings:
   - PQXDH master secret: `"UmbraVox_PQXDH_v1"`
   - Signal ratchet root key: `"UmbraVox_Ratchet_v1"`
   - PQ chain key derivation: `"UmbraVox_PQChain_v1"`
   - PQ per-message key derivation: `"UmbraVox_PQMsg_v1"`
   - HMAC chain key derivation: `"UmbraVox_HMAC_v1"`
   - The info string is bound into the PRF output (HKDF-Expand), making
     outputs from different contexts computationally independent.

3. **Chain key → message key separation:** `MK = HMAC(CK, 0x01)`,
   `CK_next = HMAC(CK, 0x02)`.  The constant bytes 0x01 and 0x02 serve
   as domain separators within the chain.

No key is used raw in two different algorithms or contexts.  □

### 5.2 Nonce Misuse Resistance

**Attack class:** GCM nonce reuse → authentication key recovery.

**Theorem 5.2 (Structural Nonce Uniqueness).**

Under correct ratchet operation, no (key, nonce) pair is ever repeated
in AES-256-GCM encryption.

**Proof.**

The GCM nonce is derived from the ratchet state:

```
nonce = encode_12bytes(chain_id, message_number)
```

Within a single ratchet chain (single key):
- `message_number` is a monotonic counter, incremented for each message.
- Counter overflow (> 2^{32}) triggers mandatory ratchet step (new key).
- Therefore, nonces are unique within a key's lifetime.

Across ratchet chains:
- Each chain uses a different key (derived from fresh DH or ML-KEM output).
- Nonce reuse across different keys is harmless (GCM security is per-key).

**Failure mode:** If ratchet state is corrupted (e.g., counter reset), nonce
reuse becomes possible.  Mitigation: ratchet state is stored encrypted
with integrity protection (HKDF-derived storage key + HMAC).  Corruption
is detected and the session is terminated.  □

### 5.3 Related-Key Attacks

**Attack class:** Related-key differentials on AES (Biryukov & Khovratovich
2009).

**Resistance claim:** Not applicable to UmbraVox.

**Analysis:**

Related-key attacks require the adversary to observe encryptions under keys
with known relationships (e.g., K and K ⊕ Δ).  In UmbraVox, all keys are
derived via HKDF from independent random sources (DH outputs, ML-KEM
shared secrets).  The adversary has no control over key relationships.

HKDF outputs are computationally independent of each other (PRF property),
so no useful key relationship exists between any two ratchet keys.

**Immune.**

### 5.4 Multi-Key Attacks

**Attack class:** Multi-key/multi-target security degradation (generic bound;
Bellare, Boldyreva & Micali 2000).

**Threat:** With N active sessions, each using a different AES-256 key,
the adversary's advantage in breaking *any one* key increases by factor N
(generic multi-key bound).

**UmbraVox analysis:**

```
Adv^{multi-key}(A) ≤ N · Adv^{single-key}(A)
```

For N = 10^6 concurrent sessions, using per-key AEAD security ~106 bits
(Proof-01 §4.6, accounting for ~1000 messages of up to 64 KiB per ratchet chain):
```
Adv ≤ 10^6 · 2^{-106} ≈ 2^{-86}
```

Still well above 80-bit practical threshold.  With ratchet re-keying
(~1000 messages per key), the effective per-key ciphertext count is
small, and the multi-key advantage remains negligible.

**Immune for practical session counts.**

---

## 6. Traffic Analysis and Metadata Attacks

### 6.1 Message Length Analysis

**Attack class:** Plaintext length inference from ciphertext length.

**UmbraVox mitigation:** Messages are padded to 1024-byte blocks
(`doc/03-cryptography.md`).  The adversary observes only the number of
blocks, not the exact plaintext length.

**Residual leakage:** The number of 1024-byte blocks reveals the message
size to within 1024 bytes.  For a typical chat message (< 1024 bytes),
all messages produce a single block — no length information is leaked.

For longer messages, the adversary learns ⌈length/1024⌉.  This is an
accepted trade-off between bandwidth efficiency and metadata protection.

### 6.2 Timing Correlation

**Attack class:** Inter-message timing analysis to infer conversation
patterns.

**UmbraVox mitigations:**
- **Dandelion++ stem phase:** Randomised routing delays during propagation.
- **11-day truncation:** Historical timing data is erased.
- **No padding of inter-message intervals** (v1 limitation).

**Residual risk:** An adversary observing the blockchain in real time can
correlate transaction timestamps with external events.  V1 mitigations
(stealth addresses, encrypted headers, fixed fees, uniform blocks) reduce
on-chain metadata exposure (`doc/10-security.md` threat matrix: "On-chain
metadata" rated LOW (V1 mitigated)).

### 6.3 Graph Analysis of Communication Patterns

**Attack class:** Social graph inference from sender/recipient addresses.

**UmbraVox v1 mitigations:** Stealth addresses (DKSAP) are mandatory in V1.
Each transaction uses a one-time derived address:
```
stealth_addr = H(r · PK_recipient) · G + PK_recipient
```

This breaks the link between transactions and long-term identities.
Combined with encrypted headers, fixed fees, uniform block sizes, and
address rotation, the communication graph is not constructible from
on-chain data alone.

### 6.4 Dandelion++ Deanonymisation

**Attack class:** Topology inference to link transactions to IP addresses.

**Resistance analysis:**

Dandelion++ provides sender anonymity through a two-phase propagation:

1. **Stem phase:** Transaction forwarded along a random path (each node
   forwards to exactly one peer, chosen per epoch).
2. **Fluff phase:** After a geometric random number of hops (E[hops] ≈ 10),
   the transaction is broadcast via standard gossip.

**Theorem 6.1 (Dandelion++ Anonymity Bound).**

For an adversary controlling a fraction p < 0.5 of network nodes (A7'),
the probability of correctly identifying the transaction source is:

```
Pr[correct attribution] ≤ p + (1-p) · p^{h}
```

where h is the stem length (geometric, E[h] ≈ 10).

For p = 0.20 (adversary controls 20% of nodes):
```
Pr[correct] ≤ 0.20 + 0.80 · 0.20^{10} ≈ 0.20 + 8.2 × 10^{-8} ≈ 0.20
```

The adversary's success probability is approximately their network fraction,
no better than random guessing among their observed peers.  Note: This is a simplified upper bound assuming the adversary gains no information from partial stem observation. A full analysis (Fanti et al. 2018) shows that Dandelion++ achieves near-optimal source anonymity among all graph-based propagation mechanisms, with the adversary's precision degrading exponentially in the stem length.

**Proof sketch.**  The adversary can only identify the source if:
1. The source is one of their controlled nodes (probability p), OR
2. All h stem-phase nodes are controlled by the adversary (probability p^h),
   allowing them to trace back to the source.

For h ≥ 10 and p < 0.5, the second term is negligible.  □

---

## 7. State Recovery and Fault Attacks

### 7.1 Cold Boot Attacks

**Attack class:** DRAM remanence (Halderman et al. 2008).

**UmbraVox mitigations:**
- Ratchet keys are erased after use (forward secrecy).
- At most ~1000 skipped message keys in memory (~64 KB).
- Long-term keys are encrypted at rest with passphrase-derived key
  (HKDF from Argon2id output).

**Residual risk:** A cold boot attack captures the current ratchet state.
Forward secrecy protects past messages; post-compromise security restores
confidentiality after the next DH ratchet step (Proof-02 §2.2).

### 7.2 Fault Injection

**Attack class:** Bellcore attack on RSA/CRT (Boneh et al. 1997),
differential fault analysis on AES (Piret & Quisquater 2003).

**Applicability to UmbraVox:**

- **AES:** A single fault during the penultimate round can reveal the key
  with 2 faulty ciphertexts.  Mitigation: encrypt-then-verify (GCM
  authentication tag catches faulted ciphertexts before delivery).
- **Ed25519:** A fault during signing could produce an invalid signature
  that leaks the private key.  Mitigation: verify the signature after
  signing (sign-then-verify pattern).
- **ML-KEM:** Faults during decapsulation could leak the secret key.
  Mitigation: implicit rejection (FO transform) means faulted
  decapsulation produces a pseudorandom output, not the correct shared
  secret.

**Implementation requirement:** All signing operations must verify their
output before releasing it.  All decryption operations must verify the
authentication tag before processing the plaintext.

### 7.3 State Compromise Recovery Timeline

After full state compromise, the recovery timeline for each property:

| Property | Recovery Mechanism | Time to Restore |
|----------|-------------------|-----------------|
| PQ confidentiality | Next PQ ratchet refresh (50 msgs) | Minutes to hours |
| Classical confidentiality | Next DH ratchet step | Next message exchange |
| Forward secrecy (PQ) | PQ ratchet refresh | ≤ 50 messages |
| Forward secrecy (DH) | DH ratchet step | Next message exchange |
| Authentication | Cannot recover without new key agreement | Requires session reset |

---

## 8. Comprehensive Security Budget

The following table gives the effective security level for each attack
class, identifying the binding constraint:

| Attack Class | Target | Effective Security (bits) | Binding Constraint |
|-------------|--------|--------------------------|-------------------|
| Brute force (classical) | AES-256 | 256 | Key space |
| Brute force (Grover) | AES-256 | 128 | Grover quadratic speedup |
| Differential/linear | AES-256 | >256 | Data complexity exceeds codebook |
| Birthday+GHASH (per-key AEAD) | AES-256-GCM | 106 | PRP-PRF switching + GHASH forgery, q_e≈10³, L≈2^{12} |
| Pollard's rho | X25519 | 126 | √q on Curve25519 |
| Shor (quantum) | X25519 | 0 | **Mitigated by ML-KEM wrapper** |
| BKZ (classical) | ML-KEM-768 | 182 | Lattice dimension |
| BKZ (quantum) | ML-KEM-768 | 128 | Core-SVP quantum |
| Nonce reuse | AES-GCM | ∞ (structurally prevented) | Ratchet monotonic counter |
| Related-key | AES-256 | N/A (no key relations) | HKDF independence |
| Timing | All | 0 leakage (constant-time) | Implementation requirement |
| Power/fault | Ed25519, AES | Mitigated | Sign-verify, GCM auth |
| Traffic analysis | Metadata | COMPREHENSIVE (v1) | Stealth addresses (DKSAP), encrypted headers, fixed fees, uniform blocks |
| Cold boot | RAM state | Forward secrecy | Ratchet erasure |

**Minimum effective security for message confidentiality: ~106 bits
classical per-key** (bound by AES-256-GCM birthday + GHASH forgery terms
for ~1000 messages of up to 64 KiB per ratchet chain; see Proof-01 §4.6).  **128 bits quantum**
(bound by ML-KEM-768 and AES-256 under Grover).

**Minimum effective security for authentication: 126 bits classical, 0 bits
quantum** (bound by Ed25519 DLP; quantum mitigation requires PQ signature
upgrade).

---

## 9. Summary of Findings

1. **No known classical cryptanalytic attack reduces any primitive below
   ~106-bit per-key security.** The per-key AEAD bound is ~106 bits
   (AES-256-GCM birthday + GHASH forgery terms for ~1000 messages of up
   to 64 KiB per ratchet chain).
   The weakest asymmetric primitive is Ed25519/ECVRF at ~126 bits
   (Pollard's rho on the ~252-bit group order).

2. **Message confidentiality is quantum-resistant at 128 bits** via the
   ML-KEM-768 outer wrapper, even if all classical-only primitives are
   broken.

3. **Authentication and consensus are NOT quantum-resistant** (Ed25519 and
   ECVRF are broken by Shor).  Migration to PQ signatures is required
   before CRQC availability.  Chain revision mechanism supports this upgrade.

4. **Side-channel resistance requires constant-time C implementations.**
   The pure Haskell path is for correctness verification; production
   deployment must use the FFI path with verified constant-time properties.

5. **Nonce reuse is structurally prevented** by the ratchet's monotonic
   counter.  This is the most critical implementation invariant for AES-GCM
   security.

6. **On-chain metadata protection is comprehensive in v1.** Stealth addresses
   (DKSAP), encrypted headers, fixed fees, uniform blocks, and address rotation
   prevent communication graph construction from on-chain data alone.

7. **Ratchet re-keying limits exposure** to side-channel, multi-key, and
   state compromise attacks by bounding the number of operations per key
   to ~50–1000.
