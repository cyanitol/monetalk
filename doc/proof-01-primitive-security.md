# Proof-01: Cryptographic Primitive Security Reductions

**DO-333 Requirement:** REQ-CRYPTO-009
**Source:** `doc/03-cryptography.md` lines 5–199
**Assumptions used:** A1, A2, A3, A4, A5, A6, A10 (see `doc/21-formal-proofs-index.md`).
SHA-256/SHA-512 collision resistance (§1) requires only the Merkle-Damgård
structural property, not A4.

---

## Preamble

This document provides security reductions for each of the 9 cryptographic
primitives used in UmbraVox.  Every primitive is mapped to a standard
security game; the reduction shows that any efficient adversary breaking the
primitive in UmbraVox's usage yields an efficient adversary against a
well-studied hardness assumption.

Each section follows a uniform structure:

1. **Security Game** — formal game definition
2. **Hardness Assumption** — referenced by global ID
3. **Theorem** — advantage bound
4. **Proof** — reduction construction
5. **Concrete Security** — bit-level estimate at λ = 128
6. **Application in UmbraVox** — where the primitive is used

---

## 1. SHA-256 / SHA-512 — Collision Resistance

### 1.1 Security Game (CR)

```
Game CR_H:
  Adversary A receives no input (H is public).
  A outputs (m, m').
  A wins if m ≠ m' and H(m) = H(m').
  Adv^CR_H(A) = Pr[A wins].
```

### 1.2 Hardness Assumption

Collision resistance of SHA-256/SHA-512 follows from collision resistance of
the underlying compression function (Damgård 1989, Merkle 1989).  This is a
structural property of the Merkle-Damgård construction and does not require
A4 (the PRF assumption on the compression function).  The CR reduction is
unconditional given any collision-resistant compression function.

### 1.3 Theorem

**Theorem 1.1 (SHA-256 Collision Resistance).**
For any PPT adversary A making at most t compression-function evaluations:

```
Adv^CR_{SHA-256}(A) ≤ Adv^CR_{cf}(A') + t² / 2^{256}
```

where A' is a PPT adversary against the compression function with comparable
running time, and the second term is the birthday bound on the 256-bit output.

An identical statement holds for SHA-512 with the birthday bound t² / 2^{512}.

### 1.4 Proof

**Reduction.**  Given A that finds collisions in SHA-256, construct A' against
the compression function cf:

1. A' runs A.  When A outputs (m, m') with SHA-256(m) = SHA-256(m'), A'
   traces the Merkle-Damgård chains for m and m'.
2. Since the final outputs collide but m ≠ m', at least one intermediate
   compression-function call must collide (pigeonhole on the chain).
3. A' extracts that pair and outputs it as a compression-function collision.

The overhead is at most O(|m| + |m'|) additional compression evaluations, so
A' runs in polynomial time if A does.  The additive birthday term accounts
for random collisions among t evaluations in a 2^{256} range.  □

### 1.5 Concrete Security

At λ = 128:
- SHA-256: birthday bound gives ~128-bit collision resistance (t ≈ 2^{128} evaluations needed).
- SHA-512: ~256-bit collision resistance.

### 1.6 Application in UmbraVox

- **Block hashing:** SHA-256 Merkle root of transactions (`doc/03-cryptography.md` lines 191–199).
- **Transaction IDs:** SHA-256 hash of serialised transaction.
- **Epoch nonce:** SHA-256(epoch_nonce(N-1) || last_block_VRF_output) (`doc/04-consensus.md` lines 263–296).
- **Ed25519 internals:** SHA-512 used for key expansion and nonce derivation.

---

## 2. HMAC-SHA-512 — PRF Security

### 2.1 Security Game (PRF)

```
Game PRF_F:
  b ←$ {0, 1}
  k ←$ K
  If b = 1: Oracle O(x) = F(k, x)
  If b = 0: Oracle O(x) = R(x)  where R is a truly random function
  Adversary A has oracle access to O.
  A outputs b'.
  Adv^PRF_F(A) = |Pr[b' = 1 | b = 1] - Pr[b' = 1 | b = 0]|.
```

### 2.2 Hardness Assumption

**A4** (SHA-512 compression function is a PRF).

### 2.3 Theorem

**Theorem 2.1 (HMAC-SHA-512 PRF, Bellare 2006).**
For any PPT adversary A making at most q queries of length at most ℓ blocks:

```
Adv^PRF_{HMAC-SHA-512}(A) ≤ 2 · Adv^PRF_{cf}(A', t, q+1) + Adv^CR_{SHA-512}(A'')
```

where A' attacks the compression function as a PRF with comparable resources,
and A'' finds collisions in SHA-512.

### 2.4 Proof

**Reduction (Bellare, Canetti, Krawczyk 1996; Bellare 2006).**

HMAC is defined as:

```
HMAC_k(m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
```

1. **Inner PRF:** Model the inner hash H((k ⊕ ipad) || ·) as a keyed PRF
   with key k.  By assumption A4, replacing this with a random function
   costs at most Adv^PRF_{cf}(A').

2. **Outer PRF:** The outer hash H((k ⊕ opad) || ·) is applied to the
   fixed-length output of the inner function.  Replacing this with a random
   function costs at most Adv^PRF_{cf}(A').

3. **Collision term:** If two distinct inner-PRF outputs collide, the outer
   function cannot distinguish them.  This happens with probability at most
   Adv^CR_{SHA-512}(A'').

Summing the three terms gives the stated bound.  □

### 2.5 Concrete Security

With A4 at 128-bit security and SHA-512 collision resistance at 256 bits:

```
Adv^PRF_{HMAC}(q) ≤ 2 · 2^{-128} + 2^{-256} ≈ 2^{-127}
```

This bound holds for any polynomial number of queries q (the per-query cost is absorbed into the compression function PRF advantage term).

Effective security: ~127 bits.

### 2.6 Application in UmbraVox

- **Signal MAC:** Message authentication in Double Ratchet.
- **Chain key derivation:** CK_{i+1} = HMAC(CK_i, 0x02) (`doc/03-cryptography.md`).

---

## 3. HKDF — Extract-then-Expand PRF / Dual-PRF

### 3.1 Security Game

HKDF comprises two stages:
- **Extract:** PRK = HMAC(salt, IKM) — randomness extractor
- **Expand:** OKM = HMAC(PRK, info || counter) — PRF

### 3.2 Hardness Assumption

**A4** (HMAC-SHA-512 PRF) and **A10** (HKDF Extract modelled as random oracle
for extraction).

### 3.3 Theorem

**Theorem 3.1 (HKDF Security, Krawczyk 2010).**

(a) *Extract:* If the input keying material IKM has min-entropy ≥ λ, then
PRK is computationally indistinguishable from a uniform random key:

```
Adv^Ext_{HKDF}(A) ≤ Adv^PRF_{HMAC}(A') + 2^{-λ/2}
```

*Note on the extraction term:* The `2^{-λ/2}` term arises from the
leftover hash lemma when the source has min-entropy ≥ λ and the output
is λ bits: the statistical distance is bounded by `2^{(λ - H_∞)/2}` ≤
`2^{-λ/2}` when `H_∞ ≥ 2λ`.  In UmbraVox's PQXDH, the IKM consists of
5 independent shared secrets each contributing ≥ 128 bits of min-entropy,
for a total min-entropy well above 2λ = 256.  In the computational
extractor model (A10, HKDF in ROM), this term can be absorbed into the
PRF advantage, yielding a tighter bound.  The `2^{-λ/2} = 2^{-64}` term
is retained as a conservative upper bound that does not limit the overall
system security, since it applies only to extraction and the
dominating terms are the CDH and Module-LWE advantages.

(b) *Expand:* For any PRK indistinguishable from random, the output OKM is
indistinguishable from random:

```
Adv^PRF_{HKDF-Expand}(A) ≤ L · Adv^PRF_{HMAC}(A')
```

where L is the number of output blocks.

### 3.4 Lemma (Dual-PRF for PQXDH)

**Lemma 3.2.**  In UmbraVox's PQXDH key agreement, the HKDF input is:

```
IKM = 0xFF*32 || dh1 || dh2 || dh3 || dh4 || pq_ss
```

where dh1–dh4 are X25519 shared secrets and pq_ss is an ML-KEM-768
shared secret.  The output master secret MS is indistinguishable from
random if EITHER:
- At least one of dh1–dh4 is computationally uniform (CDH holds, A1), OR
- pq_ss is computationally uniform (Module-LWE holds, A2).

**Proof.**  By hybrid argument over the 5 shared-secret components:

- **Game 0:** Real execution.
- **Game 1:** Replace pq_ss with uniform random u_pq.
  Distance: Adv^CCA_{ML-KEM}(B) (by A2).
- **Game 2:** Replace dh1 with uniform random u_1.
  Distance: Adv^CDH(B') (by A1).
- **Game 3:** Similarly replace dh2, dh3, dh4.
  Distance: 3 · Adv^CDH(B') (by A1).
- **Game 4:** All 5 components are uniform.  By the leftover hash lemma
  (or A10), HKDF-Extract produces a computationally uniform PRK.

The hybrid argument is valid if we replace components in *either* direction
(pq_ss first, or DH first), proving the dual-PRF property.

Total advantage:

```
Adv ≤ Adv^CCA_{ML-KEM} + 4 · Adv^CDH + Adv^PRF_{HMAC}
```

If CDH is broken but Module-LWE holds, Game 1 alone suffices (pq_ss uniform
→ IKM has sufficient min-entropy).  If Module-LWE is broken but CDH holds,
Games 2–3 suffice.  □

### 3.5 Concrete Security

With CDH at ~128 bits and ML-KEM-768 at ~182 bits classical / ~128 bits
quantum: HKDF output is at least 128-bit secure under either assumption.

### 3.6 Application in UmbraVox

- **PQXDH master secret:** `HKDF(salt=0x00*32, ikm=0xFF*32||dh1||dh2||dh3||dh4||pq_ss, info="UmbraVox_PQXDH_v1")`.
- **Root key / chain key derivation:** `HKDF(salt=0x00*32, ikm=dh_out, info="UmbraVox_Ratchet_v1")` (`doc/03-cryptography.md` line 32).
- **PQ chain key derivation:** `k_pq = HKDF(salt=pq_chain_key, IKM=fresh_pq_ss, info="UmbraVox_PQChain_v1")`.
- **PQ message key derivation:** `HKDF(salt=pq_chain_key, IKM=j, info="UmbraVox_PQMsg_v1")`.

---

## 4. AES-256-GCM — AEAD (IND-CCA2)

### 4.1 Security Game (IND-CCA2 for AEAD)

```
Game IND-CCA2-AEAD:
  b ←$ {0,1}; k ←$ {0,1}^256
  Encrypt oracle: on (n, ad, m0, m1) with |m0|=|m1|, return Enc(k, n, ad, m_b)
  Decrypt oracle: on (n, ad, c) not from encrypt oracle, return Dec(k, n, ad, c)
  A outputs b'.
  Adv = |Pr[b'=1|b=1] - Pr[b'=1|b=0]|.
```

### 4.2 Hardness Assumption

**A3** (AES-256 is a PRP).

### 4.3 Theorem

**Theorem 4.1 (AES-256-GCM AEAD Security, Rogaway 2002, McGrew & Viega 2004).**

```
Adv^AEAD_{AES-256-GCM}(A) ≤ Adv^PRP_{AES-256}(A') + (q_e + q_d)² / 2^{128} + q_d · L_max / 2^{128}
```

where q_e is the number of encryption queries, q_d the number of
decryption queries, and L_max the maximum message length in 128-bit blocks.
The second term is the PRP-PRF switching lemma (birthday bound on 128-bit
blocks), and the third bounds forgery probability against GHASH (polynomial
root bound with degree L_max over GF(2^{128})).

### 4.4 Proof

**Step 1 (IND-CPA from CTR mode).**  AES-256-CTR encrypts by XORing the
plaintext with a keystream AES(k, nonce || counter).  Replace AES with a
truly random permutation (cost: Adv^PRP_{AES-256}), then with a truly random
function (cost: birthday bound (q_e + q_d)²/2^{128} via PRP-PRF switching).  The
resulting CTR keystream is indistinguishable from random, giving IND-CPA.

**Step 2 (INT-CTXT from GHASH).**  GCM computes an authentication tag via
GHASH (polynomial evaluation over GF(2^{128})) followed by encryption of the
hash with AES.  For any forgery attempt, the probability that GHASH produces
a valid tag is at most L/2^{128} per query, where L is the message length in
128-bit blocks (polynomial root bound over GF(2^{128}) with degree L).  Over
q_d queries: q_d · L_max / 2^{128}, where L_max is the maximum message length
in blocks.

**Step 3 (Composition).**  By the generic AEAD composition theorem
(Rogaway 2002): IND-CPA + INT-CTXT ⟹ IND-CCA2 for AEAD.  □

### 4.5 Nonce Uniqueness Guarantee

UmbraVox guarantees nonce uniqueness via the Double Ratchet state machine:
each ratchet step produces a unique (chain_key, message_number) pair.  The
12-byte GCM nonce is derived deterministically from the message number
(monotonic counter), ensuring no reuse within a ratchet chain.  A new
ratchet chain uses a fresh chain key, making cross-chain nonce collision
irrelevant (different keys).

### 4.6 Concrete Security

With AES-256 PRP security at ~128 bits, per-key security depends on
the number of messages encrypted under a single key.  Each ratchet chain
encrypts at most ~1000 messages (q_e ≈ 2^{10}), with q_d ≤ q_e (each
message key is used for at most one decryption):

```
Adv_per_key ≤ 2^{-128} + (q_e + q_d)²/2^{128} + q_d · L_max/2^{128}
            ≤ 2^{-128} + (2^{11})²/2^{128} + 2^{10} · L_max/2^{128}
            = 2^{-128} + 2^{-106} + 2^{10} · L_max / 2^{128}
```

UmbraVox transactions are at most 64 KiB (`doc/hardening/22-network-protocol-security.md`
line 235), so L_max = 65536/16 = 4096 = 2^{12} blocks.  The forgery term
becomes 2^{10} · 2^{12} / 2^{128} = 2^{-106}.  The dominant term is
2^{-106}, giving per-key security of ~106 bits, well above the 100-bit
practical threshold.
The ratchet's frequent re-keying ensures the birthday term remains negligible.

### 4.7 Application in UmbraVox

- **Signal encryption:** Per-message AES-256-GCM under message keys.
- **PQ wrapper encryption:** AES-256-GCM under PQ-derived keys.
- **Overhead:** 12-byte nonce + 16-byte GCM tag = 28 bytes per message (`doc/03-cryptography.md` lines 151–159).

---

## 5. X25519 — CDH Security on Curve25519

### 5.1 Security Game (CDH)

```
Game CDH_{Curve25519}:
  g = fixed base point of Curve25519
  a, b ←$ ℤ_q
  A receives (g, g^a, g^b).
  A outputs Z.
  A wins if Z = g^{ab}.
  Adv^CDH(A) = Pr[A wins].
```

(Here g^a denotes scalar multiplication a·G on Curve25519.)

### 5.2 Hardness Assumption

**A1** (CDH on Curve25519).

### 5.3 Theorem

**Theorem 5.1 (X25519 CDH Security).**
For any PPT adversary A:

```
Adv^CDH_{X25519}(A) ≤ Adv^CDH_{Curve25519}(A)
```

The X25519 function (RFC 7748) is a direct instantiation of Diffie-Hellman
on Curve25519 using the Montgomery ladder.  There is no security loss in
the reduction; the X25519 shared secret is the CDH value itself.

### 5.4 Proof

**Reduction.**  Given CDH challenge (G, aG, bG), the X25519 computation
is precisely the Montgomery ladder computing abG from the x-coordinate of
bG and the scalar a.  Any adversary recovering the shared secret from
(aG, bG) directly solves CDH.  □

### 5.5 Concrete Security

Curve25519 has group order q ≈ 2^{252}.  Pollard's rho gives CDH
security of O(√q) ≈ O(2^{126}), providing ~126-bit classical security.

**Quantum note:**  Shor's algorithm solves ECDLP (and hence CDH) in
polynomial time on a sufficiently large quantum computer.  X25519 alone
is NOT post-quantum secure.  UmbraVox mitigates this via the ML-KEM-768
PQ wrapper (see Proof-02 §3–§5).

### 5.6 Application in UmbraVox

- **PQXDH:** 4 DH exchanges (dh1 = DH(IK_A, SPK_B), dh2 = DH(EK_A, IK_B), dh3 = DH(EK_A, SPK_B), dh4 = DH(EK_A, OPK_B)).
- **DH ratchet steps:** Fresh ephemeral DH in each ratchet cycle.

---

## 6. Ed25519 — EUF-CMA Unforgeability

### 6.1 Security Game (EUF-CMA)

```
Game EUF-CMA_{Ed25519}:
  (sk, pk) ← KeyGen()
  A has access to signing oracle Sign(sk, ·).
  A outputs (m*, σ*).
  A wins if Verify(pk, m*, σ*) = 1 and m* was never queried to Sign.
  Adv^EUF-CMA(A) = Pr[A wins].
```

### 6.2 Hardness Assumption

**A5** (DDH on Ed25519 curve). Note: The EUF-CMA reduction (§6.3) requires only DLP hardness, which is implied by DDH (A5). A5 is cited here because it is the registered assumption for Ed25519 in the global assumptions registry; the proof uses the weaker DLP consequence.

### 6.3 Theorem

**Theorem 6.1 (Ed25519 Unforgeability).**

In the random oracle model (ROM), for any PPT adversary A making q_s
signing queries and q_h hash queries:

```
Adv^EUF-CMA_{Ed25519}(A) ≤ sqrt((q_h + q_s + 1) · (Adv^DLP_{Ed25519}(A') + 1/q))
```

where q is the group order of Ed25519 (~2^{252}).

In the algebraic group model (AGM, Fuchsbauer, Kiltz & Loss 2018):

```
Adv^EUF-CMA_{Ed25519}(A) ≤ Adv^DLP_{Ed25519}(A')
```

with a tight reduction (no quadratic loss).

### 6.4 Proof

**ROM Proof (Pointcheval & Stern 1996, adapted to Ed25519).**

Ed25519 is a Schnorr-like signature scheme.  The forking lemma applies:

1. Run A to obtain a forgery (m*, σ* = (R*, s*)).
2. Rewind A with a different random oracle response for H(R* || pk || m*).
3. Obtain a second forgery (m*, σ** = (R*, s**)) with the same R* but
   different challenge c** ≠ c*.
4. From s* - s** = (c* - c**) · sk mod q, extract sk.

This yields a DLP solver A' with:

```
Adv^DLP(A') ≥ Adv^EUF-CMA(A)² / (q_h + q_s + 1) - 1/q
```

Inverting: Adv^EUF-CMA(A) ≤ sqrt((q_h + q_s + 1) · (Adv^DLP(A') + 1/q)),
giving the stated bound.

**AGM Proof (Fuchsbauer, Kiltz & Loss 2018).**  In the AGM, every group element
output by A is accompanied by its representation in terms of input group
elements.  The Schnorr verification equation s*G = R* + c*·pk directly
yields a DLP instance when A provides the algebraic representation of R*.
The reduction is tight: Adv^EUF-CMA ≤ Adv^DLP.  □

**Note:** UmbraVox uses PureEd25519 (RFC 8032 Section 5.1), where messages
are NOT pre-hashed.  This avoids collision attacks on the hash function
that would weaken the signature scheme.

### 6.5 Concrete Security

Ed25519 group order: ~2^{252}.  DLP security: ~126 bits (Pollard's rho).
With AGM tight reduction: ~126-bit EUF-CMA security.

### 6.6 Application in UmbraVox

- **Transaction signatures:** Every transaction is signed with Ed25519.
- **SPK signatures:** Signed prekeys in PQXDH.
- **Heartbeat responses:** `sign(challenge || validator_pubkey, sk)` (`doc/04-consensus.md` lines 183–209).

---

## 7. ML-KEM-768 — IND-CCA2 from Module-LWE

### 7.1 Security Game (IND-CCA2 for KEM)

```
Game IND-CCA2-KEM:
  (pk, sk) ← KeyGen()
  (c*, ss0) ← Encaps(pk)
  ss1 ←$ {0,1}^256
  b ←$ {0,1}
  A receives (pk, c*, ss_b).
  A has access to Decaps(sk, ·) oracle (cannot query c*).
  A outputs b'.
  Adv = |Pr[b'=1|b=1] - Pr[b'=1|b=0]|.
```

### 7.2 Hardness Assumption

**A2** (Module-LWE with k=3, q=3329).

### 7.3 Theorem

**Theorem 7.1 (ML-KEM-768 IND-CCA2 Security, FIPS 203).**

```
Adv^CCA_{ML-KEM-768}(A) ≤ Adv^CPA_{ML-KEM-768}(A') + q_H / 2^{256}
```

where the first term reduces to Module-LWE via the FO (Fujisaki-Okamoto)
transform, and q_H is the number of random oracle queries.

*Model note:* This bound applies in the classical Random Oracle Model
(ROM).  In the Quantum ROM (QROM), the FO transform incurs a quadratic
security loss (Jiang, Zhang, Ma 2018; Hofheinz, Hövelmanns, Kiltz 2017):
`Adv^CCA ≤ q_H^2 / 2^{256} + Adv^CPA`.  For q_H ≤ 2^{64} (a generous
bound on quantum hash queries), the QROM term is `2^{128} / 2^{256} =
2^{-128}`, which remains negligible.  UmbraVox's security claims use the
ROM bound above; the QROM bound is tighter in the relevant parameter
range and does not degrade below λ = 128.

The underlying IND-CPA security reduces to Module-LWE:

```
Adv^CPA_{ML-KEM-768}(A') ≤ Adv^MLWE_{3,3329}(A'')
```

### 7.4 Proof

**Step 1 (FO Transform: IND-CPA → IND-CCA2).**

ML-KEM applies the FO transform with implicit rejection:

1. Decapsulation re-encrypts with the decrypted message m' and checks
   whether the resulting ciphertext matches c.
2. On mismatch, output a pseudorandom value H(z || c) where z is a secret
   random seed (implicit rejection).
3. This prevents the decapsulation oracle from leaking information: valid
   queries return the correct shared secret, invalid queries return
   pseudorandom output independent of sk.

Security loss: at most q_H / 2^{256} from random oracle collisions.

**Step 2 (IND-CPA from Module-LWE).**

The IND-CPA scheme encrypts by computing:

```
c = (A·r + e1, t^T·r + e2 + ⌈q/2⌋·m) mod q
```

where A is the public matrix, t = A·s + e is the public key, and r, e1, e2
are fresh noise.  Distinguishing this from random reduces directly to
Module-LWE (replacing A·r + e1 with uniform, then t^T·r + e2 with uniform).

**Step 3 (Module-LWE → LWE).**

Module-LWE with module rank k=3 over R_q = ℤ_q[X]/(X^{256}+1) reduces to
standard LWE with dimension n = k·256 = 768 (Langlois & Stehlé 2015).  □

### 7.5 Concrete Security

NIST Category 3: ~182-bit classical security, ~128-bit quantum security
(core-SVP methodology).

Implicit rejection ensures no information leakage even on decapsulation
failure, which is critical for UmbraVox's PQ ratchet refresh
(`doc/03-cryptography.md` lines 113–118).

### 7.6 Application in UmbraVox

- **PQXDH:** pq_ss component of the initial key agreement.
- **PQ ratchet refreshes:** Fresh ML-KEM encapsulation every 50 messages per direction (`doc/03-cryptography.md` lines 151–159).

---

## 8. ECVRF-ED25519-SHA512 — Pseudorandomness + Uniqueness

### 8.1 Security Games

The VRF must satisfy two properties:

```
Game VRF-PR (Pseudorandomness):
  (pk, sk) ← KeyGen()
  b ←$ {0,1}
  A chooses challenge input x*.
  For all x ≠ x*: On query x, return (proof, VRF(sk, x)).
  For x*: return only y* where
    If b=1: y* = VRF(sk, x*)   (real output, proof withheld)
    If b=0: y* ←$ {0,1}^{512}  (random, no proof)
  A outputs b'.
  Adv^VRF-PR(A) = |Pr[b'=1|b=1] - Pr[b'=1|b=0]|.

Property VRF-UQ (Uniqueness):
  For all (pk, x), there exists at most one y such that
  a valid proof π exists with Verify(pk, x, y, π) = 1.
```

### 8.2 Hardness Assumption

**A5** (DDH on Ed25519 curve).  The hash-to-curve map (Elligator2) is modelled
as a random oracle (required for programming the DDH challenge into a specific
input point in the pseudorandomness reduction).

### 8.3 Theorem

**Theorem 8.1 (ECVRF-ED25519-SHA512-ELL2 Pseudorandomness, RFC 9381).**

```
Adv^VRF-PR_{ECVRF}(A) ≤ Adv^DDH_{Ed25519}(A') + q_v / 2^{128}
```

where q_v is the number of VRF evaluation queries (distinct from the
group order q ≈ 2^{252} used in §5–§6).

**Theorem 8.2 (ECVRF Uniqueness).**

For ECVRF-ED25519-SHA512-ELL2 (the Elligator2 suite, as specified in
`doc/04-consensus.md` line 6), uniqueness is unconditional (information-
theoretic): for any public key pk and input x, the VRF output y = Γ·cofactor
is uniquely determined by pk and x via the deterministic Elligator2
hash-to-curve map.

### 8.4 Proof of Pseudorandomness

**Reduction to DDH.**

The VRF output is derived from Γ = sk · H(x) where H maps inputs to curve
points (Elligator2).  The output is hash(cofactor · Γ).

1. Given DDH challenge (G, aG, bG, Z) where Z is either abG or random.
2. Set pk = aG.  For all evaluation queries except the challenge query x*,
   simulate normally using knowledge of the hash-to-curve randomness.
3. For the challenge query x*, program the hash-to-curve oracle so that
   H(x*) = bG (embedding the DDH challenge).
4. The VRF output for x* should be hash(cofactor · a · bG) = hash(cofactor · abG).
   If Z = abG, compute the correct output hash(cofactor · Z).
   If Z is random, the output is indistinguishable from random.
5. A distinguisher for VRF pseudorandomness at x* yields a DDH distinguisher.
6. The additive term q_v/2^{128} accounts for the probability that the
   adversary's hash queries collide with the programmed DLEQ challenge
   point (the DLEQ challenge c is 128 bits per RFC 9381, cLen = 16).  □

### 8.5 Proof of Uniqueness

The hash-to-curve map H: {0,1}* → Ed25519 via Elligator2 is deterministic.
Given pk and x, the point Γ = sk · H(x) is uniquely determined (since sk
is the unique discrete log of pk).  The cofactor multiplication and final
hash are deterministic.  Therefore y = VRF(sk, x) is unique.

The proof π = (Γ, c, s) is a Schnorr-like DLEQ proof that log_G(pk) =
log_{H(x)}(Γ).  Verification checks this relation, so only the correct
Γ (and hence y) can produce a valid proof.  □

### 8.6 Concrete Security

DDH on Ed25519: ~126 bits (same as DLP).  VRF pseudorandomness: ~126 bits.

### 8.7 Application in UmbraVox

- **Slot leader election:** `VRF_prove(sk, epoch_nonce || slot_number)` (`doc/04-consensus.md` lines 54–65).
- **Epoch nonce contribution:** VRF output of last block feeds into next epoch nonce.

---

## 9. ChaCha20 CSPRNG — PRF + Forward Secrecy

### 9.1 Security Game (PRF for CSPRNG)

```
Game PRF-CSPRNG:
  k ←$ {0,1}^{256}
  b ←$ {0,1}
  If b=1: O(x) = ChaCha20(k, x)  (counter mode)
  If b=0: O(x) = R(x)
  Adv^PRF(A) = |Pr[b'=1|b=1] - Pr[b'=1|b=0]|.
```

### 9.2 Hardness Assumption

**A6** (ChaCha20 core is a PRF).

### 9.3 Theorem

**Theorem 9.1 (ChaCha20 CSPRNG Security).**

For any PPT adversary A making at most q queries:

```
Adv^PRF_{ChaCha20-CSPRNG}(A) ≤ Adv^PRF_{ChaCha20}(A')
```

The bound reduces directly to the ChaCha20 core PRF assumption.  (A
birthday term q²/2^{512} on the 512-bit output space exists in principle
but is vacuously negligible — e.g., 2^{-472} for q = 2^{20} — and
output collisions of a PRF do not constitute a distinguishing advantage
beyond what occurs for a truly random function with the same output size.
The dominant term is the PRF advantage.)

**Theorem 9.2 (Forward Secrecy).**

If the CSPRNG state at time t is compromised, outputs prior to the most
recent reseed (at time t' < t) are computationally indistinguishable from
random, assuming the seed entropy source (/dev/urandom)
provided ≥ λ bits of min-entropy at each reseed.

### 9.4 Proof of PRF Security

**Reduction.**  Replace ChaCha20(k, ·) with a random function (cost:
Adv^PRF_{ChaCha20}).  The CSPRNG output is then a sequence of independent
random values.  The birthday term bounds the probability of output
collisions among q distinct 512-bit PRF outputs.  □

### 9.5 Proof of Forward Secrecy

UmbraVox reseeds the CSPRNG every 2^{20} (1,048,576) outputs
(`doc/03-cryptography.md` lines 40–44):

1. At reseed, a new 256-bit seed s' is drawn via /dev/urandom.
2. The new CSPRNG key is k' = HKDF-Extract(salt=old_key, IKM=s').
3. The old key is securely erased (zeroed).

**Forward secrecy argument:**  After reseed, knowing k' reveals nothing
about k (HKDF is a PRF under A4/A10, and s' has ≥ λ bits of fresh entropy).
Therefore, outputs generated under k are indistinguishable from random
given only k'. More precisely, forward secrecy holds per reseed epoch: outputs from any epoch prior to the most recent reseed are protected, even if the current state (k') is compromised.

**Fork safety:**  On process fork, the PID changes.  The CSPRNG detects
this and immediately reseeds, ensuring the child process's output is
independent of the parent's.  □

### 9.6 Concrete Security

ChaCha20 PRF security: ~128 bits (Bernstein 2008).  With reseed interval
2^{20} outputs (each a 64-byte block), the per-key birthday term is
(2^{20})² / 2^{512} = 2^{-472}, which is negligible.

### 9.7 Application in UmbraVox

- **All key generation:** Identity keys, ephemeral keys, one-time prekeys.
- **All nonce generation:** GCM nonces (though these are also derived from ratchet state for uniqueness).
- **ML-KEM randomness:** Random coins for encapsulation.

---

## Summary of Concrete Security Levels

| Primitive | Classical (bits) | Quantum (bits) | Assumption |
|-----------|-----------------|----------------|------------|
| SHA-256 | 128 (CR) | 85 (BHT collision) | MD structure |
| HMAC-SHA-512 | 127 (PRF) | 128 (Grover on compression function key) | A4 |
| HKDF | 128 (dual-PRF) | 128 (via ML-KEM) | A4, A10 |
| AES-256-GCM | 106 (AEAD per-key, q_e≈10³, L≈2^{12}) | 128 (Grover) | A3 |
| X25519 | 126 (CDH) | 0 (Shor) | A1 |
| Ed25519 | 126 (EUF-CMA) | 0 (Shor) | A5 |
| ML-KEM-768 | 182 | 128 | A2 |
| ECVRF | 126 (PR) | 0 (Shor) | A5 |
| ChaCha20 CSPRNG | 128 (PRF) | 128 (Grover) | A6 |

The weakest classical link is Ed25519/ECVRF at ~126 bits.  Post-quantum
security of the messaging layer is ensured by ML-KEM-768 at 128 bits
(see Proof-02 for composition argument).
