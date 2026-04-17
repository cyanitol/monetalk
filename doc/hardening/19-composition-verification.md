# Hardening Spec 19: Cross-Layer Composition Verification

**Status:** Formal Verification Specification
**Scope:** Composition security of the full UmbraVox cryptographic stack
**Dependencies:** `doc/03-cryptography.md`, `doc/proof-01-primitive-security.md`, `doc/proof-02-protocol-security.md`, `doc/04-consensus.md`

---

## 0. Motivation

Each cryptographic layer in UmbraVox has been proven individually secure
(Proof-01, Proof-02).  However, secure components do not guarantee a secure
composition.  Maurer & Renner (2011) demonstrate that even IND-CCA2 schemes
can lose security when composed if key material leaks across boundaries, if
error oracles expose inner-layer state, or if ordering assumptions are
violated.  This specification enumerates every cross-layer interface,
proves isolation properties, and states the top-level composition theorem
with machine-checkable proof obligations.

---

## 1. Layer Inventory

### 1.1 Layer Enumeration (Processing Order: Encryption)

```
Layer  Name              Input              Output              Key Source
─────  ────              ─────              ──────              ──────────
L1     PQXDH             -                  MS (master secret)  IK, EK, SPK, OPK, PQPK
L2     Signal DR          plaintext m       ct_signal           mk from DH ratchet (seeded by MS)
L3     PQ Wrapper         ct_signal         ct_pq               pq_msg_key from PQ chain (seeded by MS)
L4     CBOR               ct_pq             tx_payload          (no key; deterministic encoding)
L5     Blockchain         tx_payload        block               Ed25519 tx signature (identity key)
L6     Dandelion++        block             network message     (no encryption key; routing only)
```

### 1.2 Key Material Flow

```
                ┌──────────────────────────────────────────────────────┐
                │             PQXDH Master Secret (MS)                │
                │  HKDF(0x00*32, 0xFF*32||dh1||..||dh4||pq_ss,       │
                │        info="UmbraVox_PQXDH_v1")                   │
                └──────────┬───────────────────────┬──────────────────┘
                           │                       │
              HKDF-Expand  │                       │  HKDF-Expand
         info="UmbraVox_   │                       │  (PQ chain seed
          Ratchet_v1"      │                       │   via separate
                           ▼                       ▼   derivation)
                   ┌──────────────┐       ┌──────────────┐
                   │ Signal Root  │       │  PQ Chain     │
                   │ Key (RK)     │       │  Key (pqCK_0) │
                   └──────┬───────┘       └──────┬────────┘
                          │                      │
                   DH ratchet steps        ML-KEM ratchet
                   (CDH-based)             (Module-LWE-based)
                          │                      │
                          ▼                      ▼
                   mk_signal(i)           pq_msg_key(i,j)
                   (AES-256-GCM)          (AES-256-GCM)
```

### 1.3 Invariant

**INV-LAYER-1.** Every key used for encryption at layer L_i is derived from
a distinct HKDF invocation with a unique `info` string.  No raw key material
crosses a layer boundary without passing through HKDF with a layer-specific
domain separator.

---

## 2. Key Material Isolation

### 2.1 HKDF Info String Registry

| ID    | Info String                | Layer | Purpose                           |
|-------|----------------------------|-------|-----------------------------------|
| KDF-1 | `"UmbraVox_PQXDH_v1"`      | L1    | Master secret from PQXDH          |
| KDF-2 | `"UmbraVox_Ratchet_v1"`    | L2    | Root key / chain key derivation   |
| KDF-3 | (per-message counter `j`)  | L3    | PQ per-message key derivation     |
| KDF-4 | (PQ chain ratchet)         | L3    | PQ chain key evolution            |

### 2.2 Uniqueness Proof

**Theorem 2.1 (Info String Uniqueness).**
Let S = { s_i : i in {1..4} } be the set of HKDF info strings used in
UmbraVox.  Then:

```
forall i, j in {1..|S|}, i /= j  ==>  s_i /= s_j
```

**Proof.**  By direct inspection:

- KDF-1: `"UmbraVox_PQXDH_v1"` (18 bytes)
- KDF-2: `"UmbraVox_Ratchet_v1"` (20 bytes)
- KDF-3: integer counter `j` encoded as 4-byte big-endian
- KDF-4: PQ chain key uses HKDF with `ikm = fresh_pq_ss` (256-bit ML-KEM shared secret)

KDF-1 and KDF-2 differ in both content and length.  KDF-3 and KDF-4 use
different salt values (pq_chain_key vs pq_chain_key with fresh_pq_ss as IKM).
No two invocations share the same (salt, info) pair.  []

### 2.3 Domain Separation Theorem

**Theorem 2.2 (Key Independence).**
Under assumption A10 (HKDF modelled as a random oracle for extraction), the
following key families are computationally independent:

```
{ mk_signal(i) }_{i in N}  is independent of  { pq_msg_key(j,k) }_{j,k in N}
```

**Proof.**  The Signal message keys mk_signal(i) are derived from the DH
ratchet chain:

```
RK, CK = HKDF(RK_prev, dh_out, info="UmbraVox_Ratchet_v1")
mk_signal(i) = HMAC(CK, 0x01)
```

The PQ message keys pq_msg_key(j,k) are derived from the PQ chain:

```
pq_chain_key(j) = HKDF(pq_chain_key(j-1), fresh_pq_ss)
pq_msg_key(j,k) = HKDF(pq_chain_key(j), k)
```

Both hierarchies originate from the master secret MS, but diverge at the
first HKDF-Expand step with distinct info strings ("UmbraVox_Ratchet_v1"
vs PQ chain derivation).  By the PRF property of HKDF-Expand (Proof-01,
Theorem 3.1b), outputs under distinct info strings are computationally
independent.

Formally: if there exists a distinguisher D that correlates mk_signal(i)
with pq_msg_key(j,k), then D can be used to break the PRF security of
HKDF-Expand, contradicting A4.  []

### 2.4 Cross-Layer Key Reuse Check

**Verification obligation (VER-KEY-ISO-1).**  A static analysis pass must
confirm that no `ByteString` value serving as a cryptographic key is passed
to more than one of the following functions without an intervening HKDF call:

- `aesGcmEncrypt` (Signal layer)
- `aesGcmEncrypt` (PQ wrapper layer)
- `ed25519Sign` (transaction signing)

---

## 3. Error Propagation

### 3.1 ML-KEM Decapsulation Failure

**Trigger:** ML-KEM-768 `Decaps` returns error (malformed ciphertext or
decapsulation check failure).

**Propagation path:**

```
L1 (PQXDH)         L2 (Signal DR)        L3 (PQ Wrapper)
    │                    │                     │
    │  pq_ss omitted     │                     │
    │  from IKM          │                     │
    │───────────────────>│                     │
    │                    │  session init with   │
    │                    │  classical-only MS   │
    │                    │────────────────────>│
    │                    │                     │  PQ wrapper uses
    │                    │                     │  degraded chain key
```

**Security invariant (INV-ERR-1):**  ML-KEM decapsulation failure MUST:

1. Cause fallback to classical-only key agreement (dh1||dh2||dh3||[dh4]
   without pq_ss).
2. Log a SECURITY_DOWNGRADE event (timestamp, peer fingerprint, session ID,
   failure reason).
3. Trigger a RATCHET_REFRESH request to the peer.
4. NOT expose any information about the ML-KEM secret key through the
   error path (implicit rejection per FIPS 203 guarantees this).

**Theorem 3.1 (ML-KEM Failure Isolation).**
ML-KEM implicit rejection ensures that the decapsulation output on invalid
ciphertext is `H(z || c)` where `z` is a per-key random seed.  This output
is indistinguishable from a valid shared secret to any party not holding the
ML-KEM secret key.  Therefore, decapsulation failure does not leak
information about sk_pq.

```
forall c' /= c* :  Decaps(sk, c') = H(z || c')
                    is indistinguishable from  ss ←$ {0,1}^256
                    to any adversary not knowing sk
```

**Proof.**  Direct consequence of ML-KEM IND-CCA2 security (Proof-01,
Theorem 7.1) and the FO transform with implicit rejection.  []

### 3.2 AES-GCM Authentication Failure

**Trigger:** GCM tag verification fails at either layer (Signal or PQ wrapper).

**Propagation:**

| Failure Location | Action | Rationale |
|-----------------|--------|-----------|
| PQ wrapper (L3) | Drop entire message | Outer layer integrity violated; inner ciphertext may be tampered |
| Signal (L2)     | Drop message, do NOT advance ratchet state | Prevents ratchet desync from forged messages |

**INV-ERR-2:**  A GCM authentication failure at any layer MUST NOT cause
ratchet state advancement.  The ratchet counter is incremented only after
successful decryption and authentication.

### 3.3 Ratchet Desynchronisation

**Trigger:** Peer's ratchet state diverges (e.g., lost messages exceeding
the 1,000 skipped-key limit).

**Recovery protocol:**

1. Recipient detects desync when message counter gap exceeds 1,000.
2. Recipient drops the message (does not advance past the gap).
3. After 3 consecutive failed decryptions, recipient initiates a
   RATCHET_REFRESH (re-handshake with fresh ephemeral keys).
4. The refresh re-establishes both the Signal DH ratchet and the PQ chain
   from fresh key material.

**INV-ERR-3:**  Ratchet desynchronisation MUST NOT cause the system to
accept a message encrypted under a key the recipient has not derived.
The skipped-key cache is the only mechanism for handling gaps; exceeding
it forces re-handshake.

---

## 4. Downgrade Attacks

### 4.1 Threat Model

An active adversary (Adv) controls the network and attempts to force the
system into a weaker cryptographic configuration:

- **D1:** Skip the PQ wrapper entirely (classical-only Signal).
- **D2:** Force classical-only PQXDH (omit pq_ss from IKM).
- **D3:** Force use of an exhausted/weak OPK set.

### 4.2 Defense: Mandatory PQ Wrapper

**INV-DOWN-1 (PQ Wrapper Mandatory).**

```
forall session s :
  s.pq_wrapper_enabled = True
  OR
  (s.pq_wrapper_enabled = False  AND  s.security_event_logged = True
                                  AND  s.ratchet_refresh_pending = True)
```

The PQ wrapper is a non-optional protocol layer.  A session MAY operate
temporarily without PQ protection only if:

1. ML-KEM decapsulation failed (Section 3.1), AND
2. A SECURITY_DOWNGRADE event was logged, AND
3. A RATCHET_REFRESH has been requested.

There is no configuration flag to disable the PQ wrapper.  An adversary
cannot cause the wrapper to be skipped without triggering an ML-KEM failure,
which is detectable and logged.

### 4.3 Defense: Classical Fallback Detection

**Theorem 4.1 (Downgrade Detection).**
If an adversary forces classical-only operation by injecting a malformed
ML-KEM ciphertext, the system detects this via the SECURITY_DOWNGRADE log.

**Proof.**  The only path to classical-only operation is through the ML-KEM
decapsulation failure handler (Section 3.1).  This handler unconditionally
logs the event before proceeding.  The adversary cannot suppress the log
without compromising the endpoint (excluded by threat model).  []

### 4.4 Defense: Minimum PQ Key Size

The system accepts only ML-KEM-768 encapsulation keys.  There is no
negotiation of PQ parameter sets.  An adversary cannot downgrade to a
weaker ML-KEM parameter set (e.g., ML-KEM-512) because the protocol
hardcodes the expected ciphertext size (1,088 bytes) and rejects
non-conforming ciphertexts.

```
INV-DOWN-2:
  forall pq_ct received :
    length(pq_ct) = 1088  OR  reject(pq_ct)
```

---

## 5. Version Negotiation Attacks

### 5.1 Chain Revision Mechanism

Per `doc/04-consensus.md` lines 270-289, each epoch genesis block carries a
chain revision number (`egChainRevision :: Word32`).  The protocol supports
the current revision plus the 3 immediately prior revisions.

### 5.2 Threat: Forced Downgrade via Chain Revision

An adversary controlling a significant minority of validators could attempt
to produce blocks with an older chain revision, forcing peers to process
transactions under weaker protocol rules.

### 5.3 Defense: Minimum Supported Revision

**INV-VER-1 (Minimum Revision Floor).**

```
forall block b accepted by honest node n :
  b.chainRevision >= n.currentRevision - 3
  AND
  b.chainRevision >= MINIMUM_REVISION_FLOOR
```

where `MINIMUM_REVISION_FLOOR` is a compile-time constant set to the
lowest revision that includes mandatory PQ wrapper support.  This prevents
an adversary from forcing a reversion to a pre-PQ protocol version even
if the 3-revision window would otherwise permit it.

**Theorem 5.1 (Revision Downgrade Resistance).**
An adversary cannot force an honest node to accept blocks under a revision
that lacks PQ wrapper support, provided `MINIMUM_REVISION_FLOOR` is set to
the first PQ-mandatory revision.

**Proof.**  Honest nodes reject blocks with `chainRevision < MINIMUM_REVISION_FLOOR`
unconditionally, regardless of the current revision window.  An adversary
would need to compromise the node's software (not just the network) to
bypass this check.  []

### 5.4 Defense: Revision Monotonicity

**INV-VER-2 (Epoch Revision Monotonicity).**

```
forall consecutive epochs E_i, E_{i+1} :
  E_{i+1}.chainRevision >= E_i.chainRevision
```

Chain revisions are monotonically non-decreasing across epochs.  A block
proposer cannot propose a genesis block with a lower revision than the
previous epoch.  Honest validators reject such proposals during block
validation.

### 5.5 Verification Obligation

**VER-VERSION-1.**  The block validation function must be tested with:

- Chain revision equal to `MINIMUM_REVISION_FLOOR - 1` (must reject)
- Chain revision equal to `currentRevision - 4` (must reject)
- Chain revision equal to `currentRevision - 3` (must accept)
- Chain revision rollback attempt: epoch N+1 revision < epoch N revision (must reject)

---

## 6. Ordering Dependencies

### 6.1 Chosen Order: Signal-First, PQ-Wrap-Outer

UmbraVox encrypts as:

```
ct_final = PQ_Wrap(Signal_Encrypt(m))
```

That is, Signal encryption is applied first (inner layer), and the PQ
wrapper is applied second (outer layer).

### 6.2 Correctness of Ordering

**Theorem 6.1 (Signal-Inner / PQ-Outer is Correct for Hybrid Security).**

The order Signal-first, PQ-outer provides the following properties that
the reverse order (PQ-first, Signal-outer) would not:

**(a) Post-quantum protection of Signal ciphertext metadata.**

If CDH is broken by a quantum adversary, Signal ciphertext headers (which
contain ephemeral DH public keys and ratchet metadata) would be exposed
under the reverse order.  With PQ-outer, Signal metadata is protected by
the ML-KEM-derived key even if CDH falls.

**(b) Hybrid IND-CCA2 under either assumption.**

With Signal-inner/PQ-outer:

```
Break(ct_final)  ==>  Break(PQ layer)  AND  Break(Signal layer)
                  ==>  Break(Module-LWE)  AND  Break(CDH)
```

With PQ-inner/Signal-outer, a CDH break would expose the PQ ciphertext
directly, and the adversary need only break the PQ layer:

```
Break(ct_final)  ==>  Break(Signal layer)  ==>  Break(CDH)
                  ==>  expose PQ ciphertext (but still encrypted under PQ)
```

While the PQ ciphertext would remain encrypted, the Signal metadata
(ratchet public keys, message counters) would be exposed, enabling
targeted attacks on the DH ratchet structure.

**(c) Deniability preservation.**

The outer PQ layer uses symmetric-only crypto (AES-256-GCM).  No
asymmetric signature covers the composed ciphertext.  If the PQ wrapper
were inner, the Signal MAC would cover the PQ ciphertext, which is
acceptable (MACs are deniable), but the current order ensures the
outermost layer is purely symmetric.

**Proof.**

Formally, consider the IND-CCA2 game for the composed scheme.  The
reduction in Proof-02, Theorem 4.1, proceeds by first replacing the
inner (Signal) ciphertext with a random string of the same length
(cost: Adv^CCA_Signal), then replacing the outer (PQ) ciphertext
(cost: Adv^CCA_PQ).

This reduction requires that the inner scheme's ciphertext is a valid
input to the outer scheme regardless of whether it is real or simulated.
Since AES-256-GCM accepts arbitrary byte strings as plaintext, this
holds trivially.  The reverse order would also satisfy this syntactic
requirement, but would not provide property (a) above.

The hybrid security claim follows: if only CDH is broken, the adversary
can simulate the inner Signal layer but cannot break the outer PQ layer
(Module-LWE holds).  If only Module-LWE is broken, the adversary can
strip the outer PQ layer but cannot break the inner Signal layer
(CDH holds).  []

---

## 7. Replay Across Layers

### 7.1 Threat Model

After the 11-day truncation cycle, old blocks are pruned.  An adversary
who retained a copy of a valid transaction from epoch E could attempt to
replay it in epoch E' > E.

### 7.2 Defense: Epoch-Bound Nonces

**INV-REPLAY-1 (Epoch Binding).**

Every transaction includes an epoch number in its signed payload:

```
tx_signed_payload = (sender, recipient, epoch_no, nonce, ct_pq)
tx_signature = Ed25519.Sign(sk_sender, tx_signed_payload)
```

The transaction nonce is unique per (sender, epoch) pair.  Validators
reject transactions where:

1. `epoch_no` does not match the current epoch, OR
2. `(sender, nonce)` has already been observed in the current epoch.

### 7.3 Formal Proof of Replay Prevention

**Theorem 7.1 (Replay Prevention Across Truncation).**

Let tx be a valid transaction in epoch E.  For any epoch E' > E,
tx is rejected by all honest validators in epoch E'.

**Proof.**

Case 1: `E' > E`.  The transaction's `epoch_no = E` does not match the
current epoch E'.  Validators reject per rule (1) above.

Case 2: Adversary modifies `epoch_no` to E'.  The Ed25519 signature
`tx_signature` covers `epoch_no`.  Modifying `epoch_no` invalidates the
signature.  Producing a valid signature on the modified payload requires
forging an Ed25519 signature, which contradicts A5 (EUF-CMA, Proof-01
Theorem 6.1).

Case 3: Adversary replays within the same epoch E.  The nonce
`(sender, nonce)` is already recorded.  Validators reject per rule (2).

```
forall tx valid in epoch E, forall E' /= E :
  Pr[honest_validator_accepts(tx, E')] <=
    Adv^EUF-CMA_{Ed25519}(A)
    <= (q_h + q_s + 1)^2 / q + Adv^DLP_{Ed25519}(A')
```

which is negligible at lambda = 126 bits.  []

### 7.4 Post-Truncation State Integrity

After truncation, the epoch genesis block carries forward:

- Stake snapshot (validator balances)
- Key registry (current prekey bundles)
- Nonce registry is reset (old nonces discarded)

The nonce registry reset is safe because `epoch_no` binding prevents
cross-epoch replay.  Nonces from prior epochs are irrelevant.

---

## 8. Ciphertext Malleability Across Layers

### 8.1 AES-GCM INT-CTXT

Both the Signal layer and PQ wrapper use AES-256-GCM, which provides
INT-CTXT (integrity of ciphertexts).  Any modification to the ciphertext
or authentication tag causes decryption to fail with overwhelming
probability (Proof-01, Theorem 4.1, Step 2: forgery probability
<= q_d / 2^{128}).

### 8.2 CBOR Wrapping Attack Surface

**Threat:** An adversary modifies the CBOR encoding of a transaction
without altering the inner ciphertext bytes, potentially causing the
recipient to parse the transaction differently.

**INV-MALLE-1 (CBOR Canonical Form).**

UmbraVox uses deterministic CBOR encoding (RFC 8949, Section 4.2):

1. Map keys are sorted in bytewise lexicographic order.
2. Integers use the shortest encoding.
3. Indefinite-length items are prohibited.

**Defense:**

```
forall tx_bytes received :
  let parsed = cbor_decode(tx_bytes)
  let reencoded = cbor_encode(parsed)
  assert(tx_bytes == reencoded)   -- canonical check
  OR reject(tx_bytes)
```

**Theorem 8.1 (CBOR Malleability Resistance).**

If CBOR deserialization enforces canonical encoding, then any modification
to the CBOR-encoded transaction that does not alter the decoded field
values is rejected.

**Proof.**  Canonical CBOR provides a bijection between byte sequences and
structured values (RFC 8949, Section 4.2.1).  If `tx_bytes /= tx_bytes'`
but `cbor_decode(tx_bytes) = cbor_decode(tx_bytes')`, then at least one
of the two is non-canonical and is rejected by the canonical check.  []

### 8.3 Combined Malleability Resistance

**Theorem 8.2 (Cross-Layer Non-Malleability).**

For any adversary A that modifies a transmitted message at any layer:

```
Pr[recipient accepts modified message] <=
  Adv^INT-CTXT_{AES-GCM}(A_pq)     -- PQ wrapper forgery
  + Adv^INT-CTXT_{AES-GCM}(A_sig)  -- Signal forgery
  + Pr[CBOR canonical bypass]       -- 0 if canonical check is correct
  + Adv^EUF-CMA_{Ed25519}(A_tx)    -- transaction signature forgery
```

Each term is negligible.  The product of negligible functions is negligible.
[]

### 8.4 Verification Obligation

**VER-MALLE-1.**  Fuzz testing of CBOR deserialization with:

- Valid canonical encoding (must accept)
- Non-canonical encodings of the same logical value (must reject)
- Truncated CBOR (must reject)
- CBOR with extra trailing bytes (must reject)
- CBOR with modified ciphertext bytes (GCM auth must fail after decode)

---

## 9. Timing Channels Across Layers

### 9.1 Threat Model

Decryption time at one layer may reveal information about the inner layer's
ciphertext, enabling a side-channel attack.  Specific concerns:

| Attack Vector | Information Leaked |
|--------------|-------------------|
| PQ wrapper decryption time | Signal ciphertext length (reveals message type: text vs ratchet refresh) |
| ML-KEM decapsulation time | Valid vs invalid ciphertext (but implicit rejection mitigates) |
| CBOR parsing time | Transaction structure complexity |
| GCM tag verification time | Early-reject vs full-decrypt timing |

### 9.2 Defense: Constant-Time Production Path

Per `doc/03-cryptography.md` lines 46-72, the production deployment uses
FFI bindings to constant-time C implementations for all secret-key
operations:

**INV-TIMING-1 (Constant-Time Decryption).**

```
forall ct1, ct2 with |ct1| = |ct2| :
  |time(decrypt(ct1)) - time(decrypt(ct2))| <= epsilon_hw
```

where `epsilon_hw` is the hardware-level timing jitter (cache effects,
pipeline stalls), not data-dependent branching.

### 9.3 Residual Timing Channels

**Length-dependent timing.**  AES-GCM decryption time is proportional to
ciphertext length.  Since message ciphertexts are padded to 1024-byte block
boundaries (doc/proof-02-protocol-security.md, Section 6.3), length
variations within a block are masked.

**ML-KEM implicit rejection timing.**  FIPS 203 specifies that decapsulation
always performs the full re-encryption check, outputting `H(z || c)` on
failure rather than an early error.  The C implementation must not
short-circuit on re-encryption mismatch.

**VER-TIMING-1.**  Timing tests must verify:

- `Decaps(sk, valid_ct)` and `Decaps(sk, invalid_ct)` execute within
  `epsilon_hw` of each other (measure over 10,000 iterations, require
  p > 0.05 on a t-test for timing difference).
- `AES-GCM-Decrypt(k, ct_1024)` and `AES-GCM-Decrypt(k, ct_1024')` for
  two distinct 1024-byte ciphertexts execute within `epsilon_hw`.
- GCM tag verification failure does not return faster than successful
  verification (the full decryption must be performed before checking
  the tag, or the tag check must be constant-time).

### 9.4 CBOR Parsing Timing

CBOR parsing operates on public data (the encoded transaction is visible
on-chain).  No secret-dependent branching occurs during CBOR decode.
This is not a timing channel because the adversary already knows the
CBOR structure (transactions are public).

---

## 10. Formal Composition Theorem

### 10.1 Definitions

Let:
- `lambda` : security parameter (lambda = 128)
- `negl(lambda)` : negligible function in lambda
- `PPT` : probabilistic polynomial-time
- `E_Signal(mk, m)` : Signal Double Ratchet encryption of m under message key mk
- `E_PQ(pk, ct)` : PQ wrapper encryption of ct under PQ-derived key pk
- `C(m) = E_PQ(pk_pq, E_Signal(mk_sig, m))` : composed encryption
- `KeyGen_composed()` : joint key generation (PQXDH + PQ chain initialisation)

### 10.2 Assumptions

- **A1:** CDH is hard on Curve25519 (Adv^CDH <= negl(lambda))
- **A2:** Module-LWE is hard for ML-KEM-768 parameters (Adv^MLWE <= negl(lambda))
- **A3:** AES-256 is a PRP (Adv^PRP <= negl(lambda))
- **A4:** SHA-512 compression function is a PRF (Adv^PRF_cf <= negl(lambda))
- **A5:** DLP is hard on Ed25519 curve (Adv^DLP <= negl(lambda))
- **A6:** ChaCha20 core is a PRF (Adv^PRF_CC <= negl(lambda))
- **A10:** HKDF-Extract is a randomness extractor (Theorem 3.1, Proof-01)

### 10.3 Main Theorem

**Theorem 10.1 (UmbraVox Composition Security).**

Let C be the composed UmbraVox encryption scheme.  For any PPT adversary A
in the IND-CCA2 game with at most q_e encryption queries, q_d decryption
queries, and running time t:

```
Adv^{IND-CCA2}_C(A) <=
    Adv^CCA_{ML-KEM-768}(B_1)           -- PQ key encapsulation
  + 4 * Adv^CDH_{X25519}(B_2)           -- PQXDH DH exchanges
  + Adv^EUF-CMA_{Ed25519}(B_3)          -- SPK authentication
  + (2 + L) * Adv^PRF_{HMAC-SHA512}(B_4)  -- HKDF Extract + Expand (L output blocks)
  + n * Adv^PRF_{HMAC-SHA512}(B_5)      -- Signal chain key forward secrecy (n steps)
  + 2 * Adv^AEAD_{AES-256-GCM}(B_6)    -- Signal + PQ wrapper AEAD (2 layers)
  + Adv^CR_{SHA-256}(B_7)               -- transaction hash collision resistance
```

where B_1, ..., B_7 are PPT reductions with running time at most t + poly(lambda).

Moreover (hybrid property):

```
Adv^{IND-CCA2}_C(A) is negligible if  A1 OR A2  holds
                                       AND  A3, A4, A5, A6, A10  hold
```

### 10.4 Proof

The proof proceeds by a sequence of 7 hybrid games.

**Game 0 (Real).**  The challenger runs the full UmbraVox protocol.
A interacts with encryption/decryption oracles for the composed scheme.

**Game 1 (Replace ML-KEM shared secrets).**  Replace every ML-KEM
shared secret (initial pq_ss and all ratchet refresh fresh_pq_ss) with
uniform random values.

*Transition bound:* `Adv^CCA_{ML-KEM-768}(B_1)` by a standard reduction
to ML-KEM IND-CCA2.  The adversary's decapsulation oracle is simulated
using the ML-KEM decapsulation oracle.

**Game 2 (Replace DH shared secrets).**  Replace all X25519 DH shared
secrets (dh1, ..., dh4 in PQXDH and all DH ratchet outputs) with
uniform random values.

*Transition bound:* `4 * Adv^CDH_{X25519}(B_2) + n_ratchet * Adv^CDH(B_2)`
where n_ratchet is the number of DH ratchet steps.  We absorb n_ratchet
into the CDH term since each ratchet step uses a fresh ephemeral key.

**Game 3 (Replace HKDF outputs).**  Replace all HKDF outputs (master
secret, root keys, chain keys, PQ chain keys, message keys) with
uniform random values.

*Transition bound:* `(2 + L) * Adv^PRF_{HMAC-SHA512}(B_4)` by the
HKDF PRF security (Proof-01, Theorem 3.1).  The factor 2 accounts for
Extract + Expand; L is the number of Expand output blocks.

**Game 4 (Signal forward secrecy).**  Show that compromise of chain
key CK_n does not reveal prior chain keys CK_0, ..., CK_{n-1}.

*Transition bound:* `n * Adv^PRF_{HMAC}(B_5)` by induction on the
chain (Proof-02, Theorem 2.1).

**Game 5 (Replace AES-GCM ciphertexts).**  Replace both the Signal
AES-GCM ciphertext and the PQ wrapper AES-GCM ciphertext with
encryptions of zero strings of the same length.

*Transition bound:* `2 * Adv^AEAD_{AES-256-GCM}(B_6)` by the IND-CCA2
security of AES-256-GCM applied independently to each layer (keys are
independent by Theorem 2.2 of this document).

**Game 6 (SPK authentication).**  Show that the adversary cannot inject
a forged signed prekey into the key registry.

*Transition bound:* `Adv^EUF-CMA_{Ed25519}(B_3)` (Proof-01, Theorem 6.1).

**Game 7 (Transaction integrity).**  Show that the adversary cannot
produce a transaction with a valid Ed25519 signature and SHA-256 hash
that differs from any honestly generated transaction.

*Transition bound:* `Adv^CR_{SHA-256}(B_7)` for hash collisions.

In Game 7, the adversary's view is independent of the plaintext: both
layers encrypt random strings, all keys are random, and all
authentication mechanisms are unforged.  The adversary's advantage
is 0.

**Hybrid security:**  Games 1 and 2 are independent:
- If A1 (CDH) holds but A2 (Module-LWE) fails: Game 2 alone makes all
  DH values random, providing sufficient entropy for HKDF extraction
  (Game 3).  Signal layer remains secure.
- If A2 holds but A1 fails: Game 1 alone makes all ML-KEM shared secrets
  random.  PQ wrapper remains secure.
- Security of the composed scheme requires breaking BOTH classical and
  PQ layers simultaneously.  []

### 10.5 Concrete Security

Substituting the concrete bounds from Proof-01:

```
Adv^{IND-CCA2}_C <=
    2^{-128}                              -- ML-KEM-768 (quantum)
  + 4 * 2^{-128}                          -- CDH on Curve25519
  + (q_h + q_s + 1)^2 / 2^{252}          -- Ed25519 (ROM)
  + (2 + L) * 2^{-127}                    -- HKDF via HMAC PRF
  + n * 2^{-127}                          -- chain forward secrecy
  + 2 * ((q_e + q_d)^2 / 2^{128} + q_d / 2^{128})  -- AES-GCM (2 layers)
  + 2^{-128}                              -- SHA-256 CR at birthday bound
```

For typical parameters (n <= 1000 ratchet steps, q_e + q_d <= 2^{20},
L <= 4, q_h + q_s <= 2^{40}):

```
Adv <= 2^{-128} + 2^{-126} + 2^{-172} + 6 * 2^{-127}
     + 1000 * 2^{-127} + 2 * (2^{-88} + 2^{-108}) + 2^{-128}
     ≈ 2^{-117}
```

Effective security: approximately 117 bits for the full composed system,
dominated by the chain forward secrecy term with n = 1000 ratchet steps.
Per individual session (n <= 50 between PQ refreshes): approximately
122 bits.

---

## 11. Coq Proof Structure

### 11.1 Module Dependency Graph

```
UmbraVox_Composition_Proof/
│
├── Primitives/
│   ├── SHA256.v              -- CR game, assumption A4
│   ├── HMAC_SHA512.v         -- PRF game, reduction from A4
│   ├── HKDF.v                -- Extract/Expand, dual-PRF lemma
│   ├── AES256GCM.v           -- AEAD game (IND-CCA2 + INT-CTXT)
│   ├── X25519.v              -- CDH game, assumption A1
│   ├── Ed25519.v             -- EUF-CMA game, assumption A5
│   ├── MLKEM768.v            -- IND-CCA2 game, assumption A2, FO transform
│   └── ChaCha20CSPRNG.v      -- PRF game, forward secrecy, assumption A6
│
├── Protocols/
│   ├── PQXDH.v               -- AKE-CK game, hybrid argument (Proof-02 §1)
│   │   imports: X25519, MLKEM768, HKDF, Ed25519
│   │
│   ├── DoubleRatchet.v        -- Forward secrecy + PCS theorems (Proof-02 §2)
│   │   imports: HMAC_SHA512, HKDF, X25519, AES256GCM
│   │
│   ├── PQWrapper.v            -- PQ wrapper IND-CCA2 (Proof-02 §3)
│   │   imports: MLKEM768, HKDF, AES256GCM
│   │
│   └── SignalPQComposition.v  -- Composed IND-CCA2 (Proof-02 §4)
│       imports: DoubleRatchet, PQWrapper, HKDF
│
├── Hardening/
│   ├── KeyIsolation.v         -- Theorem 2.2 (key independence)
│   │   imports: HKDF
│   │   proves: forall i j, info_string(i) <> info_string(j) ->
│   │           independent(key_family(i), key_family(j))
│   │
│   ├── ErrorPropagation.v     -- INV-ERR-1, INV-ERR-2, INV-ERR-3
│   │   imports: MLKEM768, AES256GCM, DoubleRatchet
│   │   proves: ml_kem_failure_does_not_leak_sk
│   │           gcm_failure_no_ratchet_advance
│   │
│   ├── DowngradeResistance.v  -- INV-DOWN-1, INV-DOWN-2
│   │   imports: MLKEM768, PQXDH
│   │   proves: no_pq_skip_without_log
│   │           mlkem_ciphertext_size_fixed
│   │
│   ├── VersionNegotiation.v   -- INV-VER-1, INV-VER-2
│   │   imports: (blockchain types)
│   │   proves: revision_monotonicity
│   │           minimum_revision_floor_enforced
│   │
│   ├── ReplayPrevention.v     -- Theorem 7.1
│   │   imports: Ed25519, SHA256
│   │   proves: epoch_bound_prevents_replay
│   │
│   ├── Malleability.v         -- Theorems 8.1, 8.2
│   │   imports: AES256GCM, Ed25519
│   │   proves: cbor_canonical_bijection
│   │           cross_layer_non_malleability
│   │
│   ├── OrderingCorrectness.v  -- Theorem 6.1
│   │   imports: SignalPQComposition
│   │   proves: signal_inner_pq_outer_is_correct
│   │
│   └── TimingIsolation.v      -- INV-TIMING-1 (specification only)
│       -- Timing properties cannot be proven in Coq (they are
│       -- implementation-level concerns).  This module states the
│       -- specification as axioms and verification obligations.
│
└── TopLevel/
    └── CompositionTheorem.v   -- Theorem 10.1 (main result)
        imports: ALL of the above
        proves:
          Theorem UmbraVox_composition_security :
            forall (A : Adversary) (lambda : nat),
            (assumption_CDH lambda \/ assumption_MLWE lambda) ->
            assumption_AES_PRP lambda ->
            assumption_SHA512_PRF lambda ->
            assumption_DLP lambda ->
            assumption_ChaCha20_PRF lambda ->
            assumption_HKDF_extractor lambda ->
            Adv_IND_CCA2_composed A lambda <=
              Adv_CCA_MLKEM A lambda
              + 4 * Adv_CDH_X25519 A lambda
              + Adv_EUF_CMA_Ed25519 A lambda
              + (2 + L) * Adv_PRF_HMAC A lambda
              + n * Adv_PRF_HMAC A lambda
              + 2 * Adv_AEAD_AES_GCM A lambda
              + Adv_CR_SHA256 A lambda.
```

### 11.2 Proof Obligations Summary

| Module | Theorem | Status |
|--------|---------|--------|
| `KeyIsolation.v` | Info string uniqueness + key independence | To prove |
| `ErrorPropagation.v` | ML-KEM implicit rejection isolation | To prove |
| `DowngradeResistance.v` | PQ wrapper mandatory invariant | To prove |
| `VersionNegotiation.v` | Revision monotonicity | To prove |
| `ReplayPrevention.v` | Epoch-bound replay prevention | To prove |
| `Malleability.v` | CBOR canonical bijection | To prove |
| `OrderingCorrectness.v` | Signal-inner/PQ-outer correctness | To prove |
| `TimingIsolation.v` | Constant-time specification | Axiomatised |
| `CompositionTheorem.v` | Main composition theorem (10.1) | To prove |

### 11.3 Axioms (Unproven Assumptions)

The Coq development takes the following as axioms (these are the
cryptographic hardness assumptions that cannot be proven
computationally):

```coq
Axiom cdh_hard : forall (A : CDH_Adversary) (lambda : nat),
  Adv_CDH A lambda <= negl lambda.

Axiom mlwe_hard : forall (A : MLWE_Adversary) (lambda : nat),
  Adv_MLWE A lambda <= negl lambda.

Axiom aes_prp : forall (A : PRP_Adversary) (lambda : nat),
  Adv_PRP_AES256 A lambda <= negl lambda.

Axiom sha512_prf : forall (A : PRF_Adversary) (lambda : nat),
  Adv_PRF_SHA512cf A lambda <= negl lambda.

Axiom dlp_hard : forall (A : DLP_Adversary) (lambda : nat),
  Adv_DLP_Ed25519 A lambda <= negl lambda.

Axiom chacha20_prf : forall (A : PRF_Adversary) (lambda : nat),
  Adv_PRF_ChaCha20 A lambda <= negl lambda.

Axiom hkdf_extractor : forall (A : Extractor_Adversary) (lambda : nat),
  Adv_Ext_HKDF A lambda <= negl lambda.
```

### 11.4 Estimated Proof Effort

| Module | Estimated LOC (Coq) | Complexity |
|--------|--------------------:|------------|
| Primitives (8 modules) | 2,400 | Low (game definitions + axiom statements) |
| Protocols (4 modules) | 3,200 | Medium (hybrid game sequences) |
| Hardening (8 modules) | 2,800 | Medium (cross-cutting invariants) |
| TopLevel | 800 | High (assembles all reductions) |
| **Total** | **~9,200** | |

### 11.5 External Dependencies

The Coq development should use:

- **Coq 8.18+** (for universe polymorphism in probability monad)
- **MathComp** (for finite field arithmetic in X25519/Ed25519 game definitions)
- **FCF (Foundational Cryptography Framework)** or equivalent for
  probabilistic game-based proof infrastructure

No external Haskell libraries are required; the Coq proof is independent
of the implementation.

---

## Appendix A: Verification Obligation Checklist

| ID | Obligation | Section | Type |
|----|-----------|---------|------|
| VER-KEY-ISO-1 | No cross-layer key reuse without HKDF | 2.4 | Static analysis |
| VER-VERSION-1 | Chain revision boundary testing | 5.5 | Test cases |
| VER-MALLE-1 | CBOR canonical encoding fuzz testing | 8.4 | Fuzz testing |
| VER-TIMING-1 | Constant-time decryption verification | 9.3 | Timing tests |
| INV-LAYER-1 | HKDF domain separation at every boundary | 1.3 | Coq proof |
| INV-ERR-1 | ML-KEM failure handling | 3.1 | Coq proof + test |
| INV-ERR-2 | GCM failure no ratchet advance | 3.2 | Coq proof + test |
| INV-ERR-3 | Desync forces re-handshake | 3.3 | Test cases |
| INV-DOWN-1 | PQ wrapper mandatory | 4.2 | Coq proof + test |
| INV-DOWN-2 | ML-KEM ciphertext size check | 4.4 | Test cases |
| INV-VER-1 | Minimum revision floor | 5.3 | Coq proof + test |
| INV-VER-2 | Epoch revision monotonicity | 5.4 | Coq proof + test |
| INV-REPLAY-1 | Epoch-bound nonces | 7.2 | Coq proof + test |
| INV-MALLE-1 | CBOR canonical form | 8.2 | Coq proof + fuzz |
| INV-TIMING-1 | Constant-time decryption | 9.2 | Axiomatised + test |
