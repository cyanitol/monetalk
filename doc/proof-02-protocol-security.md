# Proof-02: Protocol-Level Cryptographic Security

**DO-333 Requirement:** REQ-CRYPTO-009
**Source:** `doc/03-cryptography.md` lines 87–228
**Assumptions used:** A1, A2, A3, A4, A5, A10 (see `doc/21-formal-proofs-index.md`)
**Depends on:** Proof-01 (all primitive reductions)

---

## Preamble

This document proves security properties of UmbraVox's protocol-level
cryptographic constructions: PQXDH key agreement, Double Ratchet, the PQ
outer wrapper, their composition, and the end-to-end message confidentiality
guarantee.  Each proof builds on the primitive reductions established in
Proof-01.

---

## 1. X3DH / PQXDH Key Agreement Security

### 1.1 Security Model

We use the Canetti-Krawczyk (CK) model for authenticated key exchange (AKE),
extended for the hybrid setting (Bindel, Brendel, Fischlin, Goncalves &
Stebila 2019).

**CK Security Game:**

```
Game AKE-CK:
  Setup: Each party i has long-term key pair (IK_i, ik_i).
  Sessions: A activates sessions between parties, each producing a
            session key sk.
  Queries:
    - Send(i, j, msg): deliver message in key exchange
    - Reveal(session): reveal session key
    - Corrupt(i): reveal long-term key of party i
    - Test(session): receive either real sk or random; output guess b'

  Freshness: A session is fresh if neither it nor its partner was
             Revealed, and neither party was Corrupted before the session
             completed.

  Adv^AKE(A) = |Pr[b'=1|real] - Pr[b'=1|random]|.
```

### 1.2 PQXDH Protocol

Alice (initiator) and Bob (responder) execute:

```
Alice                                    Bob
IK_A, EK_A (ephemeral),                IK_B, SPK_B (signed prekey),
                                        OPK_B (one-time prekey),
                                        PQ_PK_B (ML-KEM-768 public key)

dh1 = X25519(ik_A, SPK_B)
dh2 = X25519(ek_A, IK_B)
dh3 = X25519(ek_A, SPK_B)
dh4 = X25519(ek_A, OPK_B)              (omitted if OPK exhausted)
(pq_ct, pq_ss) = ML-KEM.Encaps(PQ_PK_B)

IKM = 0xFF*32 || dh1 || dh2 || dh3 || dh4 || pq_ss
MS  = HKDF(salt=0x00*32, IKM, info="UmbraVox_PQXDH_v1")
```

### 1.3 Theorem

**Theorem 1.1 (PQXDH AKE Security).**

In the CK model, for any PPT adversary A:

```
Adv^AKE_{PQXDH}(A) ≤ Adv^CCA_{ML-KEM}(B₁) + 4·Adv^CDH_{X25519}(B₂)
                     + Adv^PRF_{HKDF}(B₃) + Adv^EUF-CMA_{Ed25519}(B₄)
```

Moreover, the master secret MS is indistinguishable from random if EITHER
CDH (A1) OR Module-LWE (A2) holds (hybrid security).

### 1.4 Proof (Hybrid Game Sequence)

**Game 0 (Real).**  Execute PQXDH as specified.  A interacts with the
AKE-CK game.

**Game 1 (Replace pq_ss).**  Replace the ML-KEM shared secret pq_ss with
a uniformly random value u_pq ←$ {0,1}^{256}.

*Transition:* Any distinguisher between Game 0 and Game 1 yields an
IND-CCA2 adversary against ML-KEM-768 (by A2).

```
|Pr[A wins in G0] - Pr[A wins in G1]| ≤ Adv^CCA_{ML-KEM}(B₁)
```

**Game 2 (Replace dh1).**  Replace dh1 = X25519(ik_A, SPK_B) with a
uniformly random value u_1 ←$ {0,1}^{256}.

*Transition:* In a fresh session, the adversary does not know ik_A (no
Corrupt query on Alice before session completion).  Any distinguisher
solves CDH on (IK_A, SPK_B).

```
|Pr[A wins in G1] - Pr[A wins in G2]| ≤ Adv^CDH(B₂)
```

**Game 3 (Replace dh2, dh3, dh4).**  Three identical sub-games (3a, 3b, 3c),
each replacing one DH value with uniform random via a CDH reduction
analogous to Game 2.  Each sub-game costs one CDH advantage term.

```
|Pr[A wins in G2] - Pr[A wins in G3]| ≤ 3·Adv^CDH(B₂)
```

**Game 4 (Replace MS).**  In Game 3, the HKDF input IKM consists of the
fixed prefix 0xFF*32 concatenated with 5 uniform random values.  By the
HKDF extract security (Theorem 3.1 in Proof-01, using A10), the output
MS is indistinguishable from random.

```
|Pr[A wins in G3] - Pr[A wins in G4]| ≤ Adv^PRF_{HKDF}(B₃)
```

In Game 4, the test session key is independent of all protocol messages.
A's advantage is 0.

**SPK authentication.**  Bob's signed prekey SPK_B is authenticated via
Ed25519 signature.  A forged SPK would require breaking EUF-CMA (by Theorem 6.1 of Proof-01, using A5),
adding Adv^EUF-CMA_{Ed25519}(B₄) to the bound.

**Hybrid security argument.**  Games 1–3 are independent: Game 1 relies
on A2 (Module-LWE), Games 2–3 rely on A1 (CDH).  If CDH is broken (e.g.,
by a quantum adversary), Game 1 alone ensures u_pq makes the IKM have
sufficient min-entropy for HKDF extraction.  If Module-LWE is broken,
Games 2–3 alone ensure 4 uniform DH values provide sufficient min-entropy.
Security holds if EITHER assumption holds.  The surviving component(s) contribute computational min-entropy bounded by the underlying problem hardness: ~126 bits for CDH on Curve25519 (from the Pollard-rho bound on a ~252-bit group), ~128 bits for ML-KEM-768.  For the CDH-only case, four independent DH values contribute; by Proof-01 Lemma 3.2, the combined IKM has sufficient min-entropy for HKDF extraction even though each individual CDH component provides ~126 bits (the HKDF extraction step requires only that the source has super-logarithmic min-entropy, which ~126 bits amply satisfies).  Note: computational min-entropy is bounded by the hardness of the underlying problem, not the output bitlength (256 bits).  □

### 1.5 OPK Exhaustion Degradation

When OPK_B is unavailable, dh4 is omitted:

```
IKM = 0xFF*32 || dh1 || dh2 || dh3 || pq_ss
```

The security bound becomes:

```
Adv ≤ Adv^CCA_{ML-KEM}(B₁) + 3·Adv^CDH(B₂) + Adv^PRF_{HKDF}(B₃) + Adv^EUF-CMA(B₄)
```

Loss: one fewer CDH component.  One-time binding (OPK prevents replay of
initial messages) is lost, but mutual authentication and forward secrecy
are preserved.  The PQ component is unaffected.

---

## 2. Double Ratchet — Forward Secrecy + Post-Compromise Security

### 2.1 Forward Secrecy

**Definition (Forward Secrecy).**  Compromise of the current ratchet state
does not reveal plaintext of messages encrypted under prior ratchet states.

**Theorem 2.1 (Double Ratchet Forward Secrecy).**

Let CK_0, CK_1, …, CK_n be consecutive chain keys in a symmetric ratchet
chain, where CK_{i+1} = HMAC(CK_i, 0x02).  Given CK_n, no PPT adversary
can distinguish CK_j (j < n) from random.

```
Adv^FS_{DR}(A) ≤ n · Adv^PRF_{HMAC}(A')
```

**Proof.**

By induction on the chain length and the PRF property of HMAC:

1. **Base case (n=1):** CK_0 is unknown.  CK_1 = HMAC(CK_0, 0x02).
   By the PRF property (Theorem 2.1 of Proof-01), when CK_0 is uniform,
   CK_1 is indistinguishable from random.  Since the adversary knows only
   CK_1, recovering CK_0 requires inverting the PRF.  PRF security implies
   one-wayness: if an inverter could recover CK_0 from CK_1 with non-
   negligible probability, it could distinguish HMAC(CK_0, ·) from a
   random function (by inverting, re-evaluating, and checking consistency),
   contradicting A4.

2. **Inductive step:** Assume CK_0, …, CK_{n-1} are indistinguishable from
   random given CK_n.  CK_n = HMAC(CK_{n-1}, 0x02).  By the same PRF-
   implies-one-wayness argument, CK_{n-1} cannot be recovered from CK_n.
   By the inductive hypothesis, CK_0, …, CK_{n-2} are also safe.

Each step costs one PRF advantage term.  After secure erasure of CK_j
(j < n), even a state compromise at time n reveals nothing about prior
message keys MK_j = HMAC(CK_j, 0x01).  □

### 2.2 Post-Compromise Security

**Definition (Post-Compromise Security).**  After state compromise, the
protocol eventually recovers confidentiality once both parties exchange
messages with fresh ephemeral keys.

**Theorem 2.2 (Double Ratchet Post-Compromise Security).**

After a DH ratchet step with fresh ephemeral keys (ek_A', ek_B'), the new
root key RK' is indistinguishable from random given the compromised state,
provided CDH holds (A1).

```
Adv^PCS_{DR}(A) ≤ Adv^CDH(B) + Adv^PRF_{HKDF}(B')
```

**Proof.**

1. The DH ratchet computes dh_out = X25519(ek_A', EK_B') where ek_A' is
   a fresh ephemeral secret unknown to the adversary (generated after
   compromise).
2. Even knowing the prior state (old RK, old CK), the adversary cannot
   compute dh_out without solving CDH on (ek_A'·G, EK_B').
3. The new root key RK' = HKDF(RK_old, dh_out) incorporates dh_out as
   fresh entropy.  By the HKDF extract property (A10), RK' is
   indistinguishable from random when dh_out has sufficient min-entropy.
4. All subsequent chain keys and message keys derived from RK' are
   independent of the compromised state.

**Vulnerability window:** The DH ratchet advances only when the message
direction changes (Alice→Bob then Bob→Alice, or vice versa).  In a
long one-sided conversation (e.g., many consecutive messages from Alice
without a reply from Bob), no DH ratchet step occurs and PCS is not
restored until Bob sends a reply.  During this window, the symmetric
ratchet chain keys are derivable from the compromised state.

The PQ wrapper (§3.5) partially mitigates this: PQ ratchet refreshes
occur every 50 messages per direction regardless of DH ratchet steps,
restoring PQ-layer PCS within at most 50 messages.  Full classical PCS
(DH layer) requires a direction change.  □

### 2.3 Skipped Key Security

UmbraVox limits skipped key storage (`doc/03-cryptography.md` lines 139–145):
- Maximum 1,000 skipped keys per session
- Eviction: keys older than 500 ratchet steps
- Memory bound: ~68 KB per session

**Lemma 2.3.**  The skipped key cache does not degrade forward secrecy
beyond the 500-step eviction window.

**Proof.**  A skipped message key MK_j is retained only if
current_counter - j ≤ 500.  After eviction, MK_j is erased.  State
compromise at step n reveals at most min(1000, n) cached message keys,
all within 500 steps of n.  Messages older than 500 steps have their
keys erased, preserving forward secrecy for those messages.

The memory bound is 1000 keys × 68 bytes = 68,000 bytes (~66 KiB),
comprising 32-byte public key + 4-byte counter + 32-byte message key per
skipped key.  (Note: `doc/03-cryptography.md` line 142 rounds this to
~64 KB.)  This ensures bounded resource consumption even under adversarial
message reordering.  □

---

## 3. PQ Outer Wrapper Security

### 3.1 Construction

The PQ wrapper encrypts Signal ciphertext under a PQ-derived key:

```
pq_chain_key(0) = HKDF(salt=MS, IKM=pq_ss_initial, info="UmbraVox_PQChain_v1")
pq_chain_key(i+1) = HKDF(salt=pq_chain_key(i), IKM=fresh_pq_ss, info="UmbraVox_PQChain_v1")
pq_msg_key(i, j) = HKDF(salt=pq_chain_key(i), IKM=j, info="UmbraVox_PQMsg_v1")

PQ_Wrap(signal_ct) = AES-256-GCM(pq_msg_key, signal_ct)
```

where fresh_pq_ss is obtained via ML-KEM-768 encapsulation every 50
messages per direction.

### 3.2 Theorem

**Theorem 3.1 (PQ Wrapper IND-CCA2).**

```
Adv^CCA_{PQ-Wrap}(A) ≤ Adv^CCA_{ML-KEM}(B₁) + 2·Adv^PRF_{HKDF}(B₂)
                      + Adv^CCA_{AES-GCM}(B₃)
```

### 3.3 Proof

**Game 0 (Real).**  Encrypt as specified.

**Game 1.**  Replace fresh_pq_ss with uniform random u ←$ {0,1}^{256}.

*Transition:* Adv^CCA_{ML-KEM}(B₁) by A2.

**Game 2.**  Replace pq_msg_key(i, j) with uniform random.

*Transition:* In Game 1, pq_chain_key(i) is derived from HKDF with a
uniform input u.  By the HKDF PRF property (A10), pq_chain_key(i) is
indistinguishable from random (first HKDF application).  Then
pq_msg_key(i, j) = HKDF(random, j) is also indistinguishable from random
(second HKDF application).  Cost: 2·Adv^PRF_{HKDF}(B₂).

In Game 2, pq_msg_key is already uniform random, so the PQ-wrapped
ciphertext is AES-256-GCM encryption under a truly random key.  The
adversary's residual advantage in Game 2 is at most Adv^CCA_{AES-GCM}(B₃)
by the IND-CCA2 security of AES-256-GCM (Theorem 4.1 of Proof-01).

Summing transitions: Adv ≤ Adv^CCA_{ML-KEM}(B₁) + 2·Adv^PRF_{HKDF}(B₂)
+ Adv^CCA_{AES-GCM}(B₃).  □

### 3.4 PQ Wrapper Forward Secrecy

**Lemma 3.2.**  After a PQ ratchet refresh at message i, compromise of
pq_chain_key(j) for j > i does not reveal pq_chain_key(i) or earlier keys.

**Proof.**  Each pq_chain_key(i+1) = HKDF(pq_chain_key(i), fresh_pq_ss).
By PRF one-wayness of HKDF (Proof-01, Theorem 3.1), knowledge of
pq_chain_key(i+1) does not reveal pq_chain_key(i).  □

### 3.5 PQ Wrapper Post-Compromise Security

**Lemma 3.3.**  After state compromise, the next PQ ratchet refresh (within
50 messages) restores PQ-layer confidentiality.

**Proof.**  The refresh generates a fresh ML-KEM encapsulation.  The new
pq_chain_key is HKDF(compromised_key, fresh_pq_ss).  By ML-KEM IND-CCA2
(A2), fresh_pq_ss is indistinguishable from random even given the
compromised state.  By HKDF extraction (A10), the new pq_chain_key is
indistinguishable from random.  □

---

## 4. Signal + PQ Composition Security (Hybrid IND-CCA2)

### 4.1 Main Theorem

**Lemma 4.0 (Signal DR IND-CCA2).**  The Signal Double Ratchet with AES-256-GCM provides IND-CCA2 security:
```
Adv^CCA_{Signal-DR}(A) ≤ Adv^CDH(B₁) + Adv^PRF_{HKDF}(B₂) + n·Adv^PRF_{HMAC}(B₃) + Adv^CCA_{AES-GCM}(B₄)
```
where n is the maximum chain length.  The bound is established by the
following reduction:

1. **DH ratchet step** (CDH term): Each DH ratchet produces a fresh
   shared secret dh_out.  Replacing dh_out with random incurs cost
   Adv^CDH per step; only one active DH ratchet exists at a time, so a
   single CDH term suffices (the adversary must break the *current* DH
   to compromise forward secrecy).
2. **Root key derivation** (HKDF term): RK' = HKDF(RK, dh_out).  By
   Proof-01 Theorem 3.1 (HKDF PRF security), the output RK' is
   indistinguishable from random given random dh_out.
3. **Chain key evolution** (n × HMAC term): Each of n chain steps
   applies CK_{i+1} = HMAC(CK_i, 0x02).  By Theorem 2.1 (forward
   secrecy), replacing each chain key with random incurs cost
   n · Adv^PRF_{HMAC} via a standard hybrid over chain positions.
4. **Message encryption** (AES-GCM term): By Proof-01 Theorem 4.1
   (AES-256-GCM AEAD), ciphertexts under random message keys are
   IND-CCA2.

This construction follows the modular analysis framework for Signal-like
ratchets (Alwen, Coretti & Dodis 2019, "Security of the Signal Double
Ratchet Protocol," Eurocrypt 2019), which establishes that combining
CKA (Continuous Key Agreement) with symmetric ratcheting yields
IND-CCA-like security for the composed scheme.

**Theorem 4.1 (Composed Encryption Security).**

Let PQ_Wrap(Signal_DR(m)) denote the full UmbraVox message encryption.
For any PPT adversary A:

```
Adv^CCA_{composed}(A) ≤ Adv^CCA_{Signal}(A₁) + Adv^CCA_{PQ}(A₂)
                       + Adv^PRF_{HKDF}(A₃)
```

where:
- Adv^CCA_{Signal} ≤ Adv^CDH(B) + Adv^PRF_{HKDF}(B') + n·Adv^PRF_{HMAC}(B'') + Adv^CCA_{AES-GCM}(B''')
- Adv^CCA_{PQ} ≤ Adv^CCA_{ML-KEM}(B₁) + 2·Adv^PRF_{HKDF}(B₂) + Adv^CCA_{AES-GCM}(B₃)

Moreover, Adv^CCA_{composed} is negligible if EITHER CDH (A1) OR
Module-LWE (A2) holds.

### 4.2 Proof (Hybrid Reduction)

**Game 0 (Real).**  Full protocol execution.  Message m is encrypted as:
1. Signal: ct_signal = AES-GCM(mk_signal, m)
2. PQ Wrap: ct_final = AES-GCM(mk_pq, ct_signal)

**Game 1 (Replace Signal layer).**  Replace ct_signal with encryption of
a random message of the same length.

*Transition:* The Signal Double Ratchet provides IND-CCA2 security by
combining forward secrecy (Theorem 2.1), post-compromise security
(Theorem 2.2), and AES-256-GCM AEAD security (Proof-01, Theorem 4.1).
Specifically, an adversary breaking Signal IND-CCA2 must either invert
the HMAC chain (violating PRF, A4), solve CDH on fresh ephemeral DH
(violating A1), or break AES-GCM (violating A3).  Thus:

```
|Pr[G0] - Pr[G1]| ≤ Adv^CCA_{Signal}(A₁)
```

**Game 2 (Replace PQ layer).**  Replace ct_final with encryption of a
random string under the PQ key.

*Transition:* By Theorem 3.1:

```
|Pr[G1] - Pr[G2]| ≤ Adv^CCA_{PQ}(A₂)
```

**Game 3 (Key independence).**  Argue that Signal keys and PQ keys are
derived from independent sources: Signal keys from DH ratchet (CDH),
PQ keys from ML-KEM ratchet (Module-LWE).  The two key hierarchies share
the initial master secret MS.  The PQ chain is seeded as:
`pq_chain_key(0) = HKDF(salt=MS, IKM=pq_ss_initial, info="UmbraVox_PQChain_v1")`
(§3.1).  MS serves as the salt (not the IKM) in this extraction, so even if
MS is known to the adversary, the PQ chain key's pseudorandomness depends
on the min-entropy of pq_ss_initial (from ML-KEM), not MS.  By HKDF
extract security (A10), the salt need not be secret — it only needs to be
non-degenerate.  The Signal root key is derived via a separate HKDF call
with info="UmbraVox_Ratchet_v1", providing domain separation.  Subsequent
Signal keys depend on DH ratchet outputs (CDH), while PQ keys depend on
ML-KEM encapsulations (Module-LWE).  After the initial derivation, the
two key hierarchies evolve independently.

```
|Pr[G2] - Pr[G3]| ≤ Adv^PRF_{HKDF}(A₃)
```

In Game 3, the adversary sees double encryption under two independent
random keys, which is indistinguishable from random.

**Independence argument (hybrid security):**

- If CDH holds but Module-LWE is broken: Signal layer alone provides
  IND-CCA2 security.  The PQ wrapper is transparent (adversary can
  decrypt it) but the inner Signal ciphertext remains secure.
- If Module-LWE holds but CDH is broken: PQ wrapper alone provides
  IND-CCA2 security.  The Signal layer is transparent but the outer
  PQ encryption remains secure.
- If both hold: double encryption with independent keys (standard
  composition: security is at least as strong as the stronger layer).  □

### 4.3 Deniability Preservation

**Lemma 4.2.**  The composed encryption preserves deniability: no
component of the ciphertext constitutes a non-repudiable proof of
authorship by the sender.

**Proof.**  The Signal protocol uses symmetric MACs (HMAC) for message
authentication, not digital signatures.  Both sender and receiver can
compute the MAC (shared key), so the MAC does not prove authorship to a
third party.  The PQ wrapper uses AES-256-GCM (symmetric AEAD), which
similarly provides no non-repudiation.  No asymmetric signatures are
applied to message content.

The only asymmetric signatures in the system are on prekeys (SPK) and
transactions, neither of which binds a specific message to a sender.  □

---

## 5. PQ Ratchet Forward Secrecy Restoration

### 5.1 Theorem

**Theorem 5.1 (PQ Forward Secrecy Restoration).**

After a state compromise at message i, a fresh ML-KEM encapsulation at
message i + 50 (the next PQ ratchet refresh) restores forward secrecy
for all messages from i + 50 onward.

### 5.2 Proof

Let S_i denote the compromised state at message i, which includes
pq_chain_key(k) for some ratchet epoch k.

1. **Messages i+1 to i+50:** These use pq_msg_key(k, j) = HKDF(pq_chain_key(k), j)
   for j = counter values.  Since pq_chain_key(k) is known to the adversary,
   these message keys are computable.  **These messages are NOT protected.**
   (This is the documented vulnerability window of at most 50 messages per
   direction within each 50-message refresh interval,
   `doc/03-cryptography.md` lines 151–159.)

2. **Message i+50 (PQ ratchet refresh):** The sender performs:
   ```
   (pq_ct, fresh_pq_ss) = ML-KEM.Encaps(recipient_pq_pk)
   pq_chain_key(k+1) = HKDF(pq_chain_key(k), fresh_pq_ss)
   ```

3. **fresh_pq_ss is independent of S_i:** By ML-KEM IND-CCA2 (Theorem 7.1
   of Proof-01, using A2), fresh_pq_ss is indistinguishable from random
   even given the adversary's knowledge of S_i.  The adversary does not
   know the recipient's ML-KEM secret key (separate from the compromised
   ratchet state).

4. **pq_chain_key(k+1) is indistinguishable from random:** By HKDF
   extraction (A10) with input (pq_chain_key(k), fresh_pq_ss) where
   fresh_pq_ss provides ≥ 128 bits of computational min-entropy
   (bounded by ML-KEM-768 IND-CCA2 hardness, not the 256-bit output length):

   ```
   Adv^{distinguish}(pq_chain_key(k+1), random) ≤ Adv^CCA_{ML-KEM} + Adv^PRF_{HKDF}
   ```

5. **Forward secrecy restored:** After secure erasure of pq_chain_key(k),
   the adversary cannot derive pq_chain_key(k+1) or any subsequent keys.
   Messages from i+50 onward are protected.  □

### 5.3 Vulnerability Window Analysis

The maximum vulnerability window is 50 messages per direction (within each
50-message refresh interval).  In the worst case:
- Compromise occurs at the refresh boundary (message i, just after the
  PQ ratchet refresh completes and the new chain key is derived).
- The adversary knows the new pq_chain_key(k) and can decrypt messages
  i+1 through i+50 (the next refresh point), yielding 50 vulnerable
  messages before forward secrecy is restored at message i+50.

This is a deliberate engineering trade-off: more frequent refreshes would
reduce the window but increase bandwidth overhead (each refresh costs
~2,276 bytes for the ML-KEM ciphertext + new encapsulation key).

---

## 6. End-to-End Message Confidentiality (Full Stack)

### 6.1 Theorem

**Theorem 6.1 (E2E Confidentiality).**

For any PPT adversary A who:
- Observes all blockchain data (blocks, transactions, ciphertexts)
- Controls fewer than 1/3 of validators
- Cannot compromise either endpoint's long-term keys

the probability of recovering any plaintext message is negligible:

```
Adv^E2E-conf(A) ≤ Adv^CCA_{composed}(A₁)
```

where Adv^CCA_{composed} is as in Theorem 4.1.

*Note:* Sender anonymity is a separate property provided by Dandelion++
(Layer 5).  The anonymity advantage Adv^{anon}_{Dandelion}(A₂) bounds
the probability of linking a transaction to its sender's IP address, and
is analysed independently in Proof-07 §6.

### 6.2 Proof (Layer-by-Layer)

UmbraVox messages traverse 5 layers.  We show each layer preserves
confidentiality:

**Layer 1 (Signal Double Ratchet).**  Message m is encrypted to ct_signal
under message key mk derived from the DH ratchet.  By Theorems 2.1, 2.2,
and AES-256-GCM security (Theorem 4.1 of Proof-01), ct_signal is IND-CCA2
assuming CDH (A1), AES-256 PRP (A3), and HMAC PRF (A4).

**Layer 2 (PQ Outer Wrapper).**  ct_signal is encrypted to ct_pq under
the PQ chain key.  By Theorem 3.1, ct_pq is IND-CCA2 assuming
Module-LWE (A2), AES-256 PRP (A3), and HKDF ROM (A10).

**Layer 3 (CBOR Serialisation).**  ct_pq is serialised into a CBOR-encoded
transaction.  CBOR is a deterministic encoding; it adds no security but
introduces no weakness (the ciphertext bytes are preserved verbatim).

**Layer 4 (Blockchain Storage).**  The transaction is included in a block.
The ciphertext is stored on-chain.  Validators process the transaction
without decrypting it (they have neither the Signal keys nor the PQ keys).
An adversary controlling < 1/3 of validators can read the ciphertext
(it is public on-chain) but cannot decrypt it by Layers 1–2.

**Layer 5 (Dandelion++ Network Layer).**  During propagation, Dandelion++
provides sender anonymity.  The stem phase routes the transaction through
a random path before the fluff phase broadcasts it.  This prevents linking
the transaction to the sender's IP address.

**Composition argument.**  Breaking E2E confidentiality requires either:
- Breaking the composed encryption (Theorem 4.1), which requires breaking
  BOTH CDH (Signal layer) AND Module-LWE (PQ layer) simultaneously, OR
- Compromising an endpoint's keys (excluded by assumption).

### 6.3 Metadata Limitation

**Documented v1 limitation:**  Sender and recipient addresses (public keys)
are visible on-chain in plaintext.  This is a deliberate v1 design choice;
stealth addresses are planned for v2.  The adversary can observe who
communicates with whom, but not message content.

Transaction timing, frequency, and size (rounded to 1024-byte blocks) are
also observable.  Dandelion++ mitigates IP-level timing analysis but does
not hide on-chain metadata.

### 6.4 Concrete Security Summary

Under the assumption that both CDH and Module-LWE hold:
- Classical adversary: ~126 bits for authentication (limited by Ed25519/ECVRF DLP); per-key AES-256-GCM confidentiality is ~106 bits
  for ratchet chains of ~1000 messages of up to 64 KiB (see Proof-01 §4.6)
- Quantum adversary (harvest-now-decrypt-later): ~128 bits (ML-KEM-768
  protects message confidentiality; DLP-based components affect only
  authentication and consensus, not message encryption after initial
  key agreement)

If a quantum adversary breaks CDH in the future:
- Past messages remain confidential (ML-KEM-768 provides ~128 quantum bits)
- Future key agreements require new authentication mechanism (Ed25519
  signatures on prekeys become forgeable); this is a documented v2
  migration requirement.  □
