# Hardening Spec 03: Stealth Addresses (V1)

**Status:** V1 MANDATORY
**Residual risk addressed:** On-chain sender/recipient linkability (HIGH, `doc/10-security.md` line 15)
**Depends on:** `doc/03-cryptography.md` (X25519, Ed25519, ML-KEM-768, HKDF, AES-256-GCM)
**Chain revision:** Included in V1 genesis. Stealth addresses are mandatory from launch.

---

## 1. Overview

Without stealth addresses, `sender_address` and `recipient_address` would be plaintext public key hashes visible to all full nodes. Any observer -- including archival adversaries -- can construct a complete communication graph within and across epochs.

This specification defines a Dual-Key Stealth Address Protocol (DKSAP) that eliminates on-chain sender/recipient linkability. Each transaction uses a fresh one-time address that only the intended recipient can identify and spend from, while the sender's identity is never revealed on-chain.

### 1.1 Design Goals

1. **Recipient unlinkability**: no PPT adversary can determine whether two stealth addresses belong to the same recipient without the recipient's scan key.
2. **Sender anonymity**: no return address or sender identifier appears on-chain.
3. **Post-quantum resistance**: hybrid DH + ML-KEM construction ensures unlinkability against quantum adversaries.
4. **Backward compatibility**: Forward-compatible design; stealth addresses are mandatory from V1 genesis.
5. **Compatibility with token economics**: fee payment, staking, and validator rewards all function through stealth addresses.

---

## 2. Key Architecture

### 2.1 Stealth Meta-Address

Each user publishes a **stealth meta-address** consisting of two independent key pairs:

```
StealthMetaAddress = (PK_scan, PK_spend)
```

| Key | Algorithm | Purpose | Lifetime |
|-----|-----------|---------|----------|
| sk_scan / PK_scan | X25519 | Scanning chain for incoming transactions | Rotatable |
| sk_spend / PK_spend | Ed25519 | Spending from stealth addresses | Permanent per identity |
| pk_scan_pq / sk_scan_pq | ML-KEM-768 | PQ-resistant scan key | Rotatable with sk_scan |

**Key generation:**

```
sk_scan   <- CSPRNG(32)                    -- X25519 scalar
PK_scan   = X25519(sk_scan, basepoint)
sk_spend  <- CSPRNG(32)                    -- Ed25519 seed
PK_spend  = Ed25519_pubkey(sk_spend)
(pk_scan_pq, sk_scan_pq) = ML-KEM-768.KeyGen()
```

The stealth meta-address is published in a `KEY_REGISTER` or `KEY_ROTATE` transaction alongside the existing Signal prekey bundle. The meta-address is NOT secret -- it is the public component that senders use to derive one-time stealth addresses.

### 2.2 Separation from Signal Identity Key

The scan key (sk_scan) is deliberately separate from the Signal identity key (IK). This provides:

- **Compromise isolation**: scan key compromise reveals which transactions belong to the recipient (privacy loss) but does not compromise Signal session keys or spending authority.
- **Delegation**: a user can share sk_scan with a lightweight scanning node without granting message decryption or spending capability.
- **Independent rotation**: scan keys can be rotated without disrupting active Signal sessions.

The spend key (sk_spend) is the user's Ed25519 identity key (IK) repurposed for the spending role. This avoids key proliferation while maintaining the property that only the holder of IK can authorize transactions.

### 2.3 On-Chain Meta-Address Format

Published in `KEY_REGISTER` (type 0x01) and `KEY_ROTATE` (type 0x03) transactions:

```
StealthMetaAddressRecord:
  version          : uint8    = 0x02          -- stealth address version
  pk_scan          : bytes32                  -- X25519 public key (32 bytes)
  pk_spend         : bytes32                  -- Ed25519 public key (32 bytes)
  pk_scan_pq       : bytes[1184]              -- ML-KEM-768 encapsulation key
  meta_addr_sig    : bytes64                  -- Ed25519 signature over (version || pk_scan || pk_scan_pq)
                                              -- signed by sk_spend, proving ownership
```

**Total size**: 1 + 32 + 32 + 1184 + 64 = 1,313 bytes.

The signature `meta_addr_sig` binds the scan keys to the spend key, preventing an adversary from substituting a scan key they control.

---

## 3. Stealth Address Construction

### 3.1 Classical (DLEQ-based) Stealth Address Derivation

When a sender wants to create a transaction for a recipient with meta-address `(PK_scan, PK_spend)`:

```
StealthDerive(PK_scan, PK_spend):
  1. r <- CSPRNG(32)                                -- ephemeral scalar
  2. R = X25519(r, basepoint)                       -- ephemeral public key
  3. S = X25519(r, PK_scan)                         -- shared secret (ECDH)
  4. view_tag = HKDF(salt=0x00*32, ikm=S,
                     info="UmbraVox_ViewTag_v2")[0]  -- 1 byte, for scan optimization
  5. s = HKDF(salt=0x00*32, ikm=S,
              info="UmbraVox_StealthKey_v1")         -- 32 bytes, stealth scalar
  6. PK_stealth = s * G_ed + PK_spend               -- Ed25519 point addition
  7. stealth_addr = SHA-256(0x02 || PK_stealth)[0:20]  -- 20-byte truncated hash
  8. return (stealth_addr, R, view_tag)
```

Where `G_ed` is the Ed25519 base point and `s * G_ed` denotes Ed25519 scalar-base multiplication. The point addition in step 6 is performed on the Ed25519 curve (twisted Edwards form).

**Notation clarification**: Step 3 uses X25519 (Montgomery ladder on Curve25519). Step 6 uses Ed25519 point arithmetic. The shared secret `S` from X25519 is converted to a scalar `s` via HKDF, then used in Ed25519 arithmetic. This is safe because the HKDF output is an independent pseudorandom scalar.

### 3.2 Transaction Output Format

```
StealthOutput:
  stealth_addr     : bytes20                  -- truncated hash of PK_stealth
  R                : bytes32                  -- sender's ephemeral public key
  view_tag         : uint8                    -- 1-byte prefix filter
  amount           : uint64                   -- token amount (or 0 for messages)
  payload          : bytes[]                  -- encrypted message blob (if MSG type)
  pq_ephemeral     : bytes[1088]              -- ML-KEM-768 ciphertext (see Section 5)
```

There is no persistent on-chain sender identifier. Sender addresses rotate per epoch or per message for unlinkability.

### 3.3 Recipient Scanning

The recipient scans each new block for transactions addressed to them:

```
StealthScan(sk_scan, PK_spend, block):
  for each tx in block.transactions:
    for each output in tx.outputs:
      1. S' = X25519(sk_scan, output.R)                -- recompute shared secret
      2. vt' = HKDF(salt=0x00*32, ikm=S',
                     info="UmbraVox_ViewTag_v2")[0]     -- recompute view tag
      3. if vt' != output.view_tag:
           continue                                     -- fast reject (255/256 filtered)
      4. s' = HKDF(salt=0x00*32, ikm=S',
                    info="UmbraVox_StealthKey_v1")       -- 32 bytes
      5. PK_stealth' = s' * G_ed + PK_spend             -- recompute expected stealth key
      6. addr' = SHA-256(0x02 || PK_stealth')[0:20]
      7. if addr' == output.stealth_addr:
           -- Match found. Compute spending key:
           sk_stealth = s' + sk_spend (mod L)            -- L = Ed25519 group order
           store (tx, output, sk_stealth)
```

**Correctness**: `PK_stealth = s * G_ed + PK_spend` and `sk_stealth = s + sk_spend (mod L)`, so `sk_stealth * G_ed = s * G_ed + sk_spend * G_ed = PK_stealth`. The recipient can sign with `sk_stealth`.

### 3.4 View Tag Optimization

The 1-byte view tag reduces scan work by 256x. For each output, the recipient performs one X25519 scalar multiplication (step 1) and one HKDF evaluation (step 2), then compares a single byte. Only 1/256 of outputs proceed to the full stealth key derivation (steps 4-7).

Without the view tag, every output requires a full scalar-base multiplication (step 5) and a SHA-256 hash (step 6). The view tag eliminates these for 255/256 of non-matching outputs.

---

## 4. Sender Privacy

### 4.1 No Return Address

Transactions contain no persistent sender identifier:

- The `sender_address` field from v1 is removed.
- The ephemeral key `R` is freshly generated per transaction and is not linked to any persistent identity.
- Authorization is proved by the UTXO spending signature (the sender signs the transaction with `sk_stealth` derived from a prior stealth output they received).

### 4.2 Reply Mechanism

Since there is no sender address on-chain, replies work via a separate stealth transaction:

1. Alice sends a message to Bob's stealth address. The encrypted payload within the Signal session includes Alice's stealth meta-address (inside the Double Ratchet encrypted channel, not on-chain).
2. Bob decrypts the message, obtains Alice's meta-address, and can send a reply to a fresh stealth address derived from Alice's meta-address.
3. The on-chain observer sees two independent stealth transactions with no visible link between them.

### 4.3 Transaction Authorization

A transaction spending from a stealth address is authorized by an Ed25519 signature from `sk_stealth` over the transaction body:

```
tx_sig = Ed25519_sign(sk_stealth, SHA-256(tx_body || epoch_nonce))
```

Validators verify against `PK_stealth` (which they can derive from `stealth_addr` only if the spender provides `PK_stealth` as a witness):

```
TransactionWitness:
  pk_stealth       : bytes32                  -- full Ed25519 public key
  tx_sig           : bytes64                  -- Ed25519 signature
```

Validators check: `SHA-256(0x02 || pk_stealth)[0:20] == stealth_addr` AND `Ed25519_verify(pk_stealth, tx_body || epoch_nonce, tx_sig)`.

---

## 5. Post-Quantum Stealth Addresses

### 5.1 Hybrid Construction

The classical ECDH stealth scheme (Section 3) is vulnerable to a quantum adversary who can solve the DLP on Curve25519. Such an adversary could recover `r` from `R = r * G` and recompute all stealth addresses, breaking unlinkability.

The hybrid scheme adds an ML-KEM-768 layer:

```
StealthDerive_PQ(PK_scan, PK_spend, pk_scan_pq):
  -- Classical component (same as Section 3.1, steps 1-3)
  1. r <- CSPRNG(32)
  2. R = X25519(r, basepoint)
  3. S_dh = X25519(r, PK_scan)

  -- Post-quantum component
  4. (pq_ct, S_pq) = ML-KEM-768.Encaps(pk_scan_pq)   -- 1088-byte ciphertext

  -- Combine
  5. S_combined = HKDF(salt=0x00*32,
                       ikm=0xFF*32 || S_dh || S_pq,
                       info="UmbraVox_StealthPQ_v2")    -- 32 bytes
  6. view_tag = HKDF(salt=0x00*32, ikm=S_combined,
                     info="UmbraVox_ViewTag_v2")[0]
  7. s = HKDF(salt=0x00*32, ikm=S_combined,
              info="UmbraVox_StealthKey_v1")             -- 32 bytes
  8. PK_stealth = s * G_ed + PK_spend
  9. stealth_addr = SHA-256(0x02 || PK_stealth)[0:20]
  10. return (stealth_addr, R, pq_ct, view_tag)
```

### 5.2 PQ Scanning

```
StealthScan_PQ(sk_scan, sk_scan_pq, PK_spend, block):
  for each tx in block.transactions:
    for each output in tx.outputs:
      1. S_dh' = X25519(sk_scan, output.R)
      2. S_pq' = ML-KEM-768.Decaps(sk_scan_pq, output.pq_ephemeral)
      3. S_combined' = HKDF(salt=0x00*32,
                            ikm=0xFF*32 || S_dh' || S_pq',
                            info="UmbraVox_StealthPQ_v2")
      4. vt' = HKDF(salt=0x00*32, ikm=S_combined',
                     info="UmbraVox_ViewTag_v2")[0]
      5. if vt' != output.view_tag:
           continue
      6. s' = HKDF(salt=0x00*32, ikm=S_combined',
                    info="UmbraVox_StealthKey_v1")
      7. PK_stealth' = s' * G_ed + PK_spend
      8. addr' = SHA-256(0x02 || PK_stealth')[0:20]
      9. if addr' == output.stealth_addr:
           sk_stealth = s' + sk_spend (mod L)
           store (tx, output, sk_stealth)
```

**Note**: The PQ scan is more expensive than classical scan because ML-KEM-768 decapsulation must be performed for every output BEFORE the view tag check. The view tag still filters out 255/256 of non-matching outputs before the expensive Ed25519 point arithmetic (step 7), but the ML-KEM decapsulation cost is unavoidable per-output. See Section 11 for performance analysis.

### 5.3 Hybrid Security Argument

The combined shared secret `S_combined` is derived from both `S_dh` and `S_pq` via HKDF with the `0xFF*32` domain separator (matching the PQXDH convention from `doc/03-cryptography.md`). By the HKDF extraction property:

- If CDH is hard: `S_dh` is indistinguishable from random, so `S_combined` is indistinguishable from random regardless of `S_pq`.
- If Module-LWE is hard: `S_pq` is indistinguishable from random, so `S_combined` is indistinguishable from random regardless of `S_dh`.

Unlinkability holds if EITHER assumption holds.

---

## 6. Integration with Signal Key Agreement (PQXDH)

### 6.1 Key Relationship

```
Signal keys:          IK (Ed25519), SPK (X25519), OPK (X25519), PQPK (ML-KEM-768)
Stealth keys:         sk_scan (X25519), PK_spend = IK (Ed25519), pk_scan_pq (ML-KEM-768)
```

The spend key IS the identity key. The scan key and Signal session keys are independent:

| Property | Signal IK | Stealth sk_scan | Stealth sk_spend |
|----------|-----------|-----------------|------------------|
| Session encryption | Yes (PQXDH DH1/DH2) | No | No |
| Transaction scanning | No | Yes | No |
| Transaction signing | No | No | Yes (= IK) |
| Compromise impact | Session keys exposed | Privacy loss (linkability) | Funds at risk |

### 6.2 Session Establishment with Stealth Addresses

The initial PQXDH handshake incorporates stealth addresses:

1. Alice fetches Bob's prekey bundle, which now includes `StealthMetaAddressRecord`.
2. Alice performs PQXDH as specified in `doc/03-cryptography.md` Section "Session Establishment".
3. Alice's initial message transaction uses a stealth address derived from Bob's meta-address.
4. Inside the encrypted Signal payload, Alice includes her own stealth meta-address for reply routing.

The `KEY_EXCHANGE` transaction (type 0x02) in v2 carries:

```
KEY_EXCHANGE (with stealth):
  stealth_addr     : bytes20     -- Bob's one-time stealth address
  R                : bytes32     -- ephemeral for stealth derivation
  pq_ephemeral     : bytes[1088] -- ML-KEM ciphertext for stealth
  view_tag         : uint8       -- stealth view tag
  ephemeral_key    : bytes32     -- Alice's X25519 ephemeral for PQXDH (EK_A)
  pq_ct_signal     : bytes[1088] -- ML-KEM ciphertext for PQXDH session
  encrypted_blob   : bytes[]     -- Signal-encrypted initial message
```

### 6.3 Prekey Bundle Update

The on-chain prekey bundle format is extended:

```
Prekey Bundle (with stealth meta-address):
  -- existing v1 fields --
  ik_pub           : bytes32
  spk_pub          : bytes32
  spk_sig          : bytes64
  opk_list         : [bytes32]     -- up to 100
  pqpk_pub         : bytes[1184]

  -- stealth extension --
  stealth_meta     : StealthMetaAddressRecord  -- 1,313 bytes
```

---

## 7. Integration with Token Economics

### 7.1 Fee Payment from Stealth Addresses

When spending from a stealth address, the transaction fee is paid from the stealth UTXO being consumed. The fee split (burn/producer/treasury/rebate per `doc/06-economics.md`) applies identically:

```
StealthTransaction:
  inputs:
    - stealth_addr   : bytes20       -- source stealth address
      pk_stealth     : bytes32       -- witness: full public key
      tx_sig         : bytes64       -- Ed25519 signature by sk_stealth
  outputs:
    - StealthOutput (recipient)      -- new stealth address for recipient
    - StealthOutput (change)         -- new stealth address for sender (self)
  fee:               uint64          -- deducted from input, split per economics
```

The change output uses a fresh stealth derivation back to the sender's own meta-address. This prevents linking the change output to the input.

### 7.2 Validator Rewards to Stealth Addresses

At cycle boundary, validator rewards are paid to stealth addresses:

1. The reward distribution algorithm computes each validator's reward amount per `doc/06-economics.md` Section "Reward Calculation".
2. For each validator, the protocol derives a fresh stealth address from the validator's published meta-address using a deterministic ephemeral scalar:

```
r_reward = HKDF(salt=0x00*32,
                ikm=epoch_nonce || validator_pk_scan || cycle_number,
                info="UmbraVox_RewardEphemeral_v2")
```

This is deterministic so all validators compute the same reward outputs (consensus requirement). The validator can scan and find their reward using `sk_scan` as normal.

3. The reward transaction output uses the standard `StealthOutput` format. The `R` value is `r_reward * basepoint`.

### 7.3 Staking from Stealth Addresses

Staking requires a persistent identity (validators are tracked by stake across cycles). The stake transaction links a stealth UTXO to a validator identity:

```
StakeTransaction:
  input:
    stealth_addr   : bytes20          -- stealth UTXO to stake
    pk_stealth     : bytes32          -- witness
    tx_sig         : bytes64
  stake_binding:
    validator_id   : bytes20          -- truncated hash of PK_spend
    stake_amount   : uint64
    sig_spend      : bytes64          -- Ed25519 signature by sk_spend (= IK)
                                      -- proves ownership of the validator identity
```

The `sig_spend` signature proves that the stealth address owner is the same entity as the validator, without revealing which stealth UTXOs the validator has received. The `validator_id` is a persistent public identifier derived from `PK_spend`.

**Privacy trade-off**: Staking necessarily links a stealth address to a validator identity. This is inherent -- validators must be publicly identifiable for consensus. The privacy benefit is that non-staking transactions (messages, token transfers) remain fully unlinkable.

### 7.4 Rebate Distribution

User rebates (per `doc/06-economics.md` Section "User Rebate") are paid to stealth addresses using the same deterministic ephemeral derivation as validator rewards (Section 7.2), substituting the user's `pk_scan` for the validator's.

### 7.5 Faucet Grants

Onboarding faucet grants (`doc/06-economics.md` Section "New User Onboarding") are paid to the new user's stealth address. Since the user has just registered their meta-address, the faucet operator derives a stealth address from it.

---

## 8. Formal Unlinkability Proof

### 8.1 Security Game

**Definition 8.1 (Stealth Address Unlinkability Game).**

```
Game SA-UNLINK:
  Setup:
    Challenger generates N user meta-addresses {(PK_scan_i, PK_spend_i)}_{i=1}^N.
    Adversary A receives all meta-addresses.

  Challenge:
    Challenger selects b <-$ {0,1} and two distinct users i0, i1.
    Challenger computes:
      (stealth_addr*, R*, view_tag*) = StealthDerive(PK_scan_{i_b}, PK_spend_{i_b})
    Sends (stealth_addr*, R*, view_tag*) to A.

  Queries:
    A may request:
      - StealthDerive(PK_scan_j, PK_spend_j) for any j  (sees derived addresses)
      - Corrupt(j) for any j not in {i0, i1}             (learns sk_scan_j)

  Output:
    A outputs b'. Wins if b' = b.

  Advantage:
    Adv^{SA-UNLINK}(A) = |Pr[b'=b] - 1/2|
```

### 8.2 Theorem

**Theorem 8.1 (Stealth Address Unlinkability).**

For any PPT adversary A playing Game SA-UNLINK:

```
Adv^{SA-UNLINK}(A) ≤ Adv^{DDH}_{X25519}(B_1) + Adv^{PRF}_{HKDF}(B_2)
```

In the hybrid (PQ) variant:

```
Adv^{SA-UNLINK-PQ}(A) ≤ Adv^{CCA}_{ML-KEM}(B_0) + Adv^{DDH}_{X25519}(B_1) + Adv^{PRF}_{HKDF}(B_2)
```

Moreover, unlinkability holds if EITHER DDH on Curve25519 OR Module-LWE holds.

### 8.3 Proof

**Game 0 (Real).** Execute StealthDerive as specified. The adversary receives `(stealth_addr*, R*, view_tag*)`.

**Game 1 (Replace shared secret).** Replace `S = X25519(r, PK_scan_{i_b})` with a uniformly random value `u <-$ {0,1}^{256}`.

*Transition:* The adversary sees `R = r * G` and knows `PK_scan_{i_b}`. Distinguishing `S = r * PK_scan_{i_b}` from random is exactly the DDH problem on Curve25519:

Given `(G, r*G, PK_scan_{i_b})`, distinguish `X25519(r, PK_scan_{i_b})` from random.

```
|Pr[A wins in G0] - Pr[A wins in G1]| <= Adv^{DDH}_{X25519}(B_1)
```

**Game 2 (Replace stealth scalar).** Replace `s = HKDF(salt, u, info)` and `view_tag = HKDF(salt, u, info')[0]` with uniformly random values.

*Transition:* In Game 1, the HKDF input `u` is uniform random. By the PRF property of HKDF:

```
|Pr[A wins in G1] - Pr[A wins in G2]| <= Adv^{PRF}_{HKDF}(B_2)
```

**Game 3 (Indistinguishability).** In Game 2:
- `s` is uniformly random in Z_L (integers mod the Ed25519 group order L).
- `PK_stealth = s * G_ed + PK_spend_{i_b}` where `s` is uniform random.
- Since `s` is uniform and independent of `b`, the point `s * G_ed` is a uniformly random group element.
- Therefore `PK_stealth` is uniformly random regardless of which `PK_spend_{i_b}` was used.
- `stealth_addr = SHA-256(0x02 || PK_stealth)[0:20]` is a deterministic function of a random input.
- `view_tag` is independently random (replaced in Game 2).
- `R = r * G` where `r` is independent of `b` (fresh per derivation).

The adversary's view is identically distributed for `b=0` and `b=1`. Therefore:

```
Adv(A in Game 3) = 0
```

Combining:

```
Adv^{SA-UNLINK}(A) <= Adv^{DDH}(B_1) + Adv^{PRF}_{HKDF}(B_2)
```

**Hybrid (PQ) extension:** In the PQ variant, the combined secret includes `S_pq` from ML-KEM. An additional game hop replaces `S_pq` with random, costing `Adv^{CCA}_{ML-KEM}(B_0)`. The remaining argument is identical. If DDH is broken (quantum adversary), the ML-KEM component alone ensures the combined secret is random. If Module-LWE is broken, the DDH component alone suffices. []

### 8.4 Scan Key Compromise

**Lemma 8.2.** Compromise of `sk_scan` breaks unlinkability but not unforgeability.

**Proof.** With `sk_scan`, the adversary can execute `StealthScan` and identify all transactions belonging to the victim. However, spending requires `sk_spend`, which is independent of `sk_scan`. The adversary cannot forge signatures under `sk_stealth = s + sk_spend (mod L)` because `sk_spend` remains secret and `s` is computable but does not help recover `sk_spend`. []

---

## 9. V1 Mandatory Deployment

Stealth addresses are mandatory from V1 launch. There is no migration from a non-stealth version.

- All transaction outputs use stealth addresses from genesis
- All users must publish a `StealthMetaAddressRecord` as part of identity registration
- No plaintext `sender_address` or `recipient_address` fields exist in V1 transactions
- The v1 format described in other documentation (cleartext addresses) represents the pre-launch design only and is never deployed on the live network

---

## 10. Edge Cases

### 10.1 Scan Key Compromise

**Impact**: Privacy loss (all past and future stealth transactions linkable to the victim) but NOT fund loss (sk_spend is independent and uncompromised).

**Detection**: The user cannot directly detect scan key compromise. External indicators include targeted phishing or social engineering that correlates with transaction timing.

**Response**:

1. User generates a new scan key pair: `sk_scan_new`, `PK_scan_new`, `pk_scan_pq_new`, `sk_scan_pq_new`.
2. User publishes a `KEY_ROTATE` transaction with the new `StealthMetaAddressRecord`, signed by `sk_spend`.
3. All future senders use the new `PK_scan_new`. Old stealth addresses remain spendable (sk_spend is unchanged).
4. The old `sk_scan` continues to identify old stealth outputs. The adversary can link old outputs but not new ones.
5. To break linkability of old outputs, the user can sweep all old stealth UTXOs to new stealth addresses derived from the new scan key (self-transfer).

### 10.2 Spend Key Compromise

**Impact**: Full fund loss. Adversary can spend from all stealth addresses (past and future).

**Response**: This is equivalent to identity key compromise. The user must:

1. Generate entirely new keys (new IK, new scan keys, new meta-address).
2. Publish a new `KEY_REGISTER` as a new identity.
3. Re-establish all Signal sessions.
4. Old stealth UTXOs are lost to the adversary.

### 10.3 Ephemeral Key Reuse

If the sender reuses the ephemeral scalar `r` for two different recipients, the two stealth addresses are linkable (same `R` on-chain). This is a sender-side privacy failure.

**Mitigation**: The CSPRNG specification (`doc/03-cryptography.md` Section "CSPRNG Specification") with ChaCha20-based generation and fork safety prevents scalar reuse under normal operation. Additionally, the implementation MUST check that `R` has not been used in any prior transaction by the sender (local duplicate check against the sender's transaction history).

### 10.4 Recipient Offline for Extended Period

If a recipient is offline, they accumulate unscanned blocks. Upon coming online, they must scan all missed blocks. With the view tag optimization, this is feasible but may be slow for long offline periods.

**Mitigation**: A lightweight scanning service can be deployed (trusted with `sk_scan` only). This service identifies matching outputs and notifies the user, who then uses `sk_spend` to access funds. The scanning service cannot spend or read message content.

### 10.5 ML-KEM Decapsulation Failure (PQ Stealth)

If ML-KEM-768 decapsulation fails during scanning (malformed `pq_ephemeral`):

1. The output is treated as non-matching (skipped).
2. A decapsulation failure event is logged locally.
3. If the failure is due to a malicious sender, the output is unrecoverable but represents an attack on the sender's own transaction (they wasted their fee).

### 10.6 View Tag Collision

A false-positive view tag match (probability 1/256 per non-matching output) triggers the full stealth key derivation (steps 4-7 in Section 3.3), which definitively resolves the match. View tag collisions have no security impact -- they only cause a small amount of wasted computation.

### 10.7 Stealth Address Collision

Two different stealth derivations producing the same 20-byte `stealth_addr` is a collision in a 160-bit hash space. Probability is negligible (~2^-160 per pair, birthday bound ~2^80). If a collision occurs, both recipients would compute different `PK_stealth` values and only one would match the on-chain address. The other recipient's scan would fail at step 7 (address comparison).

---

## 11. Performance Analysis

### 11.1 Per-Output Scan Cost

**Classical (DH-only) scan cost per output:**

| Operation | Cost | Performed when |
|-----------|------|----------------|
| X25519 scalar multiplication | ~150 us | Every output |
| HKDF (view tag) | ~2 us | Every output |
| View tag comparison | ~0.01 us | Every output |
| HKDF (stealth scalar) | ~2 us | 1/256 of outputs (view tag match) |
| Ed25519 scalar-base mult | ~60 us | 1/256 of outputs |
| SHA-256 (address) | ~1 us | 1/256 of outputs |

**Effective cost per output**: ~152 us (dominated by X25519).

**Hybrid (PQ) scan cost per output:**

| Operation | Cost | Performed when |
|-----------|------|----------------|
| X25519 scalar multiplication | ~150 us | Every output |
| ML-KEM-768 decapsulation | ~120 us | Every output |
| HKDF (combined secret) | ~3 us | Every output |
| HKDF (view tag) | ~2 us | Every output |
| View tag comparison | ~0.01 us | Every output |
| HKDF (stealth scalar) | ~2 us | 1/256 of outputs |
| Ed25519 scalar-base mult | ~60 us | 1/256 of outputs |
| SHA-256 (address) | ~1 us | 1/256 of outputs |

**Effective cost per output (PQ)**: ~275 us (X25519 + ML-KEM dominate).

### 11.2 Per-Block Scan Cost

Assuming 4,444 transactions per block (V1 block capacity), each with 1.5 outputs on average (6,666 outputs):

| Mode | Cost per block | Blocks per epoch (3,927 slots) | Cost per epoch |
|------|---------------|-------------------------------|----------------|
| Classical | 6,666 × 152 us = ~1.01s | ~785 (f=0.20 at 11s slots) | ~13.2 min |
| Hybrid PQ | 6,666 × 275 us = ~1.83s | ~785 | ~23.9 min |

These costs assume single-threaded scanning. With 4-core parallelism, epoch scan time reduces to ~3.3 min (classical) or ~6.0 min (PQ).

### 11.3 Memory Requirements

Per-output scan state:

```
Scanning context (persistent):
  sk_scan          : 32 bytes
  sk_scan_pq       : 2,400 bytes (ML-KEM-768 secret key)
  PK_spend         : 32 bytes
  Total            : ~2.5 KB

Per matched output (stored):
  stealth_addr     : 20 bytes
  sk_stealth       : 32 bytes
  tx_reference     : 32 bytes (tx hash)
  output_index     : 4 bytes
  Total            : 88 bytes per received transaction
```

For a user who receives 1,000 transactions per cycle: ~88 KB of stealth key storage.

### 11.4 Optimization Strategies

1. **Parallel scanning**: Outputs within a block are independent. Scan work is trivially parallelizable across CPU cores.

2. **Batched X25519**: Multiple scalar multiplications can be batched using Montgomery's trick for simultaneous inversion, reducing per-operation cost by ~20% for large batches.

3. **Scan checkpointing**: Store the last scanned block height. On restart, resume from checkpoint rather than re-scanning the full chain.

4. **Pruned scanning**: After cycle boundary (11-day truncation), old blocks are pruned. The scan window is bounded by the cycle length.

5. **Delegated scanning**: Users can delegate scanning to a semi-trusted node by sharing `sk_scan`. The delegate identifies matching outputs but cannot spend or decrypt messages. This enables mobile/lightweight clients.

6. **View tag extension**: If scan cost remains prohibitive, the view tag can be extended to 2 bytes (65,536x filtering) at the cost of 1 additional byte per output. This requires a chain revision.

---

## 12. Data Structures Summary

### 12.1 Wire Formats (CBOR)

All structures are CBOR-encoded per the existing transaction serialization convention.

```
-- Stealth meta-address (published on-chain)
StealthMetaAddressRecord = CBOR_MAP {
  0x01: uint8,          -- version (0x02)
  0x02: bytes(32),      -- pk_scan (X25519)
  0x03: bytes(32),      -- pk_spend (Ed25519)
  0x04: bytes(1184),    -- pk_scan_pq (ML-KEM-768 encapsulation key)
  0x05: bytes(64)       -- meta_addr_sig (Ed25519 by sk_spend)
}

-- Stealth transaction output
StealthOutput = CBOR_MAP {
  0x01: bytes(20),      -- stealth_addr
  0x02: bytes(32),      -- R (ephemeral public key)
  0x03: uint8,          -- view_tag
  0x04: uint64,         -- amount
  0x05: bytes(*),       -- payload (encrypted message, variable length)
  0x06: bytes(1088)     -- pq_ephemeral (ML-KEM-768 ciphertext)
}

-- Transaction witness (for spending)
TransactionWitness = CBOR_MAP {
  0x01: bytes(32),      -- pk_stealth (full Ed25519 public key)
  0x02: bytes(64)       -- tx_sig (Ed25519 signature)
}

-- Stake binding (links stealth to validator identity)
StakeBinding = CBOR_MAP {
  0x01: bytes(20),      -- validator_id (hash of PK_spend)
  0x02: uint64,         -- stake_amount
  0x03: bytes(64)       -- sig_spend (Ed25519 by sk_spend)
}
```

### 12.2 Transaction Types (V1)

| Type | Code | Description |
|------|------|-------------|
| MSG_V2 | 0x10 | Encrypted message to stealth address |
| KEY_REGISTER_V2 | 0x11 | Identity + prekey bundle + stealth meta-address |
| KEY_ROTATE_V2 | 0x13 | Prekey rotation + optional meta-address update |
| TRANSFER_V2 | 0x14 | Token transfer between stealth addresses |
| STAKE_V2 | 0x15 | Stake from stealth address |
| UNSTAKE_V2 | 0x16 | Unstake to stealth address |
| REWARD_V2 | 0x17 | Validator reward to stealth address (protocol-generated) |

These transaction types are the V1 format. The legacy type codes (0x00-0x04) described in pre-launch documentation are never deployed on the live network.

---

## 13. HKDF Domain Separation Summary

All HKDF invocations in this specification use SHA-512 and salt `0x00*32`, consistent with `doc/03-cryptography.md`. The `info` strings provide domain separation:

| Context | Info String | Output Length |
|---------|-------------|---------------|
| View tag derivation | `"UmbraVox_ViewTag_v2"` | 1 byte (first byte of 32) |
| Stealth scalar derivation | `"UmbraVox_StealthKey_v1"` | 32 bytes |
| PQ combined secret | `"UmbraVox_StealthPQ_v2"` | 32 bytes |
| Reward ephemeral derivation | `"UmbraVox_RewardEphemeral_v2"` | 32 bytes |

These are distinct from all existing HKDF info strings (`"UmbraVox_PQXDH_v1"`, `"UmbraVox_Ratchet_v1"`).

---

## 14. Test Requirements (DO-178C DAL A)

### 14.1 Correctness Tests

1. **Round-trip**: For 10,000 random meta-addresses, verify `StealthScan(StealthDerive(...))` recovers the correct `sk_stealth` and the derived `PK_stealth` matches.
2. **Spending**: For each round-trip, verify `Ed25519_verify(PK_stealth, msg, Ed25519_sign(sk_stealth, msg))` holds.
3. **PQ round-trip**: Same as (1) but using `StealthDerive_PQ` and `StealthScan_PQ`.
4. **View tag filtering**: Verify that non-matching outputs are rejected at view tag step with probability >= 255/256 over 100,000 random trials.

### 14.2 Unlinkability Tests

5. **Statistical unlinkability**: Generate 10,000 stealth addresses for the same recipient. Verify no statistical distinguisher (chi-squared test on address byte distribution) can distinguish them from 10,000 addresses for 10,000 different recipients, at significance level p < 0.01.
6. **Cross-output independence**: Verify that `R` values across outputs are statistically independent (no correlation in byte distribution).

### 14.3 Edge Case Tests

7. **Scan key rotation**: Verify that outputs derived before and after key rotation are both scannable with their respective scan keys.
8. **Ephemeral reuse detection**: Verify that the duplicate `R` check catches reuse.
9. **ML-KEM failure**: Verify graceful handling of malformed `pq_ephemeral`.
10. **Migration**: Verify Phase 1 dual-mode acceptance and Phase 2 v1 rejection.

### 14.4 Cross-Validation

11. **Haskell vs C**: All stealth address operations (derive, scan, sign, verify) cross-validated between pure Haskell and FFI C implementations with 10,000 random inputs each, per `doc/03-cryptography.md` Section "Equivalence Testing".

---

## 15. References

| Reference | Relevance |
|-----------|-----------|
| EIP-5564 (Stealth Addresses) | Ethereum stealth address standard; DKSAP basis |
| Ruffing, Moreno-Sanchez, Kate (2017) "CoinShuffle++" | Stealth address unlinkability analysis |
| Todd (2014) "Stealth Addresses" | Original stealth address proposal |
| FIPS 203 | ML-KEM-768 specification |
| RFC 7748 | X25519 specification |
| RFC 8032 | Ed25519 specification |
| Bindel et al. (2019) | Hybrid key exchange security model |
