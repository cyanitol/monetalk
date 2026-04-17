# Cryptographic Architecture

## Primitives (all hand-implemented, standard library only)

| Primitive | Standard | Purpose |
|-----------|----------|---------|
| SHA-256 | FIPS 180-4 | Block hashing, transaction IDs |
| SHA-512 | FIPS 180-4 | Ed25519 internals, HKDF |
| HMAC | RFC 2104 | Signal MAC, authentication |
| HKDF | RFC 5869 | Key derivation throughout |
| AES-256 | FIPS 197 | Symmetric encryption core |
| GCM mode | NIST SP 800-38D | AEAD for Signal + PQ wrapper |
| X25519 | RFC 7748 | Diffie-Hellman key exchange |
| Ed25519 (PureEd25519) | RFC 8032 Section 5.1 | Digital signatures, transaction signing |
| ML-KEM-768 | FIPS 203 | Post-quantum key encapsulation |
| ECVRF-ED25519-SHA512 | RFC 9381 | PoS slot leader election |
| ChaCha20 | RFC 8439 | CSPRNG stream cipher |

**Implementation priority**: SHA-256 -> HMAC -> HKDF -> AES-256-GCM -> X25519/Ed25519 -> ML-KEM -> VRF -> ChaCha20

### Ed25519 Variant

PureEd25519 per RFC 8032 Section 5.1. Messages are NOT pre-hashed before signing. This is the standard Ed25519 algorithm where the message is passed directly to the signing function (not the Ed25519ph pre-hash variant from Section 5.1.1). All transaction signatures and SPK signatures use PureEd25519.

### HKDF Parameters

All HKDF invocations use SHA-512 as the underlying hash and the following parameters:

| Context | Salt | Info String |
|---------|------|-------------|
| PQXDH master secret derivation | 32 zero bytes (0x00 * 32) | `"UmbraVox_PQXDH_v1"` |
| Double Ratchet chain key derivation | 32 zero bytes (0x00 * 32) | `"UmbraVox_Ratchet_v1"` |

The domain separator `0xFF * 32` (32 bytes of 0xFF) is prepended to the DH concatenation before HKDF input, per Signal spec convention. This ensures domain separation between the PQXDH KDF input and other protocol uses of HKDF.

Full PQXDH derivation: `HKDF(salt=0x00*32, ikm=0xFF*32 || dh1 || dh2 || dh3 || dh4 || pq_ss, info="UmbraVox_PQXDH_v1")`

### CSPRNG Specification

ChaCha20-based CSPRNG for all key generation and nonce generation:

- **Seed source**: `/dev/urandom`, 256 bits, read at node startup
- **Reseed interval**: every 2^20 (1,048,576) outputs, reseeded from `/dev/urandom`
- **Fork safety**: PID check on each call. If PID differs from the PID recorded at last seed/reseed, the CSPRNG is immediately reseeded before producing output. This prevents child processes from sharing CSPRNG state after `fork()`

## Side-Channel Mitigation Strategy

Pure Haskell implementations are NOT constant-time. GHC's runtime introduces timing variability through lazy evaluation (thunk forcing is data-dependent), garbage collector pauses, and branch prediction artifacts. This is an acknowledged and unavoidable property of the platform.

### Dual-Output Code Generation

The TQL-1 qualified code generator produces two outputs from the same FIPS/RFC specification:

1. **Pure Haskell reference implementation** -- used for correctness verification and cross-validation. This code is human-readable, structurally mirrors the spec, and runs entirely within base/standard libraries (no external dependencies). It is NOT suitable for production use where timing attacks are a concern.

2. **FFI binding stubs to constant-time C implementations** -- used for production deployment. The C code uses fixed-time comparisons, constant-time conditional selects, and avoids secret-dependent branching. The FFI layer is minimal: marshal `ByteString` to/from C `uint8_t*` buffers.

Both outputs are generated from the same specification source, ensuring structural correspondence.

### Equivalence Testing

For every crypto primitive, equivalence between the two paths is verified:

- 10,000+ random inputs per primitive, generated from a deterministic CSPRNG seed for reproducibility
- For each input: compute result via pure Haskell path AND via FFI path, assert bitwise equality
- Covers all edge cases (zero inputs, max-length inputs, boundary values) in addition to random inputs

### Deployment Model

- **Production nodes**: use the FFI path exclusively for all secret-key operations
- **Test and verification**: use the pure Haskell path for property-based testing, formal reasoning, and cross-validation against FFI output
- This satisfies the "no external libraries" constraint for verification while achieving constant-time guarantees for production

## Signal Protocol

### Key Types

| Key | Algorithm | Lifetime |
|-----|-----------|----------|
| Identity Key (IK) | Ed25519/X25519 dual-use | Permanent per user |
| Signed PreKey (SPK) | X25519 | Rotated every ~48 hours |
| One-Time PreKey (OPK) | X25519 | Single use, consumed on first contact |
| PQ PreKey (PQPK) | ML-KEM-768 | Single use, consumed on first contact |

### OPK Management and Exhaustion Handling

- **Initial bundle**: 100 OPKs published in the KEY_REGISTER transaction
- **Replenishment threshold**: when fewer than 20 OPKs remain (tracked by on-chain key registry), the node publishes a KEY_REPLENISH transaction containing 50 new OPKs
- **Exhaustion fallback**: if all OPKs are exhausted before replenishment, session establishment falls back to X3DH without an OPK. The `dh4` term is omitted from the HKDF input. This reduces forward secrecy for the first message only: if Bob's SPK is later compromised, that single session's initial message can be decrypted. All subsequent messages remain protected by the Double Ratchet. This is a documented and accepted tradeoff, consistent with the Signal specification's handling of OPK exhaustion.

### Session Establishment (PQXDH)

Hybrid classical + post-quantum key agreement:

```
Alice -> Bob (first message):
  1. Fetch Bob's prekey bundle from on-chain key registry
  2. Verify SPK signature (Ed25519)
  3. Generate ephemeral X25519 keypair
  4. Compute 4 DH shared secrets:
     dh1 = X25519(Alice_IK, Bob_SPK)
     dh2 = X25519(Alice_EK, Bob_IK)
     dh3 = X25519(Alice_EK, Bob_SPK)
     dh4 = X25519(Alice_EK, Bob_OPK)  -- if available, omitted if OPKs exhausted
  5. ML-KEM encapsulate against Bob's PQPK -> (pq_ct, pq_ss)
  6. Master secret = HKDF(salt=0x00*32, ikm=0xFF*32 || dh1 || dh2 || dh3 || [dh4] || pq_ss, info="UmbraVox_PQXDH_v1")
  7. Initialize Double Ratchet with master secret
  8. Encrypt message, include ephemeral key + pq_ct in header
```

### ML-KEM Decapsulation Failure Handling

If ML-KEM-768 decapsulation returns an error (malformed ciphertext, decapsulation check failure):

1. The session falls back to a **classical-only Signal ratchet** using only the DH-derived secrets (`dh1 || dh2 || dh3 || [dh4]`). The `pq_ss` term is omitted from HKDF input.
2. A **security downgrade event** is logged with: timestamp, peer identity key fingerprint, session ID, and failure reason.
3. The node sends a **RATCHET_REFRESH** message to the peer, requesting re-establishment of the PQ layer with a fresh ML-KEM encapsulation.
4. Until the PQ layer is re-established, the session operates without post-quantum protection. This is functionally equivalent to standard Signal without the PQ extension.

### Double Ratchet State

```haskell
data RatchetState = RatchetState
  { rsDHSend      :: !(X25519SecretKey, X25519PublicKey)
  , rsDHRecv      :: !X25519PublicKey
  , rsRootKey     :: !ByteString        -- 32 bytes
  , rsSendChain   :: !ByteString        -- 32 bytes
  , rsRecvChain   :: !ByteString        -- 32 bytes
  , rsSendN       :: !Word32
  , rsRecvN       :: !Word32
  , rsPrevChainN  :: !Word32
  , rsSkippedKeys :: !(Map (X25519PublicKey, Word32) ByteString)
  }
```

### Skipped Key Storage Limits

Out-of-order message delivery requires storing skipped message keys. To prevent memory exhaustion from adversarial gap injection:

- **Maximum skipped keys per session**: 1,000
- **Eviction policy**: keys older than 500 ratchet steps from the current ratchet counter are evicted
- **Memory bound**: at most ~64 KB per session (1,000 keys * 32-byte X25519 public key + 4-byte counter + 32-byte message key)
- **Overflow behavior**: if a message would require storing more than 1,000 skipped keys, the message is dropped and the sender is expected to retransmit (the ratchet state is not advanced past the gap)

This prevents OOM attacks where an adversary injects messages with large sequence number gaps to force unbounded key storage.

### OTR Deniability

Signal's X3DH already provides deniable authentication via DH-only key agreement (no signatures on message content). MACs use symmetric keys derivable by either party. The Ed25519 blockchain signature covers only the encrypted blob, not plaintext. A separate OTR layer is unnecessary.

## Post-Quantum Outer Wrapper

Sits OUTSIDE Signal. Independent key exchange using ML-KEM-768.

- **Initial PQ key**: Derived during PQXDH session setup (the `pq_ss` serves double duty)
- **PQ ratchet**: Every 50 messages **per direction** (not bidirectional total), perform a fresh ML-KEM encapsulation to introduce new quantum-resistant entropy. The counter is per-direction monotonic: Alice's send counter and Bob's send counter are tracked independently. If the 50th message is lost, the ratchet refresh occurs on the next successful message exchange in that direction.
- **Per-message encryption**: AES-256-GCM with key derived from PQ chain via HKDF
- **Overhead**: 28 bytes per message (12-byte nonce + 16-byte GCM tag). PQ ratchet messages add ~2,276 bytes (ML-KEM ciphertext + new encapsulation key)
- **Deniability preserved**: Only symmetric crypto (AES-GCM), no PQ signatures on content

## PQ Ciphertext Transmission

ML-KEM-768 ciphertexts (~1,088 bytes) exceed the single-block payload limit and require multi-block transmission. The overhead depends on message type:

### KEY_EXCHANGE messages (0x02)

Full ML-KEM ciphertext transmitted as a two-block message:

- **Block 0**: message header (226 bytes) + first 782 bytes of PQ ciphertext + 16 bytes padding
- **Block 1**: remaining 306 bytes of PQ ciphertext + padding to block boundary

This occurs once per session establishment.

### Normal messages

Only 28 bytes of overhead per message:

- 12-byte nonce
- 16-byte GCM authentication tag

The PQ ciphertext is NOT repeated on normal messages. The shared secret derived during key exchange (or the most recent ratchet refresh) is already incorporated into the key schedule.

### RATCHET_REFRESH messages (0x04)

A fresh ML-KEM encapsulation is performed approximately every 50 messages (per direction) to inject new quantum-resistant entropy. The fresh ciphertext is transmitted using two 1,024-byte blocks (same structure, different header size):

- **Block 0**: ratchet refresh header + first 802 bytes of new PQ ciphertext
- **Block 1**: remaining 286 bytes + padding

## Block Hash Specification

`bhBodyHash` is computed as the SHA-256 Merkle root of transaction hashes in canonical order:

- **Canonical order**: transactions are sorted by transaction hash ascending (lexicographic byte comparison)
- **Tree structure**: binary balanced Merkle tree
- **Odd leaf handling**: if a level has an odd number of nodes, the last (unpaired) leaf is promoted to the next level without hashing
- **Leaf nodes**: `SHA-256(tx_hash)` for each transaction
- **Internal nodes**: `SHA-256(left_child || right_child)`
- **Empty block**: `bhBodyHash = SHA-256("")` (hash of empty input)

## Security Model

PQXDH provides IND-CCA2 security under the **hybrid assumption**: security holds if EITHER the classical DH problem (Computational Diffie-Hellman on Curve25519) OR the ML-KEM problem (Module-LWE) is hard. This is the standard hybrid argument as described by Bindel et al. (2019).

This is NOT a novel construction. UmbraVox follows Signal's PQXDH specification exactly, combining classical X3DH with ML-KEM-768 key encapsulation. The security reduction is:

- If an adversary breaks the combined scheme, they must break BOTH the CDH assumption on Curve25519 AND the Module-LWE assumption underlying ML-KEM-768
- Compromise of the classical layer alone (e.g., by a quantum computer solving CDH) does not break confidentiality because the ML-KEM shared secret remains secure
- Compromise of the PQ layer alone (e.g., by a cryptanalytic advance against ML-KEM) does not break confidentiality because the classical DH shared secrets remain secure

The Double Ratchet provides forward secrecy and post-compromise security on top of the initial PQXDH key agreement. The PQ outer wrapper's periodic ratchet refresh (every 50 messages per direction) restores post-quantum forward secrecy even if a prior PQ ratchet state was compromised.

## Formal Composition Proof Requirement (DO-178C DAL A)

The composition of Signal Double Ratchet with ML-KEM-768 outer wrapper introduces a non-trivial security argument. The two layers share entropy through the PQXDH derivation and periodic PQ ratchet refreshes. Formal analysis is required to ensure that the composition does not weaken either layer.

### Requirements

- The composition security of Signal Double Ratchet + ML-KEM-768 outer wrapper must be formally analyzed
- A TLA+ or Coq model must prove that compromise of either layer alone does not break confidentiality of the combined construction
- The HKDF composition `HKDF(salt=0x00*32, ikm=0xFF*32 || dh1 || dh2 || dh3 || dh4 || pq_ss, info="UmbraVox_PQXDH_v1")` must be proven secure under the standard model, specifically that the output is indistinguishable from random when at least one of the DH or PQ inputs is uncompromised
- The proof must cover the ratchet refresh cycle: fresh ML-KEM encapsulation every ~50 messages must restore forward secrecy even if the classical DH ratchet state was previously compromised

### Deliverable

Formal proof artifact location: `test/evidence/crypto-composition-proof/`

The artifact must include the model source (TLA+ or Coq), all assumptions stated explicitly, and a machine-checkable proof that the stated security properties hold.

## MC/DC Test Requirements

Every cryptographic primitive must achieve 100% MC/DC (Modified Condition/Decision Coverage) structural coverage, consistent with DO-178C DAL A objectives.

### NIST Known Answer Tests

All NIST KAT (Known Answer Test) vectors for each primitive are embedded as individual test cases. Each KAT vector constitutes a separate test case with an explicit expected output comparison.

### Round-Trip Properties

For all encryption primitives, the round-trip property must hold:

```
decrypt(encrypt(m, k), k) == m    for all valid m, k
```

This is verified via property-based testing with at minimum 10,000 random (m, k) pairs per primitive.

### Algebraic Invariants

All finite field operations (used in X25519, Ed25519, ML-KEM) must satisfy:

- **Closure**: result of every operation is within the field
- **Associativity**: `(a * b) * c == a * (b * c)` for all a, b, c
- **Identity**: `a * 1 == a` and `a + 0 == a` for all a
- **Inverse**: `a * a^(-1) == 1` for all nonzero a

### Edge Cases

Every primitive must be tested with:

- Zero key (all 0x00 bytes)
- Max key (all 0xFF bytes)
- All-ones input
- Empty input (where the primitive permits zero-length input)
- Minimum and maximum length inputs

### Cross-Validation

Pure Haskell reference implementation vs FFI production implementation:

- 10,000+ random inputs per primitive
- Deterministic CSPRNG seed for reproducibility
- Bitwise equality of outputs required
- Covers both the happy path and all edge cases listed above

## On-Chain Key Registry

Prekey bundles are published as special blockchain transactions:

```
Transaction types:
  MSG           -- encrypted chat message
  KEY_REGISTER  -- initial identity + prekey bundle (100 OPKs)
  KEY_ROTATE    -- signed prekey rotation
  KEY_REPLENISH -- one-time prekey batch refill (50 OPKs, triggered when <20 remain)
```

At 11-day truncation, the key registry state is carried forward in the epoch genesis block (deterministic snapshot).

## Standard References

| Standard | Title |
|----------|-------|
| FIPS 203 | ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) |
| FIPS 180-4 | Secure Hash Standard (SHA-2 family) |
| FIPS 197 | Advanced Encryption Standard (AES) |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| RFC 7748 | Elliptic Curves for Security (X25519) |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (Ed25519) |
| RFC 8439 | ChaCha20 and Poly1305 for IETF Protocols |
| NIST SP 800-38D | Recommendation for Block Cipher Modes of Operation: GCM |
| NIST SP 800-57 | Recommendation for Key Management |
