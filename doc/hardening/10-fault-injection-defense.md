# Hardening-10: Fault Injection Defense

**Scope:** Defense against active fault injection attacks (voltage glitching,
laser fault injection, EM pulses, rowhammer) that target cryptographic
operations to extract key material.

**Threat model:** An adversary who can induce single-bit or multi-bit faults
at precise moments during cryptographic computations.  The attacker may
observe faulty outputs and correlate them with correct outputs to recover
secret keys (differential fault analysis).

**Applies to:** All 11 cryptographic primitives listed in `doc/03-cryptography.md`.

**References:**
- Boneh, DeMillo, Lipton (1997) — Bellcore attack on RSA-CRT
- Piret & Quisquater (2003) — DFA on AES
- Ambrose et al. (2007) — fault attacks on EdDSA
- `doc/proof-07-cryptanalysis-resistance.md` §7.2

---

## 1. Sign-then-Verify Pattern (Ed25519)

### Threat

A single-bit fault during Ed25519 scalar multiplication can produce a
signature (R', S') where R' lies on a different curve or subgroup.  Given
one correct and one faulty signature on the same message, the adversary can
solve for the private scalar via:

```
a = (S - S') · (H(R,A,M) - H(R',A,M))^{-1}  mod L
```

### Countermeasure

Every Ed25519 signing operation MUST verify its own output before releasing
the signature to any caller or network buffer.

```
function ed25519_sign_hardened(sk, pk, msg):
    // First computation
    sig = ed25519_sign(sk, msg)

    // Verify before release
    valid = ed25519_verify(pk, msg, sig)

    if not valid:
        // Fault detected — wipe and abort
        secure_wipe(sk)
        secure_wipe(sig)
        panic("FAULT DETECTED: Ed25519 sign-then-verify failed")

    return sig
```

### Cost

One additional Ed25519 verification per signature (~2x signing cost).
Ed25519 verification is cheaper than signing (no secret scalar multiply),
so the overhead is approximately 1.5x total.

### Failure mode

If the fault also corrupts the verification, a bad signature could be
released.  This is addressed by the double computation countermeasure in §4.

---

## 2. Encrypt-then-Authenticate Check (AES-256-GCM)

### Threat

A fault during AES-256-GCM decryption (specifically, during the penultimate
AES round) can produce a faulty plaintext.  If the caller processes this
faulty plaintext, Piret & Quisquater (2003) show that two faulty ciphertexts
suffice to recover the full AES-256 key.

A fault during GCM tag computation can cause a forged message to be accepted,
enabling chosen-ciphertext attacks.

### Countermeasure

The GCM authentication tag MUST be verified BEFORE any plaintext is returned
to the caller.  Tag comparison MUST be timing-safe (constant-time).

```
function aes_gcm_decrypt_hardened(key, nonce, ciphertext, aad, tag):
    // Step 1: Decrypt to obtain candidate plaintext
    candidate_plaintext = aes_gcm_decrypt_raw(key, nonce, ciphertext, aad)

    // Step 2: Recompute authentication tag
    expected_tag = ghash_compute(key, nonce, ciphertext, aad)

    // Step 3: Constant-time tag comparison
    //   XOR all bytes, OR into accumulator — no early exit
    diff = 0x00
    for i in 0..15:
        diff = diff | (tag[i] ^ expected_tag[i])

    if diff != 0x00:
        // Authentication failure — wipe candidate plaintext
        secure_wipe(candidate_plaintext)
        secure_wipe(expected_tag)
        // Return generic error — no detail about which byte differed
        return Error("decryption failed")

    return candidate_plaintext
```

### Critical requirements

1. **No partial plaintext release.**  The candidate plaintext buffer MUST NOT
   be accessible to any caller until the tag is verified.  In Haskell/FFI,
   this means the C decryption function returns the plaintext only after
   internal tag verification succeeds.

2. **Timing-safe comparison.**  The `diff` accumulator ensures all 16 bytes
   are compared regardless of where a mismatch occurs.  No early return.

3. **Error indistinguishability.**  The caller receives a single error type
   for all failure modes (wrong key, corrupted ciphertext, corrupted tag,
   truncated input).  See §6.

---

## 3. ML-KEM Implicit Rejection

### Threat

If ML-KEM decapsulation returns a distinguishable error on malformed
ciphertexts, an adversary can mount a chosen-ciphertext attack to recover
the decapsulation key (analogous to Bleichenbacher's attack on PKCS#1 v1.5).

### Countermeasure (FIPS 203 compliance)

ML-KEM's Fujisaki-Okamoto (FO) transform mandates **implicit rejection**:
on decapsulation failure, the output is `H(z || c)` where `z` is a secret
random seed stored with the private key and `c` is the ciphertext.  This
output is indistinguishable from a valid shared secret.

Both the success and failure paths MUST execute identical code, differing
only in the value selected via constant-time conditional move.

```
function mlkem_decapsulate_hardened(dk, ct):
    // dk contains (sk, pk, h_pk, z) where z is 32-byte implicit rejection seed

    // Step 1: Decapsulate to obtain candidate shared secret
    m_prime = mlkem_decrypt(dk.sk, ct)

    // Step 2: Re-encapsulate to verify
    (ct_prime, K_success) = mlkem_encapsulate_deterministic(dk.pk, m_prime)

    // Step 3: Compute rejection key (always computed, regardless of match)
    K_reject = sha3_256(dk.z || ct)

    // Step 4: Constant-time comparison of ct vs ct_prime
    ct_match = constant_time_bytes_eq(ct, ct_prime)
    //   ct_match is 0xFF..FF if equal, 0x00..00 if not

    // Step 5: Constant-time select — no branch
    //   If match: K = K_success
    //   If no match: K = K_reject
    K = constant_time_select(ct_match, K_success, K_reject)

    // Step 6: Wipe intermediates
    secure_wipe(m_prime)
    secure_wipe(ct_prime)
    secure_wipe(K_success)
    secure_wipe(K_reject)

    return K
```

### Timing equivalence verification

Both paths (success and failure) MUST execute the same instruction sequence.
Verification approach:

```
function verify_mlkem_timing_equivalence():
    (dk, ek) = mlkem_keygen()

    // Valid ciphertext
    (ct_valid, _) = mlkem_encapsulate(ek)

    // Invalid ciphertext (random bytes, same length)
    ct_invalid = random_bytes(len(ct_valid))

    // Time both paths over 10,000 iterations
    times_valid   = [time(mlkem_decapsulate_hardened(dk, ct_valid))   for _ in 1..10000]
    times_invalid = [time(mlkem_decapsulate_hardened(dk, ct_invalid)) for _ in 1..10000]

    // Welch's t-test: p > 0.05 required (no statistically significant difference)
    t, p = welch_t_test(times_valid, times_invalid)
    assert p > 0.05, "ML-KEM timing leak detected"
```

---

## 4. Double Computation

### Threat

A single transient fault (voltage glitch, cosmic ray, EM pulse) during key
generation or signing can corrupt the output without corrupting the
verification logic.  If the fault is not reproduced on a second computation,
comparing the two outputs detects it.

### Countermeasure

For critical operations (key generation, signing, key derivation), compute
the result twice using independent code paths or diversified inputs, and
compare before using.

```
function ed25519_sign_double(sk, pk, msg):
    // Computation 1
    sig1 = ed25519_sign(sk, msg)

    // Memory barrier — prevent compiler/CPU from reusing computation 1
    memory_barrier()

    // Computation 2
    sig2 = ed25519_sign(sk, msg)

    // Compare both signatures (must be identical for deterministic signing)
    match = constant_time_bytes_eq(sig1, sig2)

    if not match:
        secure_wipe(sk)
        secure_wipe(sig1)
        secure_wipe(sig2)
        panic("FAULT DETECTED: double computation mismatch in Ed25519 sign")

    // Additionally verify (sign-then-verify from §1)
    valid = ed25519_verify(pk, msg, sig1)
    if not valid:
        secure_wipe(sk)
        secure_wipe(sig1)
        panic("FAULT DETECTED: Ed25519 sign-then-verify failed")

    secure_wipe(sig2)
    return sig1


function keygen_double(algorithm):
    // algorithm is one of: x25519, ed25519, mlkem768

    // Computation 1
    entropy = csprng_read(required_entropy_bytes(algorithm))
    (sk1, pk1) = algorithm.keygen(entropy)

    // Computation 2 (same entropy, re-derived)
    (sk2, pk2) = algorithm.keygen(entropy)

    // Compare
    sk_match = constant_time_bytes_eq(sk1, sk2)
    pk_match = constant_time_bytes_eq(pk1, pk2)

    if not (sk_match and pk_match):
        secure_wipe(entropy)
        secure_wipe(sk1)
        secure_wipe(sk2)
        panic("FAULT DETECTED: double computation mismatch in keygen")

    secure_wipe(entropy)
    secure_wipe(sk2)
    secure_wipe(pk2)
    return (sk1, pk1)


function hkdf_derive_double(salt, ikm, info, length):
    // Computation 1
    out1 = hkdf(salt, ikm, info, length)

    memory_barrier()

    // Computation 2
    out2 = hkdf(salt, ikm, info, length)

    match = constant_time_bytes_eq(out1, out2)

    if not match:
        secure_wipe(out1)
        secure_wipe(out2)
        secure_wipe(ikm)
        panic("FAULT DETECTED: double computation mismatch in HKDF")

    secure_wipe(out2)
    return out1
```

### Cost

2x computation for each protected operation.  For UmbraVox's workload profile:

| Operation | Frequency | Overhead |
|-----------|-----------|----------|
| Ed25519 sign | Per transaction (~1/sec) | +1 sign + 1 verify |
| Key generation | Per session setup (rare) | +1 keygen |
| HKDF derive | Per ratchet step (~1/msg) | +1 HKDF |
| AES-GCM encrypt | Per message | Not doubled (GCM tag provides integrity) |

AES-GCM encryption is NOT doubled because the GCM authentication tag serves
as an integrity check on the ciphertext.  A faulted encryption produces a
ciphertext whose tag will not verify on the recipient's end.

---

## 5. Instruction Skip Detection

### Threat

On embedded or hardware targets, an attacker can use voltage glitching or
laser injection to skip individual instructions.  Critical scenarios:

- Skipping the comparison instruction in sign-then-verify (§1)
- Skipping the branch instruction after MAC verification (§2)
- Skipping the conditional select in ML-KEM implicit rejection (§3)
- Skipping the key wipe instruction after use

### Countermeasure

Insert cryptographic checksums (MACs) on intermediate state at critical
control flow points.  An instruction skip will cause a checksum mismatch
at the next verification point.

```
function instrumented_sign(sk, pk, msg):
    // Derive a per-invocation canary key from the CSPRNG
    canary_key = csprng_read(32)

    // Checkpoint 0: before signing
    state_0 = hmac_sha256(canary_key, "checkpoint_0" || sk || msg)

    sig = ed25519_sign(sk, msg)

    // Checkpoint 1: after signing, before verify
    //   state_1 depends on state_0 — a skipped sign would produce wrong sig
    state_1 = hmac_sha256(canary_key, "checkpoint_1" || state_0 || sig)

    valid = ed25519_verify(pk, msg, sig)

    // Checkpoint 2: after verify
    //   Encode the verification result into the checkpoint
    valid_byte = if valid then 0x01 else 0x00
    state_2 = hmac_sha256(canary_key, "checkpoint_2" || state_1 || valid_byte)

    // Verify checkpoint chain
    //   Recompute expected state_2 from state_1 assuming valid_byte == 0x01
    expected_state_2 = hmac_sha256(canary_key, "checkpoint_2" || state_1 || 0x01)

    chain_ok = constant_time_bytes_eq(state_2, expected_state_2)

    if not chain_ok:
        secure_wipe(sk)
        secure_wipe(sig)
        secure_wipe(canary_key)
        panic("FAULT DETECTED: instruction skip in signing pipeline")

    secure_wipe(canary_key)
    secure_wipe(state_0)
    secure_wipe(state_1)
    secure_wipe(state_2)
    return sig


function instrumented_decrypt(key, nonce, ct, aad, tag):
    canary_key = csprng_read(32)

    // Checkpoint 0: inputs bound
    state_0 = hmac_sha256(canary_key, "decrypt_cp0" || key || nonce || ct)

    plaintext = aes_gcm_decrypt_raw(key, nonce, ct, aad)

    // Checkpoint 1: decryption complete
    state_1 = hmac_sha256(canary_key, "decrypt_cp1" || state_0 || plaintext)

    expected_tag = ghash_compute(key, nonce, ct, aad)
    tag_ok_byte = constant_time_bytes_eq_to_byte(tag, expected_tag)

    // Checkpoint 2: tag verified
    state_2 = hmac_sha256(canary_key, "decrypt_cp2" || state_1 || tag_ok_byte)

    // Verify the chain expects tag_ok_byte == 0xFF (match)
    expected_state_2 = hmac_sha256(canary_key, "decrypt_cp2" || state_1 || 0xFF)

    chain_ok = constant_time_bytes_eq(state_2, expected_state_2)

    if not chain_ok:
        secure_wipe(plaintext)
        secure_wipe(key)
        secure_wipe(canary_key)
        return Error("decryption failed")

    secure_wipe(canary_key)
    return plaintext
```

### Why HMAC and not a simple counter

A simple counter or flag variable (`verified = true`) can be set by a single
instruction skip or a single-bit fault.  An HMAC checkpoint requires the
attacker to produce a valid MAC over the correct intermediate state, which
requires knowing the canary key — a fresh 256-bit random value.

---

## 6. Error Code Handling

### Threat

Returning different error codes for different cryptographic failure modes
enables oracle attacks:

- **Padding oracle (Vaudenay 2002):** Distinguishing "invalid padding" from
  "invalid MAC" in CBC mode allows byte-by-byte plaintext recovery.
- **Bleichenbacher (1998):** Distinguishing "valid PKCS#1 padding" from
  "invalid padding" in RSA allows decryption via ~1 million queries.
- **GCM tag vs. format errors:** Distinguishing "tag mismatch" from
  "malformed nonce" reveals information about the key.

### Countermeasure

All cryptographic operations MUST return exactly one of two outcomes:
**success** or **generic failure**.  No additional diagnostic information
is encoded in the error type, error code, error message, log output, or
timing.

```
// CORRECT — single error type
data CryptoResult a
    = CryptoSuccess a
    | CryptoFailure     -- no payload, no reason code, no message

// WRONG — leaks oracle information
data CryptoResult a
    = CryptoSuccess a
    | InvalidTag        -- attacker learns tag didn't match
    | InvalidNonce      -- attacker learns nonce was malformed
    | InvalidCiphertext -- attacker learns ciphertext was malformed
    | DecapsulationFail -- attacker learns ML-KEM rejected
```

### Implementation rules

1. **No error detail in return values.**  `CryptoFailure` carries no payload.

2. **No differential logging.**  Crypto failures are logged as
   `"crypto operation failed"` with a session ID and timestamp.  The log
   MUST NOT contain which check failed, what the expected value was, or
   any partial computation result.

3. **No differential timing.**  All failure paths must take the same time
   as the success path.  For AES-GCM decryption, compute the plaintext
   unconditionally, then wipe it if the tag fails.  Do not short-circuit.

4. **No differential exceptions.**  In Haskell, all crypto failures are
   returned via `Either CryptoFailure a`, never thrown as exceptions
   (exception types carry stack traces that may leak information).

```
function unified_error_decrypt(key, nonce, ct, aad, tag):
    // Always compute plaintext (no short-circuit)
    plaintext = aes_gcm_decrypt_raw(key, nonce, ct, aad)

    // Always compute tag
    expected_tag = ghash_compute(key, nonce, ct, aad)

    // Always compare
    tag_ok = constant_time_bytes_eq(tag, expected_tag)

    // Always perform the conditional wipe (wipe if bad, no-op if good)
    conditional_wipe(plaintext, not tag_ok)

    // Return result — same structure either way
    if tag_ok:
        return CryptoSuccess(plaintext)
    else:
        return CryptoFailure
```

---

## 7. Control Flow Integrity

### Threat

An attacker who can manipulate the program counter (via fault injection,
ROP gadgets, or corrupted return addresses) can:

- Jump past the verification check in sign-then-verify
- Jump past the tag comparison in GCM decryption
- Jump past key wipe operations
- Jump directly to the "return success" instruction

### Countermeasure

Crypto functions use a **guard variable pattern** where the return value
is only computed/released if a chain of guard values matches expected
constants.

```
GUARD_SIGNED    = 0xA5A5A5A5_DEADBEEF
GUARD_VERIFIED  = 0x5A5A5A5A_CAFEBABE
GUARD_RELEASED  = 0xC3C3C3C3_F00DCAFE

function cfi_protected_sign(sk, pk, msg):
    guard = 0x0000000000000000

    // Phase 1: Sign
    sig = ed25519_sign(sk, msg)
    guard = guard ^ GUARD_SIGNED      // guard = 0xA5A5A5A5_DEADBEEF

    // Phase 2: Verify
    valid = ed25519_verify(pk, msg, sig)
    if valid:
        guard = guard ^ GUARD_VERIFIED  // guard = 0xFFFFFFFF_15457555
    else:
        secure_wipe(sk)
        secure_wipe(sig)
        panic("verification failed")

    // Phase 3: Release gate
    expected_guard = GUARD_SIGNED ^ GUARD_VERIFIED  // 0xFFFFFFFF_15457555
    guard_ok = constant_time_u64_eq(guard, expected_guard)

    if not guard_ok:
        secure_wipe(sk)
        secure_wipe(sig)
        panic("FAULT DETECTED: control flow integrity violation")

    guard = guard ^ GUARD_RELEASED
    return sig


function cfi_protected_decrypt(key, nonce, ct, aad, tag):
    guard = 0x0000000000000000

    // Phase 1: Decrypt
    plaintext = aes_gcm_decrypt_raw(key, nonce, ct, aad)
    guard = guard ^ GUARD_SIGNED        // reuse constant: marks "decrypted"

    // Phase 2: Authenticate
    expected_tag = ghash_compute(key, nonce, ct, aad)
    tag_ok = constant_time_bytes_eq(tag, expected_tag)
    if tag_ok:
        guard = guard ^ GUARD_VERIFIED
    else:
        secure_wipe(plaintext)
        guard = 0x0000000000000000       // force guard mismatch
        // Fall through to guard check — do not return early

    // Phase 3: Release gate
    expected_guard = GUARD_SIGNED ^ GUARD_VERIFIED
    guard_ok = constant_time_u64_eq(guard, expected_guard)

    if not guard_ok:
        secure_wipe(plaintext)
        return CryptoFailure

    return CryptoSuccess(plaintext)
```

### Why constants matter

The guard constants are chosen to have high Hamming distance from each other
and from zero.  A single-bit fault cannot transform one guard value into
another.  The XOR chain ensures that skipping any phase produces a guard
value that does not match the expected final value.

| Guard | Hamming distance from 0 | Hamming distance from others |
|-------|------------------------|------------------------------|
| `GUARD_SIGNED` (0xA5A5A5A5DEADBEEF) | 40 | ≥20 from VERIFIED |
| `GUARD_VERIFIED` (0x5A5A5A5ACABEBABE) | 38 | ≥20 from SIGNED |
| `GUARD_RELEASED` (0xC3C3C3C3F00DCAFE) | 38 | ≥20 from both |

---

## 8. Redundant Conditional Checks

### Threat

A single-bit fault on the flag register or the branch instruction can flip
a "signature invalid" result to "signature valid" (or vice versa).

### Countermeasure

All critical security checks are performed twice using diversified
computation, meaning the two checks use different intermediate
representations so a single fault cannot corrupt both.

```
function redundant_signature_check(pk, msg, sig):
    // Check 1: Standard verification
    result_1 = ed25519_verify(pk, msg, sig)

    // Check 2: Recompute R from the signature equation
    //   S*B = R + H(R,A,M)*A
    //   Verify by computing S*B - H(R,A,M)*A and comparing to R
    R = sig[0..31]
    S = sig[32..63]
    h = sha512(R || pk || msg) mod L
    lhs = ed25519_scalarmult_base(S)
    rhs = ed25519_point_add(R, ed25519_scalarmult(pk_point, h))
    result_2 = constant_time_bytes_eq(
        ed25519_point_encode(lhs),
        ed25519_point_encode(rhs)
    )

    // Both must agree
    if result_1 and result_2:
        return true
    else:
        return false


function redundant_mac_check(key, data, received_mac):
    // Check 1: Compute and compare
    computed_mac_1 = hmac_sha256(key, data)
    ok_1 = constant_time_bytes_eq(computed_mac_1, received_mac)

    // Check 2: Compute again with byte-reversed intermediate
    //   (different register/memory layout, same mathematical result)
    computed_mac_2 = hmac_sha256(key, data)
    ok_2 = constant_time_bytes_eq(computed_mac_2, received_mac)

    // Check 3: Compare the two computed MACs against each other
    ok_3 = constant_time_bytes_eq(computed_mac_1, computed_mac_2)

    // All three must hold
    ok = ok_1 and ok_2 and ok_3

    secure_wipe(computed_mac_1)
    secure_wipe(computed_mac_2)
    return ok


function redundant_nonce_freshness(nonce_counter, last_seen):
    // Check 1: Standard comparison
    fresh_1 = (nonce_counter > last_seen)

    // Check 2: Diversified — subtract and check sign bit
    diff = nonce_counter - last_seen
    fresh_2 = (diff > 0) and (diff < 2^31)   // overflow guard

    // Check 3: Bitwise — ensure nonce_counter != last_seen
    fresh_3 = not constant_time_u64_eq(nonce_counter, last_seen)

    // All three must agree on "fresh"
    return fresh_1 and fresh_2 and fresh_3
```

---

## 9. Per-Primitive Fault Model

For each of the 11 primitives in `doc/03-cryptography.md`, the following
table identifies what a single-bit fault at each stage could leak and the
specific countermeasure applied.

### 9.1 SHA-256

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Round function (Ch, Maj, Σ) | Corrupted hash output; if used as commitment, can break binding | Double computation (§4): hash twice, compare |
| Message schedule (W[t]) | Incorrect expansion → wrong hash; no key leak (no secret input in block hashing) | Double computation for Merkle root validation |
| Final addition (H+a, H+b, ...) | Wrong hash; detected by double computation | Double computation |

```
function sha256_hardened(input):
    h1 = sha256(input)
    memory_barrier()
    h2 = sha256(input)
    if not constant_time_bytes_eq(h1, h2):
        panic("FAULT DETECTED: SHA-256 mismatch")
    return h1
```

**Secret key exposure risk:** None directly (SHA-256 processes public data
in block hashing).  When used inside HMAC with a secret key, the HMAC
double computation covers this case.

### 9.2 SHA-512

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Round function | Corrupted hash; when used in Ed25519 nonce generation, can produce biased nonce → private key recovery via lattice attack | Double computation of nonce: `r = SHA-512(sk_prefix \|\| msg)` computed twice |
| Message schedule | Same as SHA-256 | Double computation |

```
function ed25519_nonce_hardened(sk_prefix, msg):
    r1 = sha512(sk_prefix || msg)
    memory_barrier()
    r2 = sha512(sk_prefix || msg)
    if not constant_time_bytes_eq(r1, r2):
        secure_wipe(sk_prefix)
        panic("FAULT DETECTED: Ed25519 nonce computation mismatch")
    return r1 mod L
```

**Critical:** A faulted nonce in Ed25519 is catastrophic.  Two signatures
with related nonces allow private key extraction (see
`doc/proof-07-cryptanalysis-resistance.md` §2.2).  Double computation of
the nonce is mandatory.

### 9.3 HMAC

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Inner hash | Wrong MAC → authentication bypass if attacker controls the fault | Double computation + redundant check (§8) |
| Outer hash | Wrong MAC → same risk | Double computation |
| Key XOR (ipad/opad) | Modified effective key → MAC computed under wrong key; detected by double computation | Double computation |

```
function hmac_sha256_hardened(key, data):
    mac1 = hmac_sha256(key, data)
    memory_barrier()
    mac2 = hmac_sha256(key, data)
    if not constant_time_bytes_eq(mac1, mac2):
        secure_wipe(key)
        panic("FAULT DETECTED: HMAC mismatch")
    secure_wipe(mac2)
    return mac1
```

### 9.4 HKDF

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Extract phase (HMAC) | Wrong PRK → all derived keys compromised for this session | Double computation (§4: `hkdf_derive_double`) |
| Expand phase (HMAC iterations) | Wrong output key material → session keys incorrect; detected by protocol failure or double computation | Double computation |

**Secret key exposure risk:** A faulted HKDF during PQXDH derivation
produces wrong session keys.  No direct key leak, but the session may
use predictable keys if the fault zeroes the PRK.  Double computation
prevents this.

### 9.5 AES-256

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| SubBytes (round 13, penultimate) | Piret-Quisquater DFA: 2 faulted ciphertexts → full key recovery | GCM tag check (§2) rejects faulted ciphertext; sign-then-verify on encryption side via tag recomputation |
| MixColumns | Partial key byte recovery with ~40 faults | GCM tag + double computation on encryption |
| Key schedule | Wrong round key → all subsequent rounds use wrong keys; full key recoverable with DFA | Double computation of key schedule at setup |
| AddRoundKey (final round) | Direct XOR with round key; single fault reveals key bytes | GCM tag catches faulted output |

```
function aes256_gcm_encrypt_hardened(key, nonce, plaintext, aad):
    // Encrypt
    (ct1, tag1) = aes256_gcm_encrypt(key, nonce, plaintext, aad)

    // Verify by decrypting and comparing
    pt_check = aes256_gcm_decrypt_raw(key, nonce, ct1, aad)
    tag_check = ghash_compute(key, nonce, ct1, aad)

    pt_ok = constant_time_bytes_eq(plaintext, pt_check)
    tag_ok = constant_time_bytes_eq(tag1, tag_check)

    if not (pt_ok and tag_ok):
        secure_wipe(ct1)
        secure_wipe(tag1)
        secure_wipe(pt_check)
        panic("FAULT DETECTED: AES-GCM encrypt verification failed")

    secure_wipe(pt_check)
    return (ct1, tag1)
```

### 9.6 GCM Mode (GHASH)

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| GHASH multiply (GF(2^128)) | Wrong authentication tag → forgery acceptance | Double computation of GHASH; redundant tag check (§8) |
| H computation (AES(K,0)) | Wrong hash key → all tags for this key are wrong; no direct key leak but authentication is broken | Verify H at key setup: `H = AES(K, 0); H' = AES(K, 0); assert H == H'` |
| Counter increment (CTR) | Nonce reuse → GHASH key H recovery (catastrophic, see `doc/proof-07-cryptanalysis-resistance.md` §2.4) | Double computation of counter; nonce derived from ratchet counter, verified monotonic (§8) |

### 9.7 X25519

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Montgomery ladder (conditional swap) | If swap is skipped, scalar bits leak through output | Double computation: compute DH twice, compare |
| Field multiply (mod p) | Wrong shared secret; if on twist, may leak scalar bits via invalid-curve attack | Verify result is on curve (X25519 handles this via clamping + twist security); double computation |
| Final clamping | Unclamped scalar → small-subgroup attack information | Double computation of clamped scalar; verify clamping bits after setting them |

```
function x25519_hardened(scalar, point):
    result1 = x25519(scalar, point)
    memory_barrier()
    result2 = x25519(scalar, point)

    if not constant_time_bytes_eq(result1, result2):
        secure_wipe(scalar)
        panic("FAULT DETECTED: X25519 mismatch")

    // Check for all-zero result (low-order point)
    if constant_time_is_zero(result1):
        secure_wipe(scalar)
        panic("X25519: low-order point detected")

    secure_wipe(result2)
    return result1
```

### 9.8 Ed25519

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Nonce generation (SHA-512) | Biased or repeated nonce → full private key recovery (lattice attack) | Double computation of nonce (§9.2); deterministic nonce prevents reuse |
| Scalar multiplication (nonce * B) | Wrong R → faulty signature; if released, combined with valid signature leaks sk | Sign-then-verify (§1) |
| Hash-to-scalar (SHA-512(R\|\|A\|\|M)) | Wrong challenge → faulty S value; combined with correct S leaks sk | Sign-then-verify (§1) + double computation (§4) |
| Final S computation (r + h*a mod L) | Direct private key involvement; fault here → S leaks a | Sign-then-verify catches invalid S |

**Ed25519 is the highest-risk primitive for fault injection** because the
private scalar `a` directly participates in the output `S = r + h*a mod L`.

### 9.9 ML-KEM-768

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| NTT (Number Theoretic Transform) | Wrong polynomial multiplication → decapsulation produces wrong shared secret | Implicit rejection (§3): wrong output is H(z\|\|c), indistinguishable from valid |
| Noise sampling | Biased noise → lattice dimension effectively reduced; key recovery easier | Double computation of noise sampling at keygen |
| Decapsulation re-encryption check | If the comparison is skipped, a chosen-ciphertext attack succeeds | Implicit rejection makes comparison result irrelevant to output format; redundant check (§8) |
| Compression/decompression | Rounding errors amplified by fault → information leak about secret polynomial | Implicit rejection covers this |

```
function mlkem_keygen_hardened():
    seed = csprng_read(64)  // d || z per FIPS 203

    (dk1, ek1) = mlkem_keygen(seed)
    memory_barrier()
    (dk2, ek2) = mlkem_keygen(seed)

    dk_ok = constant_time_bytes_eq(dk1, dk2)
    ek_ok = constant_time_bytes_eq(ek1, ek2)

    if not (dk_ok and ek_ok):
        secure_wipe(seed)
        secure_wipe(dk1)
        secure_wipe(dk2)
        panic("FAULT DETECTED: ML-KEM keygen mismatch")

    // Encaps/decaps round-trip check
    (ct, ss_enc) = mlkem_encapsulate(ek1)
    ss_dec = mlkem_decapsulate_hardened(dk1, ct)  // uses §3 implicit rejection

    if not constant_time_bytes_eq(ss_enc, ss_dec):
        secure_wipe(dk1)
        secure_wipe(seed)
        panic("FAULT DETECTED: ML-KEM round-trip failed")

    secure_wipe(seed)
    secure_wipe(dk2)
    secure_wipe(ek2)
    secure_wipe(ct)
    secure_wipe(ss_enc)
    secure_wipe(ss_dec)
    return (dk1, ek1)
```

### 9.10 ECVRF-ED25519-SHA512

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Hash-to-curve (ECVRF_encode_to_curve) | Wrong curve point H → VRF output is invalid; if accepted, leader election is manipulable | VRF proof verification after computation (analogous to sign-then-verify) |
| Scalar multiplication (sk * H) | Wrong Gamma → faulty VRF output; combined with correct output leaks sk | Double computation + verify proof |
| Proof generation (DLEQ proof) | Faulty proof leaks relationship between sk and Gamma | Verify proof after generation |

```
function ecvrf_prove_hardened(sk, pk, alpha):
    // Double computation
    (pi1, beta1) = ecvrf_prove(sk, alpha)
    memory_barrier()
    (pi2, beta2) = ecvrf_prove(sk, alpha)

    if not constant_time_bytes_eq(pi1, pi2):
        secure_wipe(sk)
        panic("FAULT DETECTED: VRF prove mismatch")

    // Verify the proof
    (valid, beta_check) = ecvrf_verify(pk, alpha, pi1)

    if not valid:
        secure_wipe(sk)
        panic("FAULT DETECTED: VRF prove-then-verify failed")

    if not constant_time_bytes_eq(beta1, beta_check):
        secure_wipe(sk)
        panic("FAULT DETECTED: VRF beta mismatch")

    secure_wipe(pi2)
    secure_wipe(beta2)
    return (pi1, beta1)
```

### 9.11 ChaCha20

| Fault Location | What Leaks | Countermeasure |
|----------------|------------|----------------|
| Quarter-round (ARX operations) | Wrong keystream → CSPRNG output is biased or predictable | Double computation: generate keystream twice, compare before using as random output |
| Counter increment | Counter stuck → keystream repetition → XOR of two plaintexts | Double computation of counter; verify monotonicity |
| Key/nonce setup | Wrong key loaded → output is deterministic function of wrong key; if key is all-zero, output is public | Verify key is non-zero after setup; double computation |

```
function csprng_generate_hardened(state, num_bytes):
    // Generate twice from the same state
    (output1, state_next1) = chacha20_generate(state, num_bytes)
    (output2, state_next2) = chacha20_generate(state, num_bytes)

    if not constant_time_bytes_eq(output1, output2):
        secure_wipe(state)
        panic("FAULT DETECTED: CSPRNG output mismatch")

    if not constant_time_bytes_eq(state_next1, state_next2):
        secure_wipe(state)
        panic("FAULT DETECTED: CSPRNG state advance mismatch")

    secure_wipe(output2)
    secure_wipe(state_next2)
    return (output1, state_next1)
```

### Summary: Per-Primitive Defense Matrix

| # | Primitive | Primary Risk | Primary Defense | Secondary Defense |
|---|-----------|-------------|-----------------|-------------------|
| 1 | SHA-256 | Hash collision (commitment break) | Double computation | — |
| 2 | SHA-512 | Ed25519 nonce bias → key recovery | Double computation of nonce | Sign-then-verify |
| 3 | HMAC | Auth bypass | Double computation | Redundant check |
| 4 | HKDF | Wrong session keys | Double computation | Protocol failure detection |
| 5 | AES-256 | DFA key recovery (Piret-Quisquater) | GCM tag verification | Double computation on encrypt |
| 6 | GCM | Forgery acceptance | Double GHASH | Redundant tag check |
| 7 | X25519 | Scalar bit leak via invalid curve | Double computation | Low-order point check |
| 8 | Ed25519 | **Full private key recovery** | Sign-then-verify | Double computation + nonce double-check |
| 9 | ML-KEM-768 | CCA key recovery | Implicit rejection | Double keygen + round-trip test |
| 10 | ECVRF | Leader election manipulation + key leak | Prove-then-verify | Double computation |
| 11 | ChaCha20 | Predictable CSPRNG output | Double computation | Reseed verification |

---

## 10. Testing: Fault Injection Simulation

### 10.1 Fault Injection Framework

A test harness that systematically introduces single-bit faults at every
stage of every cryptographic operation and verifies that:

1. No key material is leaked (the operation aborts or returns generic error).
2. No invalid output is accepted as valid.
3. All wipe operations execute (key material is zeroed).

```
function fault_injection_test_suite():
    results = []

    for primitive in ALL_PRIMITIVES:
        for operation in primitive.operations:    // e.g., sign, verify, encrypt, decrypt
            for fault_point in operation.fault_points:
                for bit_position in 0..max_state_bits:
                    result = run_single_fault_test(
                        primitive, operation, fault_point, bit_position
                    )
                    results.append(result)

    assert all(r.safe for r in results), "Fault injection safety violation"
    return results


function run_single_fault_test(primitive, operation, fault_point, bit_position):
    // Step 1: Generate valid inputs
    (sk, pk, input_data) = generate_test_vectors(primitive)

    // Step 2: Set up fault injection hook
    //   The hook flips bit `bit_position` at `fault_point` during execution
    install_fault_hook(operation, fault_point, bit_position)

    // Step 3: Execute the hardened operation
    try:
        output = operation.hardened_variant(sk, pk, input_data)

        // If we get here, the operation succeeded despite the fault
        // Verify the output is CORRECT (not faulted)
        reference_output = operation.reference_variant(sk, pk, input_data)

        if output != reference_output:
            return TestResult(
                safe = false,
                reason = "Faulted output accepted as valid"
            )

        // Output matched reference — the fault had no effect (acceptable)
        return TestResult(safe = true, reason = "Fault had no observable effect")

    catch FaultDetected:
        // Hardened operation detected the fault and aborted — correct behavior
        // Verify key material was wiped
        sk_wiped = verify_memory_zeroed(sk.memory_region)

        if not sk_wiped:
            return TestResult(
                safe = false,
                reason = "Fault detected but key material not wiped"
            )

        return TestResult(safe = true, reason = "Fault detected, keys wiped, operation aborted")

    catch e:
        // Unexpected exception — may leak information via exception type
        return TestResult(
            safe = false,
            reason = "Unexpected exception: " + type(e)
        )

    finally:
        remove_fault_hook()
        secure_wipe(sk)
```

### 10.2 Fault Point Enumeration

For each primitive, the test framework enumerates fault injection points
at the granularity of individual operations within the algorithm:

| Primitive | Fault Points |
|-----------|-------------|
| SHA-256 | Each of 64 rounds: Ch, Maj, Σ0, Σ1, message schedule W[t], working variables a-h |
| SHA-512 | Each of 80 rounds: same as SHA-256 |
| HMAC | Inner hash input, inner hash output, outer hash input, outer hash output, ipad XOR, opad XOR |
| HKDF | Extract HMAC call, each Expand HMAC iteration |
| AES-256 | Each of 14 rounds: SubBytes (each of 16 bytes), ShiftRows, MixColumns, AddRoundKey; key schedule |
| GCM | GHASH multiply (each of 128 bit positions), counter increment, final XOR |
| X25519 | Each of 255 ladder steps: conditional swap, point add, point double, field multiply, field reduce |
| Ed25519 | Nonce hash, scalar multiply (each of 253 doublings), hash-to-scalar, final S computation |
| ML-KEM-768 | NTT (each butterfly), noise sampling (each coefficient), compress, decompress, re-encrypt compare |
| ECVRF | Hash-to-curve, scalar multiply, DLEQ nonce, DLEQ challenge, DLEQ response |
| ChaCha20 | Each of 20 rounds: each of 4 quarter-rounds; counter increment; key/nonce load |

### 10.3 Statistical Verification

After running the full fault injection suite, compute aggregate statistics:

```
function fault_injection_report(results):
    total_tests    = len(results)
    faults_caught  = count(r for r in results if r.reason contains "detected")
    faults_benign  = count(r for r in results if r.reason contains "no observable")
    faults_leaked  = count(r for r in results if not r.safe)
    keys_not_wiped = count(r for r in results if r.reason contains "not wiped")

    // Required pass criteria
    assert faults_leaked   == 0, "CRITICAL: fault injection leaked key material"
    assert keys_not_wiped  == 0, "CRITICAL: key material not wiped after fault"

    // Detection rate (informational — benign faults are acceptable)
    detection_rate = faults_caught / (faults_caught + faults_benign)

    print("Total fault tests:     ", total_tests)
    print("Faults detected:       ", faults_caught)
    print("Benign faults:         ", faults_benign)
    print("Key material leaked:   ", faults_leaked)
    print("Keys not wiped:        ", keys_not_wiped)
    print("Detection rate:        ", detection_rate)
```

### 10.4 Multi-Bit Fault Testing

While single-bit faults are the primary model, the test suite also runs
a reduced set of multi-bit fault tests:

```
function multi_bit_fault_test(primitive, operation, num_bits):
    // For each operation, test 1000 random multi-bit faults
    for trial in 1..1000:
        fault_bits = random_select(num_bits, range(0, max_state_bits))
        fault_point = random_select(1, operation.fault_points)

        install_multi_fault_hook(operation, fault_point, fault_bits)

        result = run_single_fault_test(primitive, operation, fault_point, fault_bits[0])
        assert result.safe, "Multi-bit fault safety violation"

        remove_fault_hook()
```

Multi-bit faults with 2, 4, and 8 simultaneous bit flips are tested.
The expected detection rate decreases with more bits (an adversary with
multi-bit fault capability can potentially bypass some countermeasures),
but the primary invariant — no key material leaked — must still hold.

### 10.5 Continuous Integration

The fault injection test suite runs as part of the CI pipeline:

- **On every commit:** 1000 randomly selected fault tests (fast, ~30 seconds)
- **Nightly:** Full single-bit fault enumeration for Ed25519, ML-KEM, and
  AES-256 (the three highest-risk primitives)
- **Weekly:** Complete fault enumeration for all 11 primitives, including
  multi-bit faults

Test evidence is stored in `test/evidence/fault-injection/` with
timestamped results and the CSPRNG seed used for reproducibility.

---

## Appendix A: Secure Wipe Specification

All `secure_wipe` calls in this document MUST:

1. Write zeros to every byte of the target buffer.
2. Use a memory barrier or volatile write to prevent the compiler from
   optimizing away the wipe.
3. Verify that the wipe succeeded by reading back and checking for zero.

```
function secure_wipe(buffer):
    // Write zeros
    for i in 0..len(buffer)-1:
        volatile_write(buffer[i], 0x00)

    // Memory barrier — prevent reordering past this point
    memory_barrier()

    // Verify (read back through volatile to prevent optimization)
    for i in 0..len(buffer)-1:
        if volatile_read(buffer[i]) != 0x00:
            panic("CRITICAL: secure_wipe verification failed")
```

In the FFI C implementation, use `explicit_bzero()` (POSIX) or
`SecureZeroMemory()` (Windows), both of which are guaranteed not to be
optimized away.

---

## Appendix B: Interaction with Side-Channel Mitigations

Fault injection defenses and side-channel mitigations are complementary but
can conflict:

| Concern | Resolution |
|---------|------------|
| Double computation doubles timing side-channel surface | Both computations use the same constant-time code path; no additional timing information is leaked |
| Guard variable comparisons must be constant-time | All guard comparisons use `constant_time_u64_eq`, never short-circuit `==` |
| HMAC checkpoints add operations with secret key | Canary key is ephemeral (per-invocation), not derived from long-term secrets; compromise of canary reveals nothing about cryptographic keys |
| Error uniformity (§6) vs. fault detection panics | Panics are internal abort, not returned to network peers; the peer sees a connection drop, not a differentiated error code |

---

## Appendix C: Deployment Tiers

Not all deployments face the same fault injection risk.  The countermeasures
in this document are tiered:

| Tier | Environment | Required Countermeasures |
|------|-------------|------------------------|
| **T1** | Software on general-purpose OS | §1 (sign-then-verify), §2 (GCM tag check), §3 (implicit rejection), §6 (error codes) |
| **T2** | High-value server / validator node | T1 + §4 (double computation), §7 (CFI), §8 (redundant checks) |
| **T3** | Embedded / hardware / HSM | T2 + §5 (instruction skip detection), full §9 per-primitive hardening |

All tiers require §10 (testing) at the appropriate level.
