# Hardening Spec 01: Constant-Time Implementation

**DO-178C DAL A Requirement:** REQ-SIDE-CHANNEL-001
**Source:** `doc/03-cryptography.md` (side-channel mitigation strategy), `doc/10-security.md` (threat matrix row "Crypto timing side-channels"), `doc/proof-07-cryptanalysis-resistance.md` Section 3
**Scope:** All 11 cryptographic primitives listed in `doc/03-cryptography.md` lines 5--18

---

## 0. Definitions

**Constant-time:** An implementation is constant-time if its execution trace (instruction sequence, memory access pattern, and branch targets) is independent of secret inputs. Formally: for all pairs of secret inputs s1, s2, the observable hardware events (instruction pointer sequence, data cache line accesses, branch predictor state) are identical.

**Secret data:** Any value whose disclosure to an adversary would violate a security property. This includes private keys, shared secrets, nonces derived from private keys, plaintext, HMAC keys, ratchet chain keys, VRF secret scalars, ML-KEM secret vectors, and AES round keys.

**Public data:** Ciphertext, public keys, nonces, message lengths, protocol headers, authentication tags (after computation).

---

## 1. Inventory of Secret-Dependent Operations

Every function that touches secret data is listed below. Each entry specifies the primitive, the operation, the secret input, and the timing risk.

### 1.1 SHA-256 / SHA-512

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Compression function (64/80 rounds) | HMAC key material via inner/outer pad; Ed25519 nonce derivation input `sk_prefix \|\| m` | Sigma/Ch/Maj functions use bitwise ops only -- no risk if implemented with fixed-width integer arithmetic. Risk arises only if the message length is secret (it is not in UmbraVox). |
| Padding | Message length | Length is public in all UmbraVox usages. No risk. |

### 1.2 HMAC-SHA-512

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Inner hash: `SHA-512((k XOR ipad) \|\| m)` | Key k (32 bytes) | Key XOR is constant-time on fixed-width words. No risk from the XOR itself. Risk inherited from SHA-512 internals. |
| Outer hash: `SHA-512((k XOR opad) \|\| inner_hash)` | Key k | Same as above. |
| Comparison of computed MAC vs received MAC | Both MACs | **HIGH RISK.** Early-exit `==` leaks the position of the first differing byte. Must use constant-time comparison. |

### 1.3 HKDF (Extract + Expand)

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Extract: `HMAC(salt, IKM)` | IKM (DH outputs, ML-KEM shared secret) | Inherited from HMAC. |
| Expand: `HMAC(PRK, info \|\| counter)` | PRK (pseudo-random key) | Inherited from HMAC. |

### 1.4 AES-256

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| SubBytes (S-box) | State bytes (derived from plaintext XOR round key) | **CRITICAL.** Table-lookup S-box is cache-timing vulnerable. Each lookup address depends on secret state bytes, leaking via Flush+Reload or Prime+Probe. |
| ShiftRows | State | No risk (fixed permutation independent of values). |
| MixColumns | State | No risk if implemented with XOR and xtime() using constant-time conditional masking (not branches). |
| AddRoundKey | Round key | No risk (XOR only). |
| Key schedule | Cipher key | S-box lookups in key schedule share the same vulnerability as SubBytes. |

### 1.5 AES-256-GCM (GHASH + CTR)

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| GHASH polynomial multiply in GF(2^128) | Hash subkey H = AES(k, 0^128) | **HIGH RISK.** Schoolbook multiply with conditional reduction leaks bits of H via timing. Variable-time multiply on operand weight is exploitable. |
| CTR keystream generation | Counter block (public), but AES key is secret | Inherited from AES-256. |
| Tag comparison on decryption | Computed tag vs received tag | **HIGH RISK.** Must use constant-time comparison. |

### 1.6 X25519

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Scalar multiplication (Montgomery ladder) | 255-bit scalar (private key) | **HIGH RISK** if implemented with branching double-and-add. Montgomery ladder is inherently constant-time if conditional swap is implemented correctly. |
| Field arithmetic: multiply, square, reduce mod p = 2^255 - 19 | Intermediate field elements derived from secret scalar | **RISK** if using variable-time multiplication or reduction (e.g., GMP's mpn_mul with operand-dependent timing). |
| Clamping | Secret scalar | No risk (bitwise OR/AND on fixed positions). |

### 1.7 Ed25519 (PureEd25519)

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Key expansion: `SHA-512(seed)` | 32-byte seed | Inherited from SHA-512. |
| Nonce generation: `SHA-512(sk_prefix \|\| m)` | Upper 32 bytes (bytes 32..63) of expanded key | Inherited from SHA-512. |
| Scalar multiplication: `[r]B` and `[s]B` during signing | Nonce scalar r (secret), verification does not touch secrets | **CRITICAL.** Must use fixed-window or constant-time ladder. Variable-time double-and-add leaks scalar bits. |
| Scalar reduction mod L (group order) | Nonce r, signing scalar s | **RISK.** Barrett or Montgomery reduction must be constant-time. Trial subtraction with early exit leaks magnitude. |
| Point encoding/decoding | Public (used on public keys during verification) | No risk (verification is not secret-dependent). |

### 1.8 ML-KEM-768 (FIPS 203)

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| NTT (Number Theoretic Transform) | Secret polynomial coefficients s, e | **RISK.** Butterfly operations use modular arithmetic. If Barrett/Montgomery reduction branches on operand size, timing leaks coefficient values. |
| Inverse NTT | Decrypted polynomial | Same as NTT. |
| Polynomial multiply (NTT domain) | Secret polynomial s | Inherited from NTT. |
| Compress/Decompress | Ciphertext coefficients (public), but decompress touches secret s during decapsulation | **RISK** from division/rounding if not constant-time. |
| Decapsulation re-encryption check | Secret key s, message m' | **CRITICAL.** The FO transform re-encrypts and compares. The comparison MUST be constant-time and the branch on match/mismatch MUST execute both paths identically (implicit rejection). |
| CBD (Centered Binomial Distribution) sampling | Random seed (secret) | **RISK** if popcount or addition is variable-time. |
| Encode/Decode | Secret polynomial during KeyGen/Decaps | No risk if using fixed-width arithmetic. |

### 1.9 GHASH (standalone entry for GCM)

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| GF(2^128) multiplication | Hash subkey H | See Section 1.5. |
| GF(2^128) reduction mod x^128 + x^7 + x^2 + x + 1 | Intermediate product | **RISK** if conditional reduction is used. |

### 1.10 ChaCha20

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Quarter round (a += b; d ^= a; d <<<= 16; ...) | Key (256 bits), counter, nonce | ARX (add-rotate-XOR) operations are inherently constant-time on fixed-width registers. **No risk** if implemented with 32-bit unsigned integer arithmetic. |
| Block function (20 rounds) | Key material | No risk (ARX only). |
| Keystream XOR with plaintext | Plaintext | No risk (XOR only). |

### 1.11 ECVRF-ED25519-SHA512

| Operation | Secret Input | Timing Risk |
|-----------|-------------|-------------|
| Elligator2 hash-to-curve | Input x (public) | No risk (public input). |
| Scalar multiplication: `[sk] * H(x)` | VRF secret key sk | **CRITICAL.** Same risks as Ed25519 scalar multiply. Must use fixed-window or Montgomery ladder. |
| DLEQ proof generation (Schnorr-like) | Secret key sk, nonce k | Same as Ed25519 signing. |
| Scalar arithmetic mod L | Secret scalar | Same as Ed25519 scalar reduction. |

---

## 2. Constant-Time Patterns Required

### 2.1 AES-256: Bitsliced Implementation

**Algorithm:** Bitsliced AES as described by Konighofer (2008) and Kasper & Schwabe (2009).

**Approach:**
- Represent the 16-byte AES state as 128 bits distributed across 8 registers, one register per bit position.
- SubBytes becomes a sequence of ~115 Boolean gates (AND, OR, XOR, NOT) operating on the 8 bit-sliced registers. No table lookups whatsoever.
- ShiftRows and MixColumns become register permutations and XOR chains.
- Process 8 blocks in parallel (one per bit position across 64-bit registers) for throughput.

**Single-block mode:** When encrypting fewer than 8 blocks (e.g., a single GCM counter block), pad the remaining 7 slots with dummy data, compute all 8, and discard 7. This wastes ~7/8 of the computation but maintains constant-time properties.

**Key schedule:** Also bitsliced. The S-box applications in the key schedule use the same Boolean circuit as SubBytes.

**Forbidden:** `uint8_t sbox[256]` lookup tables in any form.

### 2.2 X25519: Montgomery Ladder

**Algorithm:** Montgomery ladder per RFC 7748 Section 5, with constant-time conditional swap (cswap).

**Approach:**
- Process scalar bits from most significant to least significant.
- At each step, perform a conditional swap of two point representations based on the current scalar bit, then a combined differential-add-and-double.
- The conditional swap MUST be implemented as:
  ```c
  void ct_cswap(uint64_t *a, uint64_t *b, uint64_t flag) {
      uint64_t mask = -(uint64_t)(flag & 1);  // 0x0000... or 0xFFFF...
      for (int i = 0; i < LIMBS; i++) {
          uint64_t t = mask & (a[i] ^ b[i]);
          a[i] ^= t;
          b[i] ^= t;
      }
  }
  ```
- Exactly 255 ladder steps, regardless of scalar value.
- No early termination on leading zeros.

**Field arithmetic (mod p = 2^255 - 19):**
- Represent field elements as 5 x 51-bit limbs in radix-2^51 (or 10 x 25.5-bit limbs per djb's ref10).
- Multiplication: schoolbook 5x5 multiply, then reduce. All multiplies are on unsigned 64-bit or 128-bit integers (constant-time on all modern CPUs).
- Reduction: the "carry chain" adds multiples of 19 to the high limb and propagates carries. No conditional branches -- carry is always computed and added (the value is 0 if there is no carry).
- Inversion: use Fermat's little theorem, a^(p-2) mod p, via a fixed addition chain. No branching on the exponent.

### 2.3 Ed25519: Fixed-Window Scalar Multiplication

**Algorithm:** Fixed-window (width w=4) scalar multiplication with precomputed table, per the SUPERCOP ref10 implementation.

**Approach:**
- Precompute a table of 16 multiples of the base point: `[0]B, [1]B, ..., [15]B`.
- Recode the scalar into base-16 signed digits (Non-Adjacent Form is NOT used; use regular fixed-window decomposition with constant number of digits).
- For each digit, select the appropriate table entry using a constant-time table lookup (see below), then add to the accumulator.
- Every loop iteration performs exactly one point addition, regardless of digit value.

**Constant-time table lookup:**
```c
// Select table[index] without leaking index via cache timing
void ct_select(ge_precomp *result, const ge_precomp table[16], int index) {
    memset(result, 0, sizeof(*result));
    for (int i = 0; i < 16; i++) {
        uint64_t mask = ct_eq(i, index);  // 0xFFFF... if equal, 0 otherwise
        ct_cmov(result, &table[i], mask);
    }
}
```
This reads ALL 16 table entries every time, selecting the correct one via masking.

**Scalar reduction mod L:**
- Barrett reduction with fixed-width operands.
- The Barrett constant mu = floor(2^512 / L) is precomputed.
- All intermediate values are represented in fixed-width 512-bit integers (8 x 64-bit limbs).
- Final conditional subtraction uses ct_select, not a branch.

### 2.4 ML-KEM-768: Barrett Reduction for NTT

**Algorithm:** NTT with Barrett reduction for all modular arithmetic mod q = 3329.

**Approach for modular arithmetic:**
- All coefficients are represented as `int16_t` (signed 16-bit).
- Barrett reduction for modular reduction after multiply:
  ```c
  // Reduce a mod q=3329, constant-time
  int16_t barrett_reduce(int16_t a) {
      int32_t t;
      const int16_t v = 20159;  // floor(2^26 / q + 0.5)
      t = (int32_t)v * a + (1 << 25);
      t >>= 26;
      t *= KYBER_Q;
      return a - (int16_t)t;
  }
  ```
- NTT butterfly: fixed pattern of multiply-and-add, no conditional branches.
- Inverse NTT: same butterfly structure in reverse.

**Decapsulation (FO transform with implicit rejection):**
- After decrypting to obtain m', re-encrypt with m' to produce c'.
- Compare c' with the received c using constant-time `ct_memcmp()`.
- Compute BOTH the real shared secret `ss_real = H(K_bar || H(c))` AND the rejection value `ss_rej = H(z || c)` where z is the 32-byte implicit rejection seed from the secret key.
- Select between them using constant-time `ct_select_bytes()` based on the comparison result.
- **Both code paths execute fully.** The select occurs AFTER both values are computed.

**CBD sampling:**
- Centered Binomial Distribution sampling uses popcount on random bytes.
- Use a constant-time popcount via lookup-free bit manipulation:
  ```c
  uint32_t ct_popcount(uint32_t x) {
      x = x - ((x >> 1) & 0x55555555);
      x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
      return ((x + (x >> 4)) & 0x0F0F0F0F) * 0x01010101 >> 24;
  }
  ```

### 2.5 GHASH: Constant-Time GF(2^128) Multiplication

**Algorithm:** Schoolbook binary polynomial multiplication with constant-time reduction, OR use of hardware PCLMULQDQ where available.

**Software fallback (no PCLMULQDQ):**
- Represent 128-bit polynomials as two `uint64_t` values.
- Multiplication: 64x64 -> 128-bit carryless multiply decomposed into four 32x32 schoolbook multiplies, each implemented as a loop over all 32 bits (no skipping zero bits):
  ```c
  void ct_gf128_mul(uint64_t *rh, uint64_t *rl,
                    uint64_t ah, uint64_t al,
                    uint64_t bh, uint64_t bl) {
      // Process every bit of b, unconditionally
      for (int i = 0; i < 64; i++) {
          uint64_t mask = -((bl >> i) & 1);
          // XOR a into result, masked
          *rl ^= (al & mask);
          *rh ^= (ah & mask);
          // shift a left by 1 (with carry into high)
          uint64_t carry = al >> 63;
          al <<= 1;
          ah = (ah << 1) | carry;
      }
      // ... repeat for bh
  }
  ```
- Reduction mod x^128 + x^7 + x^2 + x + 1: fixed shift-and-XOR sequence, no conditionals.

**Hardware path (PCLMULQDQ):**
- Use `_mm_clmulepi64_si128` intrinsic for carryless multiply.
- PCLMULQDQ is constant-time on all Intel/AMD CPUs since Westmere (2010).
- Reduction via the Gueron & Kounavis (2010) shift-XOR method (no branches).

### 2.6 HMAC / HKDF: Constant-Time Comparison

HMAC and HKDF computations themselves are constant-time (SHA-512 internals use only bitwise ops and addition on fixed-width words). The critical operation is **MAC verification**:

```c
// Returns 0 if equal, non-zero otherwise. Constant-time.
int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return (int)result;
}
```

### 2.7 ChaCha20: ARX (Inherently Constant-Time)

ChaCha20's quarter-round function uses only:
- 32-bit unsigned addition (constant-time on all platforms)
- 32-bit XOR (constant-time)
- 32-bit left rotation by fixed amounts (constant-time)

No special implementation technique is needed. The C implementation MUST use `uint32_t` types (not arbitrary-precision integers) and MUST NOT use lookup tables for rotation.

### 2.8 ECVRF: Same as Ed25519

The ECVRF scalar multiplication `[sk] * H(x)` uses the identical fixed-window algorithm as Ed25519 (Section 2.3). The DLEQ proof computation `s = k - c*sk mod L` uses constant-time modular arithmetic (Barrett reduction, same as Section 2.3).

---

## 3. Banned Patterns

The following coding patterns are **absolutely forbidden** in any code path that processes secret data. Violations are treated as security defects and block release.

### 3.1 Secret-Dependent Branches

**Forbidden:**
```c
// BANNED: branch on secret value
if (secret_byte & 0x80) {
    do_something();
}

// BANNED: ternary on secret
result = (secret_bit) ? value_a : value_b;

// BANNED: switch on secret
switch (secret_value) { ... }

// BANNED: loop count depends on secret
for (int i = 0; i < secret_length; i++) { ... }

// BANNED: while loop with secret-dependent termination
while (secret_value != 0) { secret_value >>= 1; count++; }
```

**Required replacement:** Conditional move via bitwise masking:
```c
uint64_t ct_select(uint64_t a, uint64_t b, uint64_t flag) {
    uint64_t mask = -(flag & 1);
    return (a & mask) | (b & ~mask);
}
```

### 3.2 Secret-Indexed Array Lookups

**Forbidden:**
```c
// BANNED: S-box table indexed by secret
uint8_t result = sbox[secret_byte];

// BANNED: precomputed table indexed by secret digit
Point p = table[secret_digit];

// BANNED: any array where index depends on secret
char c = buffer[secret_offset];
```

**Required replacement:** Full-table scan with constant-time selection (see Section 2.3 `ct_select`), or bitsliced computation that avoids tables entirely (see Section 2.1).

### 3.3 Variable-Time Division and Modular Reduction

**Forbidden:**
```c
// BANNED: hardware division instruction (data-dependent on most CPUs)
uint32_t q = a / b;
uint32_t r = a % b;

// BANNED: GMP mpz_mod (variable-time)
mpz_mod(result, a, modulus);

// BANNED: trial subtraction with early exit
while (a >= modulus) a -= modulus;

// BANNED: GCD with secret operand (Euclidean algorithm is variable-time)
gcd(secret_a, public_b);
```

**Required replacement:**
- Barrett reduction (precomputed reciprocal, fixed iteration count)
- Montgomery reduction (fixed multiplication sequence)
- Fermat inversion via fixed addition chain (for field inversion)

### 3.4 Early-Exit Comparisons

**Forbidden:**
```c
// BANNED: memcmp (returns on first difference)
if (memcmp(computed_tag, received_tag, 16) == 0) { ... }

// BANNED: strcmp
if (strcmp(a, b) == 0) { ... }

// BANNED: == on multi-byte secret arrays via any short-circuit mechanism
if (a[0] == b[0] && a[1] == b[1] && ...) { ... }

// BANNED: bcmp (may short-circuit on some platforms)
if (bcmp(a, b, len) == 0) { ... }
```

**Required replacement:** `ct_memcmp()` as defined in Section 2.6.

### 3.5 Variable-Time Encoding/Serialization

**Forbidden:**
```c
// BANNED: sprintf with secret values (output length depends on value)
sprintf(buf, "%d", secret_value);

// BANNED: variable-length encoding of secret
int len = encode_varint(secret_value, buf);
```

### 3.6 Compiler Optimization Hazards

**Forbidden:**
```c
// BANNED: relying on volatile alone for constant-time
// (volatile prevents reordering but does not prevent
//  the compiler from converting ct_select into a branch)
volatile int x = secret;
result = x ? a : b;  // compiler may still branch
```

**Required:** All constant-time primitives must be compiled with the following flags, AND verified post-compilation (see Section 6):
- `-O2` (not `-O3`, which is more aggressive about if-conversion)
- No link-time optimization (`-fno-lto`) for constant-time modules
- Barrier functions (empty assembly blocks) around critical selections to prevent compiler rewriting

### 3.7 Haskell-Specific Banned Patterns

**Forbidden in pure Haskell code paths that handle secrets (verification/test path only, but still applies):**

```haskell
-- BANNED: pattern match on secret (compiles to branch)
case secretBit of
  0 -> valueA
  _ -> valueB

-- BANNED: guards on secret values
f x | x > threshold = ...
    | otherwise      = ...

-- BANNED: Data.List.lookup with secret index
-- BANNED: (!!) with secret index
-- BANNED: Integer arithmetic (GMP is variable-time)
let result = secretInteger * publicInteger  -- GMP timing leak
```

---

## 4. Haskell-Specific Risks

GHC and the Haskell runtime introduce timing variability that is **fundamentally incompatible** with constant-time requirements. This section catalogs every known risk and specifies the mitigation.

### 4.1 Lazy Evaluation and Thunk Forcing

**Risk:** Haskell's default evaluation strategy is lazy. A thunk (unevaluated expression) is only computed when its value is demanded. If the decision to force a thunk depends on secret data, the timing of the force reveals information about the secret.

**Example of dangerous code:**
```haskell
-- Thunk 'expensiveComputation' is only forced if secretBit is True
let result = if secretBit then expensiveComputation else cheapValue
seq result ()  -- forcing here, but the cost differs
```

**Mitigation:**
- All secret-dependent computation MUST go through the FFI path to C.
- The pure Haskell path is used ONLY for correctness verification against known test vectors, never in production with real secrets.
- Even in the Haskell verification path, use `BangPatterns` and `seq` to force all intermediate values eagerly, reducing (but not eliminating) timing variability.

### 4.2 GHC Integer and GMP

**Risk:** Haskell's `Integer` type uses GMP (`libgmp`) for arbitrary-precision arithmetic. GMP's multiplication, division, and modular reduction are variable-time -- execution time depends on operand magnitude and number of limbs.

**Specific leaks:**
- `mpn_mul`: time proportional to product of limb counts
- `mpn_tdiv_qr`: time depends on quotient size
- `mpn_gcd`: Euclidean algorithm with data-dependent iteration count
- Small integers (fitting in a single machine word) use a fast path via GHC's `S#` constructor, creating a timing discontinuity at the word boundary

**Mitigation:**
- **Production:** All modular arithmetic is performed in C via FFI using fixed-width limb representations (e.g., 5 x uint64_t for Curve25519 field elements). GMP is never invoked for secret-dependent computation.
- **Verification path:** Accept that timing leaks exist. The verification path processes only test vectors (not real secrets), so the leak is not exploitable.
- **Do NOT use** `Integer` for any field element, scalar, or polynomial coefficient type, even in types that are only ever constructed/destructed at the FFI boundary.

### 4.3 Garbage Collector Timing

**Risk:** GHC's garbage collector (GC) introduces unpredictable pauses. If GC behavior correlates with secret data (e.g., allocation patterns differ based on a secret branch), the GC pauses become a side channel.

**Additional risk:** GC may move sensitive data in memory, leaving copies of secret material in freed heap regions that are not zeroed.

**Mitigation:**
- **Production:** Secret data lives in C-allocated memory (`malloc`/`mmap`), not on the GHC heap. The GC never sees or moves secret data.
- Use `ForeignPtr` with custom finalizers (see Section 7) to reference C-allocated secret buffers from Haskell.
- Never store secret bytes in Haskell `ByteString` (which is GHC-heap-allocated and subject to GC copying). Instead, use `ForeignPtr Word8` pointing to C-managed buffers.

### 4.4 Strictness and Unboxing

**Risk:** Even with `BangPatterns`, GHC may float out subexpressions, inline code differently based on constructor tags, or fail to unbox values, creating data-dependent allocation patterns.

**Mitigation:**
- For production: irrelevant (all crypto is in C via FFI).
- For verification: compile with `-O0` to minimize optimizer interference, accept that timing guarantees do not hold.

### 4.5 Short-Circuit Boolean Evaluation

**Risk:** Haskell's `(&&)` and `(||)` are short-circuit by definition. `False && expensive` never evaluates `expensive`.

**Mitigation:**
- Never use `(&&)` or `(||)` with secret-dependent operands.
- In the FFI path, this is handled by C's bitwise `&` and `|` operators on the result of `ct_memcmp`.

### 4.6 Exception and Error Paths

**Risk:** If a cryptographic function throws an exception on certain secret-dependent conditions (e.g., "point not on curve" during decoding), the exception itself is a timing signal.

**Mitigation:**
- The C FFI functions MUST return error codes, never `abort()` or signal.
- The Haskell wrapper converts error codes to `Either` values AFTER the constant-time C function has completed.
- ML-KEM decapsulation in particular MUST NOT throw on invalid ciphertext -- it returns the implicit rejection value.

---

## 5. FFI Boundary Specification

### 5.1 General Conventions

All FFI functions follow these conventions:

1. **Calling convention:** C calling convention (`ccall`).
2. **Memory ownership:** Caller allocates all buffers (input and output) before calling. Callee never allocates.
3. **Buffer sizing:** All buffer sizes are compile-time constants or passed explicitly. No callee-determined sizes.
4. **Return value:** `int` status code. `0` = success, non-zero = error. The callee MUST NOT return early on error before completing all constant-time work.
5. **No global state:** All functions are pure (no static variables, no global state). Thread-safe by construction.
6. **Alignment:** All buffers must be aligned to 16-byte boundaries (for potential SIMD use in bitsliced AES and NTT).

### 5.2 Function Signatures

```c
/*
 * All functions return 0 on success, non-zero on error.
 * All pointer parameters are non-NULL, caller-allocated.
 * Sizes are in bytes unless otherwise noted.
 */

/* ---- SHA-256 ---- */
// out: 32 bytes
int UmbraVox_sha256(uint8_t *out, const uint8_t *msg, size_t msg_len);

/* ---- SHA-512 ---- */
// out: 64 bytes
int UmbraVox_sha512(uint8_t *out, const uint8_t *msg, size_t msg_len);

/* ---- HMAC-SHA-512 ---- */
// out: 64 bytes, key: 64 bytes (zero-padded if shorter)
int UmbraVox_hmac_sha512(uint8_t *out,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *msg, size_t msg_len);

/* ---- HKDF-SHA-512 ---- */
// prk_out: 64 bytes
int UmbraVox_hkdf_extract(uint8_t *prk_out,
                          const uint8_t *salt, size_t salt_len,
                          const uint8_t *ikm, size_t ikm_len);

// okm_out: okm_len bytes (caller specifies)
int UmbraVox_hkdf_expand(uint8_t *okm_out, size_t okm_len,
                         const uint8_t *prk, size_t prk_len,
                         const uint8_t *info, size_t info_len);

/* ---- AES-256 (single block, for GCM internals) ---- */
// out: 16 bytes, key: 32 bytes, in: 16 bytes
int UmbraVox_aes256_encrypt_block(uint8_t *out,
                                  const uint8_t *key,
                                  const uint8_t *in);

/* ---- AES-256-GCM ---- */
// ct_out: pt_len bytes, tag_out: 16 bytes
// nonce: 12 bytes, key: 32 bytes
int UmbraVox_aes256gcm_encrypt(uint8_t *ct_out, uint8_t *tag_out,
                               const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *pt, size_t pt_len);

// pt_out: ct_len bytes
// Returns 0 on success (tag valid), -1 on tag mismatch.
// MUST complete all computation before returning -1 (constant-time).
int UmbraVox_aes256gcm_decrypt(uint8_t *pt_out,
                               const uint8_t *key,
                               const uint8_t *nonce,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *ct, size_t ct_len,
                               const uint8_t *tag);

/* ---- X25519 ---- */
// shared_out: 32 bytes, scalar: 32 bytes, point: 32 bytes
int UmbraVox_x25519(uint8_t *shared_out,
                    const uint8_t *scalar,
                    const uint8_t *point);

// pub_out: 32 bytes, scalar: 32 bytes
// Computes scalar * basepoint
int UmbraVox_x25519_base(uint8_t *pub_out,
                         const uint8_t *scalar);

/* ---- Ed25519 ---- */
// sig_out: 64 bytes, sk: 32 bytes (seed), msg: arbitrary length
int UmbraVox_ed25519_sign(uint8_t *sig_out,
                          const uint8_t *sk,
                          const uint8_t *msg, size_t msg_len);

// Returns 0 if valid, -1 if invalid.
// Verification is NOT secret-dependent (all inputs are public), so
// constant-time is not strictly required, but we use it anyway to
// avoid being a timing oracle for fault attacks.
int UmbraVox_ed25519_verify(const uint8_t *sig,
                            const uint8_t *pk,
                            const uint8_t *msg, size_t msg_len);

// pk_out: 32 bytes, sk: 32 bytes (seed)
int UmbraVox_ed25519_pubkey(uint8_t *pk_out, const uint8_t *sk);

/* ---- ML-KEM-768 ---- */
// pk_out: 1184 bytes, sk_out: 2400 bytes
// coins: 64 bytes of randomness (caller provides from CSPRNG)
int UmbraVox_mlkem768_keygen(uint8_t *pk_out, uint8_t *sk_out,
                             const uint8_t *coins);

// ct_out: 1088 bytes, ss_out: 32 bytes
// coins: 32 bytes of randomness
int UmbraVox_mlkem768_encaps(uint8_t *ct_out, uint8_t *ss_out,
                             const uint8_t *pk,
                             const uint8_t *coins);

// ss_out: 32 bytes
// Implicit rejection: on invalid ciphertext, ss_out is set to
// H(z || ct) where z is embedded in sk. Constant-time.
int UmbraVox_mlkem768_decaps(uint8_t *ss_out,
                             const uint8_t *sk,
                             const uint8_t *ct);

/* ---- ECVRF-ED25519-SHA512 ---- */
// proof_out: 80 bytes, hash_out: 64 bytes
int UmbraVox_ecvrf_prove(uint8_t *proof_out, uint8_t *hash_out,
                         const uint8_t *sk,
                         const uint8_t *alpha, size_t alpha_len);

// hash_out: 64 bytes
// Returns 0 if valid, -1 if invalid. (Verification is public-input.)
int UmbraVox_ecvrf_verify(uint8_t *hash_out,
                          const uint8_t *pk,
                          const uint8_t *proof,
                          const uint8_t *alpha, size_t alpha_len);

/* ---- ChaCha20 ---- */
// out: len bytes, key: 32 bytes, nonce: 12 bytes, counter: initial counter
int UmbraVox_chacha20(uint8_t *out,
                      const uint8_t *key,
                      const uint8_t *nonce,
                      uint32_t counter,
                      const uint8_t *in, size_t len);

/* ---- Utility ---- */
// Constant-time memory comparison. Returns 0 if equal.
int UmbraVox_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len);

// Secure memory zeroing (cannot be optimized away).
void UmbraVox_ct_memzero(void *buf, size_t len);
```

### 5.3 Haskell FFI Declarations

```haskell
-- Example FFI import (all follow this pattern)
foreign import ccall unsafe "UmbraVox_x25519"
    c_x25519 :: Ptr Word8    -- shared_out (32 bytes, caller-allocated)
             -> Ptr Word8    -- scalar (32 bytes)
             -> Ptr Word8    -- point (32 bytes)
             -> IO CInt      -- 0 on success

foreign import ccall unsafe "UmbraVox_ct_memzero"
    c_memzero :: Ptr Word8 -> CSize -> IO ()
```

**Use `unsafe` for all crypto FFI calls.** These functions:
- Do not call back into Haskell
- Do not block
- Execute in bounded time (no loops dependent on unbounded input except message length, which is bounded by protocol)

The `unsafe` qualifier avoids the overhead of saving/restoring the Haskell thread state, which itself could introduce timing variability.

### 5.4 Memory Management at the FFI Boundary

1. **Allocation:** The Haskell wrapper allocates output buffers using `mallocForeignPtrBytes` (pinned, GC-tracked) or, for secret data, using `mallocBytes` wrapped in a `ForeignPtr` with a zeroing finalizer (see Section 7).

2. **Pinning:** All buffers passed to C MUST be pinned (not moveable by GC). `mallocForeignPtrBytes` produces pinned memory. `ByteString` internals use pinned memory. Never pass unpinned `MutableByteArray#` to C.

3. **Lifetime:** The Haskell wrapper ensures (via `withForeignPtr` or `bracket`) that buffers remain live for the duration of the FFI call.

4. **Zeroing:** After the FFI call completes, secret input buffers are zeroed via `UmbraVox_ct_memzero` before being released. Output buffers containing secrets are wrapped in `ForeignPtr` with zeroing finalizers.

---

## 6. Verification Methodology

### 6.1 Dudect Statistical Testing

**Tool:** The dudect methodology (Reparaz, Gierlichs, Verbauwhede 2017).

**Principle:** Measure execution time of the function under test with two classes of inputs: "fixed" (constant secret) and "random" (varying secret). Apply Welch's t-test to the two timing distributions. If the t-statistic exceeds the threshold (|t| > 4.5), the implementation is non-constant-time.

**Test harness design:**
```c
// For each function under test:
#define NUM_MEASUREMENTS 1000000
#define THRESHOLD 4.5

typedef struct {
    uint8_t input[MAX_INPUT_SIZE];
    uint8_t class;  // 0 = fixed, 1 = random
} test_case_t;

void dudect_test(void (*func)(const uint8_t*, uint8_t*),
                 size_t input_size) {
    double sum_fixed = 0, sum_random = 0;
    double sum_sq_fixed = 0, sum_sq_random = 0;
    uint64_t n_fixed = 0, n_random = 0;

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        test_case_t tc;
        // Alternate fixed/random, measure with rdtsc/rdtscp
        uint64_t start = rdtscp();
        func(tc.input, output);
        uint64_t end = rdtscp();
        uint64_t elapsed = end - start;

        if (tc.class == 0) {
            sum_fixed += elapsed; sum_sq_fixed += elapsed*elapsed; n_fixed++;
        } else {
            sum_random += elapsed; sum_sq_random += elapsed*elapsed; n_random++;
        }
    }

    double t = welch_t_test(sum_fixed, sum_sq_fixed, n_fixed,
                            sum_random, sum_sq_random, n_random);
    assert(fabs(t) < THRESHOLD);  // FAIL if timing depends on input
}
```

**Measurement details:**
- Use `rdtscp` (serializing timestamp counter) on x86_64 for cycle-accurate timing.
- Disable CPU frequency scaling (`cpupower frequency-set -g performance`).
- Disable turbo boost (`echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo`).
- Pin test process to a single CPU core (`taskset -c 0`).
- Run at least 10^6 measurements per test.
- Apply Mains filter: discard measurements with elapsed time > mean + 3*stddev (noise from interrupts).
- Apply the Cropping technique: first 100 measurements discarded (cache warmup).

**Required test cases per primitive:**

| Primitive | Fixed Class | Random Class |
|-----------|-----------|-------------|
| AES-256 encrypt | All-zero key, fixed plaintext | Random key, same plaintext |
| AES-256-GCM decrypt | Valid tag (fixed key) | Random tag (same key) |
| X25519 | Scalar = all low bits set | Random scalar |
| Ed25519 sign | Fixed seed, fixed message | Random seed, same message |
| ML-KEM decaps (valid ct) | Valid ciphertext | Random (invalid) ciphertext |
| ML-KEM decaps (timing of implicit rejection) | Valid ct (accept path) | Invalid ct (reject path) |
| GHASH | H with low Hamming weight | Random H |
| HMAC-SHA-512 (MAC verify) | Matching MAC | Non-matching MAC |
| ECVRF prove | Scalar with leading zeros | Random scalar |
| ChaCha20 | All-zero key | Random key |
| ct_memcmp | Equal inputs | Differing at byte 0 vs byte 15 |

### 6.2 Ctgrind / Valgrind Memcheck Approach

**Tool:** ctgrind (Adam Langley's Valgrind-based tool for detecting secret-dependent branches and memory accesses).

**Principle:** Mark secret memory regions as "uninitialized" using Valgrind's client requests (`VALGRIND_MAKE_MEM_UNDEFINED`). Then run the function. If any branch or memory access depends on the "uninitialized" (secret) data, Valgrind reports a "Conditional jump or move depends on uninitialised value" or "Use of uninitialised value" error.

**Integration:**
```c
#include <valgrind/memcheck.h>

void test_x25519_ct(void) {
    uint8_t scalar[32], point[32], out[32];
    fill_random(scalar, 32);
    fill_random(point, 32);

    // Mark scalar as "secret" (uninitialized from Valgrind's perspective)
    VALGRIND_MAKE_MEM_UNDEFINED(scalar, 32);

    UmbraVox_x25519(out, scalar, point);

    // Mark output as "public" (defined) for subsequent use
    VALGRIND_MAKE_MEM_DEFINED(out, 32);
}
```

**Required annotations for each primitive:**

| Primitive | Secret (mark undefined) | Public (mark defined after) |
|-----------|------------------------|---------------------------|
| SHA-256/512 | (no secrets in UmbraVox's SHA usage directly, but mark HMAC key) | Hash output |
| HMAC-SHA-512 | Key | MAC output |
| HKDF | IKM | OKM output |
| AES-256-GCM encrypt | Key, plaintext | Ciphertext, tag |
| AES-256-GCM decrypt | Key | Plaintext (only if tag valid) |
| X25519 | Scalar | Shared secret |
| Ed25519 sign | Seed (secret key) | Signature |
| ML-KEM keygen | Coins (random seed) | pk, sk |
| ML-KEM encaps | Coins | ct, ss |
| ML-KEM decaps | sk | ss |
| ECVRF prove | sk | proof, hash |
| ChaCha20 | Key | Keystream output |

**CI integration:** Run ctgrind tests on every commit. Any Valgrind error in a `UmbraVox_*` function is a release-blocking defect.

### 6.3 Assembly Inspection

For each constant-time C function, the generated assembly MUST be manually inspected for:

1. **Conditional branches on secret-derived registers:** Search for `jz`, `jnz`, `je`, `jne`, `jl`, `jg`, `jle`, `jge`, `ja`, `jb`, `jae`, `jbe` instructions where the condition flags were set by a comparison involving a register that held secret data.

2. **Variable-indexed memory loads:** Search for `mov` instructions with register-based addressing (e.g., `mov rax, [rbx + rcx*8]`) where the index register `rcx` holds secret data.

3. **Compiler-introduced branches:** Even with branchless C source, the compiler may introduce branches for `cmov` sequences it deems unprofitable, or may convert masking operations into branches.

**Tooling:** Use `objdump -d` on the compiled object files. Annotate each function with expected instruction count and verify it matches across compilations.

**Frequency:** Assembly inspection is performed once per toolchain version change (GCC/Clang major version), once per target architecture, and whenever the C source is modified.

---

## 7. Secure Memory Erasure

### 7.1 Problem Statement

After a secret value is no longer needed, its memory must be zeroed to prevent recovery via cold boot attacks, core dumps, swap files, or GC heap scanning. Compilers aggressively optimize away "dead stores" -- zeroing memory that is never subsequently read is a dead store and will be removed.

### 7.2 C Implementation

**Primary method: `explicit_bzero` (POSIX.1-2017):**
```c
#include <string.h>

void UmbraVox_ct_memzero(void *buf, size_t len) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(buf, len, 0, len);  // C11 Annex K
#elif defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__linux__)
    explicit_bzero(buf, len);    // POSIX
#else
    // Fallback: volatile function pointer to memset
    static void *(*const volatile memset_func)(void *, int, size_t) = memset;
    memset_func(buf, 0, len);
#endif
}
```

**Why not `volatile memset`:**
The C standard does not guarantee that `volatile` on a pointer-to-function prevents optimization of the store. The `volatile` function pointer trick (assigning `memset` to a `volatile`-qualified function pointer) works on all known compilers in practice, but `explicit_bzero` or `memset_s` are the only standards-guaranteed approaches.

**Compiler barrier (belt-and-suspenders):**
```c
// After zeroing, insert a compiler barrier to prevent reordering
__asm__ __volatile__("" ::: "memory");
```

### 7.3 Haskell-Side Erasure via ForeignPtr Finalizers

```haskell
-- Allocate a secret buffer with a zeroing finalizer
allocSecret :: Int -> IO (ForeignPtr Word8)
allocSecret size = do
    ptr <- mallocBytes size
    newForeignPtr (finalizerSecretFree (fromIntegral size)) ptr

-- C finalizer that zeros then frees
foreign import ccall "&UmbraVox_secret_free"
    finalizerSecretFree :: CSize -> FinalizerPtr Word8
```

Corresponding C:
```c
// Called by GHC's finalizer mechanism when ForeignPtr is GC'd
void UmbraVox_secret_free(size_t size, uint8_t *ptr) {
    UmbraVox_ct_memzero(ptr, size);
    free(ptr);
}
```

**Note on finalizer ordering:** GHC does not guarantee when finalizers run. For defense in depth, the Haskell wrapper should ALSO explicitly zero secret buffers via `withForeignPtr` + `c_memzero` at the point where the secret is no longer needed, rather than relying solely on the GC finalizer.

### 7.4 Preventing Swap Exposure

On Linux, secret-holding pages should be locked into physical memory to prevent swapping to disk:

```c
#include <sys/mman.h>

void *UmbraVox_secret_alloc(size_t size) {
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) return NULL;
    mlock(ptr, size);         // prevent swapping
    madvise(ptr, size, MADV_DONTDUMP);  // exclude from core dumps
    return ptr;
}

void UmbraVox_secret_dealloc(void *ptr, size_t size) {
    UmbraVox_ct_memzero(ptr, size);
    munlock(ptr, size);
    munmap(ptr, size);
}
```

**`mlock` limits:** The default `RLIMIT_MEMLOCK` is 64 KB on most Linux systems. UmbraVox's secret memory budget must stay within this limit. Estimated peak secret memory:
- 5 x X25519 scalars (160 bytes)
- 1 x Ed25519 seed (32 bytes)
- 1 x ML-KEM secret key (2400 bytes)
- 1 x VRF secret key (32 bytes)
- Ratchet state (< 200 bytes)
- AES round keys (240 bytes)
- TOTAL: < 4 KB, well within 64 KB limit.

### 7.5 Stack Erasure

Secret values that transit through the C stack (local variables in crypto functions) must be zeroed before the function returns:

```c
int UmbraVox_ed25519_sign(uint8_t *sig_out, const uint8_t *sk,
                          const uint8_t *msg, size_t msg_len) {
    uint8_t expanded_sk[64];
    uint8_t nonce[64];
    // ... signing logic ...

    // Zero stack secrets before return
    UmbraVox_ct_memzero(expanded_sk, 64);
    UmbraVox_ct_memzero(nonce, 64);
    return 0;
}
```

Every C function in the FFI layer must zero ALL local variables that held secret-derived values before returning, using `UmbraVox_ct_memzero`.

---

## 8. Per-Primitive Specification Table

The following table specifies, for each of the 11 cryptographic primitives, the exact constant-time algorithm to implement and the reference C implementation to follow.

| # | Primitive | Constant-Time Algorithm | C Reference Implementation | Secret Inputs | Key Operations | Verification Method |
|---|-----------|------------------------|---------------------------|---------------|----------------|-------------------|
| 1 | **SHA-256** | Standard Merkle-Damgard with 32-bit word arithmetic (add, rotate, shift, bitwise). No secrets in SHA-256 direct usage; constant-time matters when called from HMAC. | SUPERCOP `crypto_hash/sha256/ref` (djb) | (none directly; see HMAC) | Compression: Ch, Maj, Sigma via bitwise ops on `uint32_t` | dudect with HMAC wrapper; ctgrind marking HMAC key |
| 2 | **SHA-512** | Standard Merkle-Damgard with 64-bit word arithmetic. Same structure as SHA-256 but with `uint64_t`. | SUPERCOP `crypto_hash/sha512/ref` (djb) | Ed25519 secret key bytes (via nonce derivation) | Compression: Ch, Maj, Sigma via bitwise ops on `uint64_t` | ctgrind with Ed25519 key marked secret |
| 3 | **HMAC-SHA-512** | RFC 2104 with constant-time MAC comparison via `ct_memcmp`. Inner/outer hash use SHA-512 (constant-time per above). | SUPERCOP `crypto_auth/hmacsha512/ref` | HMAC key, input keying material | Key XOR with ipad/opad; SHA-512 compression; `ct_memcmp` for verify | dudect: fixed-key vs random-key; ctgrind marking key |
| 4 | **HKDF-SHA-512** | RFC 5869. Extract = HMAC(salt, IKM). Expand = chained HMAC with counter. All constant-time via HMAC. | Custom (trivial wrapper around HMAC-SHA-512) | IKM (DH outputs, ML-KEM ss), PRK | HMAC calls only | Inherited from HMAC verification |
| 5 | **AES-256** | **Bitsliced implementation** (Kasper & Schwabe 2009). No lookup tables. S-box computed as Boolean circuit (~115 gates). Process 8 blocks in parallel; for single-block GCM use, pad remaining 7 slots. Key schedule also bitsliced. | `crypto_aes/bitsliced` from SUPERCOP; alternatively the bitsliced AES in BearSSL (`src/inner.h`, `aes_ct64_*`) | AES key (32 bytes), plaintext (16 bytes per block) | SubBytes (Boolean circuit), MixColumns (XOR/xtime with masking), AddRoundKey (XOR), ShiftRows (register permutation) | dudect: zero-key vs random-key; ctgrind marking key + plaintext; assembly inspection for absence of table loads |
| 6 | **AES-256-GCM** | CTR mode (bitsliced AES) + GHASH (see #7). Nonce is 12 bytes, counter is 32-bit big-endian. Tag comparison via `ct_memcmp`. On decrypt, plaintext is computed regardless of tag validity; tag check selects between returning plaintext or error AFTER full computation. | BearSSL `aes_ct64_*` + `ghash_ctmul64` | AES key, plaintext, hash subkey H | AES-CTR keystream generation, GHASH tag computation, `ct_memcmp` tag verification | dudect: valid-tag vs invalid-tag timing; ctgrind marking key + plaintext |
| 7 | **GHASH** | Constant-time schoolbook GF(2^128) multiplication. Process every bit of the multiplier unconditionally (no early termination on zero bits). Reduction via fixed shift-XOR sequence. On x86_64 with PCLMULQDQ: use `_mm_clmulepi64_si128` + Gueron-Kounavis reduction. | BearSSL `ghash_ctmul64.c` (software) or `ghash_pclmul.c` (hardware) | Hash subkey H = AES(k, 0^128) | GF(2^128) multiply (128 iterations, unconditional), reduction mod irreducible polynomial | dudect: low-weight H vs random H; ctgrind marking H |
| 8 | **X25519** | **Montgomery ladder** (RFC 7748 Section 5). Exactly 255 ladder steps. Constant-time conditional swap (`ct_cswap`) via XOR masking. Field arithmetic mod 2^255-19 using 5x51-bit limbs (radix-2^51). Field inversion via fixed addition chain (Fermat). No GMP. | SUPERCOP `crypto_scalarmult/curve25519/ref10` (djb, Lange, Schwabe) | 255-bit scalar (private key) | `ct_cswap`, field mul (5x5 schoolbook, `uint128_t` products), field square, field inversion (fixed chain, ~254 squarings + ~12 multiplications) | dudect: low-Hamming-weight scalar vs random; ctgrind marking scalar; assembly inspection of cswap |
| 9 | **Ed25519** | **Fixed-window (w=4) scalar multiplication** with constant-time table lookup (full-table scan with `ct_cmov`). Extended coordinates. Scalar reduction mod L via Barrett reduction with 512-bit fixed-width intermediates. Deterministic nonce via SHA-512(sk_prefix \|\| m). Sign-then-verify pattern for fault resistance. | SUPERCOP `crypto_sign/ed25519/ref10` (djb, Duif, Lange, Schwabe, Yang) | 32-byte seed (secret key), nonce scalar r, signing scalar s | `ct_select` for table lookup (scan all 16 entries), Barrett reduction mod L, extended point addition, SHA-512 for nonce | dudect: fixed-seed vs random-seed; ctgrind marking seed + expanded key + nonce; assembly inspection of table lookup |
| 10 | **ML-KEM-768** | **NTT with Barrett reduction** for all mod-q=3329 arithmetic. Butterfly operations use `int16_t` with Barrett reduce (no division instruction). CBD sampling with constant-time popcount. Decapsulation: FO transform with implicit rejection -- compute BOTH accept and reject shared secrets, select via `ct_select_bytes`. Compress/Decompress use Barrett reduction (no division). | pqcrystals-kyber reference C (`ref/`), specifically `ntt.c`, `reduce.c`, `indcpa.c`, `kem.c`. Use the "clean" reference, not the AVX2 variant. | Secret key vector s, random coins d and z, decrypted message m' | Barrett reduction (`int16_t`), NTT butterfly (fixed pattern), `ct_memcmp` for re-encryption check, `ct_select_bytes` for implicit rejection | dudect: valid-ct decaps vs invalid-ct decaps (MUST show identical timing); ctgrind marking sk + coins; assembly inspection of decaps branch |
| 11 | **ECVRF-ED25519-SHA512** | Same scalar multiply as Ed25519 (fixed-window w=4). Elligator2 hash-to-curve is on public input (not secret-dependent). DLEQ proof: `s = k - c*sk mod L` uses Barrett reduction. Cofactor multiplication is a fixed sequence of 3 doublings. | draft-irtf-cfrg-vrf reference (RFC 9381 Section 5), using Ed25519 ref10 for curve operations | VRF secret key sk, nonce k | Scalar multiply `[sk]*H(x)`, DLEQ nonce generation (deterministic, SHA-512-based), Barrett reduction mod L | dudect: fixed-sk vs random-sk; ctgrind marking sk + DLEQ nonce |

---

## 9. Compilation and Build Requirements

### 9.1 C Compiler Flags

All constant-time C source files MUST be compiled with:

```makefile
CT_CFLAGS = -O2 \
            -fno-lto \
            -fno-builtin \
            -fwrapv \
            -Wall -Wextra -Werror \
            -Wconversion \
            -std=c11
```

- `-O2`: Sufficient optimization without overly aggressive transforms.
- `-fno-lto`: Prevents link-time optimization from rewriting constant-time patterns.
- `-fno-builtin`: Prevents compiler from replacing loops with `memcmp`, `memset`, etc.
- `-fwrapv`: Makes signed integer overflow defined (wrapping), required for Barrett reduction on `int16_t`.

### 9.2 Architecture-Specific Notes

**x86_64:**
- `cmov` instructions are constant-time on all Intel/AMD CPUs.
- `imul` (64-bit multiply) is constant-time on all Intel CPUs since Sandy Bridge and all AMD CPUs since Zen.
- `div`/`idiv` are NOT constant-time. Never used.
- PCLMULQDQ is constant-time on all implementations.

**aarch64:**
- `csel` (conditional select) is constant-time.
- `mul`/`umulh` are constant-time.
- `udiv`/`sdiv` are NOT constant-time. Never used.

### 9.3 Testing Matrix

Every primitive is tested with:
1. **Dudect** (statistical timing) -- 10^6 measurements minimum
2. **Ctgrind** (Valgrind annotation) -- all secret inputs marked
3. **Assembly inspection** -- manual review of generated instructions
4. **Cross-validation** -- C FFI output == pure Haskell output for 10,000+ random inputs

Test evidence is stored in `test/evidence/timing/` with one subdirectory per primitive.

---

## 10. Incident Response for Timing Vulnerabilities

If a timing vulnerability is discovered post-deployment:

1. **Severity:** All timing vulnerabilities in secret-dependent code are classified as CRITICAL.
2. **Disclosure:** Follow coordinated disclosure. Patch before public announcement.
3. **Root cause:** Identify whether the leak is in source code (algorithm), compiler output (optimizer rewrite), or hardware (microarchitectural).
4. **Fix:** Patch the C source, re-run dudect + ctgrind, re-inspect assembly.
5. **Regression test:** Add the specific input pattern that triggered the leak to the permanent dudect test suite.
6. **Chain revision:** If the fix changes function signatures or behavior, issue a chain revision per `doc/04-consensus.md`.

---

## References

- Kasper, E. and Schwabe, P. (2009). "Faster and Timing-Attack Resistant AES-GCM." CHES 2009.
- Bernstein, D.J. (2005). "Cache-timing attacks on AES."
- Reparaz, O., Gierlichs, B., and Verbauwhede, I. (2017). "Dude, is my code constant time?" DATE 2017.
- Gueron, S. and Kounavis, M. (2010). "Intel Carry-Less Multiplication Instruction and its Usage for Computing the GCM Mode." Intel White Paper.
- Bernstein, D.J. (2006). "Curve25519: New Diffie-Hellman Speed Records." PKC 2006.
- Bernstein, D.J., Duif, N., Lange, T., Schwabe, P., and Yang, B.Y. (2012). "High-speed high-security signatures." Journal of Cryptographic Engineering.
- RFC 7748: Elliptic Curves for Security (Langley, Hamburg, Turner, 2016).
- RFC 8032: Edwards-Curve Digital Signature Algorithm (Josefsson, Liusvaara, 2017).
- RFC 9381: Verifiable Random Functions (Goldberg et al., 2023).
- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (NIST, 2024).
- BearSSL source code (Pornin, T.): https://bearssl.org/
- SUPERCOP benchmarking framework: https://bench.cr.yp.to/supercop.html
