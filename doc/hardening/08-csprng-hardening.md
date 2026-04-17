# Hardening Specification 08: CSPRNG Hardening

**Scope:** ChaCha20-based CSPRNG — the single root of all randomness in UmbraVox
**References:** `doc/03-cryptography.md` lines 40–44, `doc/proof-01-primitive-security.md` §9, `doc/proof-07-cryptanalysis-resistance.md`
**Security target:** λ = 128 bits computational entropy at all times

---

## Preamble

The CSPRNG is the foundation of every cryptographic operation in UmbraVox:
identity key generation, ephemeral keys, one-time prekeys, ML-KEM
encapsulation coins, GCM nonces, and VRF seed material.  A CSPRNG failure
is a total system compromise — every key generated from a predictable
stream is recoverable by the adversary.  This specification defines the
exact state machine, seeding discipline, reseed schedule, fork safety,
VM clone detection, and failure handling required for a production
implementation.

---

## 1. Entropy Sources

### 1.1 Primary Source: Linux getrandom()

The primary entropy source is the `getrandom(2)` syscall with flags = 0
(blocking until the kernel CSPRNG is fully seeded).

```c
#include <sys/random.h>
#include <errno.h>
#include <string.h>

/* Read exactly `len` bytes of kernel entropy.
 * Blocks until the kernel CSPRNG is seeded (boot-time safety).
 * Returns 0 on success, -1 on unrecoverable failure. */
static int entropy_read(uint8_t *buf, size_t len) {
    size_t done = 0;
    while (done < len) {
        ssize_t r = getrandom(buf + done, len - done, 0);
        if (r < 0) {
            if (errno == EINTR)
                continue;       /* interrupted — retry */
            return -1;          /* genuine failure — propagate */
        }
        done += (size_t)r;
    }
    return 0;
}
```

**Why getrandom() and not /dev/urandom:**

| Property | getrandom(2) | open+read /dev/urandom |
|----------|-------------|----------------------|
| Blocks until seeded (kernel ≥ 4.8) | Yes (flags=0) | No — may return low-entropy data on early boot |
| File descriptor exhaustion | Immune | Vulnerable (fd limit, /dev not mounted) |
| chroot / container safety | Works anywhere | Requires /dev/urandom in the mount namespace |
| TOCTOU races | None | open() can be redirected by symlink races |

**Mandatory kernel version:** Linux ≥ 4.17 (getrandom always available as
a direct syscall).  On kernels ≥ 5.6, /dev/urandom also blocks until
seeded, but getrandom() remains preferred for the fd-exhaustion and
chroot advantages.

### 1.2 Haskell Binding

```haskell
-- | Read exactly @n@ bytes from the kernel CSPRNG via getrandom(2).
-- Blocks until the kernel is fully seeded.  Calls 'die' on failure.
foreign import ccall unsafe "entropy_read"
    c_entropy_read :: Ptr Word8 -> CSize -> IO CInt

getEntropy :: Int -> IO ByteString
getEntropy n
    | n <= 0    = pure BS.empty
    | otherwise = do
        bs <- BS.create n $ \ptr -> do
            rc <- c_entropy_read ptr (fromIntegral n)
            when (rc /= 0) $
                die "FATAL: getrandom() failed — cannot seed CSPRNG"
        pure bs
```

### 1.3 Fallback Policy

There is no fallback.  If `getrandom()` fails with an error other than
`EINTR`, the process MUST abort.  Under no circumstances shall the
implementation fall back to:

- `time()` or `clock_gettime()` — predictable to within microseconds
- `/dev/random` with non-blocking read — may return short reads
- `rand()` / `srand()` — not cryptographic
- RDRAND alone — may be backdoored; insufficient as sole source

**Rationale:** A degraded CSPRNG that silently produces predictable output
is strictly worse than a crash.  Crash-fail semantics are safe: the node
goes offline, but no keys are compromised.

---

## 2. Seed Quality Verification

### 2.1 Threat Scenarios for Low-Entropy Seeds

| Scenario | Risk | Detection |
|----------|------|-----------|
| Early boot (before kernel entropy pool filled) | getrandom() returns before pool is seeded on old kernels | getrandom(flags=0) blocks — mitigated on ≥ 4.8 |
| VM clone / snapshot resume | Parent and child share identical CSPRNG state | boot_id comparison (§6), RDTSC jump (§6) |
| Container from identical image | Multiple containers seeded from same host entropy at same instant | PID + boot_id + container ID mixed into seed |
| Embedded / low-entropy hardware | No interrupt-driven entropy sources | Kernel blocks at getrandom(); node waits |

### 2.2 Minimum Entropy Threshold

The CSPRNG requires a 256-bit seed with at least 256 bits of min-entropy.
The Linux kernel's CRNG (ChaCha20-based since 4.8) is considered fully
seeded after accumulating 256 bits of estimated entropy.  The
`getrandom(flags=0)` call blocks until this threshold is met.

### 2.3 Supplemental Entropy Mixing at Startup

At process startup, after reading 32 bytes from `getrandom()`, mix in
additional non-secret but unpredictable material to increase divergence
across otherwise-identical instances:

```c
/* Additional startup entropy mixed via HKDF.
 * These inputs are not secret, but they differentiate cloned instances. */
static int mix_supplemental(uint8_t seed[32]) {
    uint8_t aux[128];
    size_t off = 0;

    /* PID (4 bytes) */
    pid_t pid = getpid();
    memcpy(aux + off, &pid, sizeof(pid)); off += sizeof(pid);

    /* Thread ID (8 bytes) */
    uint64_t tid = (uint64_t)pthread_self();
    memcpy(aux + off, &tid, sizeof(tid)); off += sizeof(tid);

    /* High-resolution clock (8 bytes) */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    memcpy(aux + off, &ts, sizeof(ts)); off += sizeof(ts);

    /* boot_id (36 bytes) — unique per boot, detects VM clones */
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, aux + off, 36);
        if (r > 0) off += (size_t)r;
        close(fd);
    }

    /* RDTSC (8 bytes) — high-resolution, hard to predict exactly */
#if defined(__x86_64__) || defined(__i386__)
    uint64_t tsc = __rdtsc();
    memcpy(aux + off, &tsc, sizeof(tsc)); off += sizeof(tsc);
#endif

    /* HKDF-Extract: new_seed = HMAC-SHA-512(key=seed, data=aux)[0..31] */
    hkdf_extract_sha512(seed, 32, aux, off, seed);

    explicit_bzero(aux, sizeof(aux));
    return 0;
}
```

---

## 3. ChaCha20 CSPRNG State Machine

### 3.1 State Definition

```c
#include <stdint.h>
#include <stdatomic.h>

#define CHACHA_KEY_BYTES    32   /* 256-bit key                      */
#define CHACHA_CTR_BYTES    16   /* 128-bit counter (4-byte block counter + 12-byte nonce) */
#define CHACHA_BUF_BYTES    64   /* one ChaCha20 block of output     */
#define RESEED_INTERVAL     (1U << 20)  /* 2^20 = 1,048,576 outputs */

struct csprng_state {
    uint8_t  key[CHACHA_KEY_BYTES];       /* 256-bit ChaCha20 key          */
    uint8_t  counter[CHACHA_CTR_BYTES];   /* 128-bit counter               */
    uint8_t  buf[CHACHA_BUF_BYTES];       /* buffered keystream block      */
    uint32_t buf_pos;                     /* offset within buf             */
    uint64_t outputs_since_reseed;        /* monotonic, reset at reseed    */
    pid_t    seed_pid;                    /* PID at last seed/reseed       */
    uint8_t  boot_id[37];                /* cached /proc/.../boot_id      */
    _Bool    initialized;                /* set after first seed          */
};
```

### 3.2 Haskell State

```haskell
data CSPRNGState = CSPRNGState
    { csprngKey             :: !(IORef ByteString)  -- 32 bytes, mutable for zeroing
    , csprngCounter         :: !(IORef Word128)      -- 128-bit counter
    , csprngBuf             :: !(IORef ByteString)  -- buffered keystream block
    , csprngBufPos          :: !(IORef Int)
    , csprngOutputCount     :: !(IORef Word64)
    , csprngSeedPid         :: !(IORef CPid)
    , csprngBootId          :: !(IORef ByteString)
    , csprngInitialized     :: !(IORef Bool)
    }
```

### 3.3 Initialization

```c
int csprng_init(struct csprng_state *st) {
    /* Read 32 bytes of kernel entropy */
    if (entropy_read(st->key, CHACHA_KEY_BYTES) != 0)
        return -1;  /* FATAL */

    /* Mix supplemental entropy */
    mix_supplemental(st->key);

    /* Zero counter — starts at 0 */
    memset(st->counter, 0, CHACHA_CTR_BYTES);

    /* Generate first keystream block */
    chacha20_block(st->key, st->counter, st->buf);
    increment_counter(st->counter);
    st->buf_pos = 0;

    st->outputs_since_reseed = 0;
    st->seed_pid = getpid();
    read_boot_id(st->boot_id, sizeof(st->boot_id));
    st->initialized = 1;

    return 0;
}
```

### 3.4 Output Generation

```c
/* Generate `len` bytes of CSPRNG output.
 * Checks fork safety and reseed schedule before every output. */
int csprng_generate(struct csprng_state *st, uint8_t *out, size_t len) {
    if (!st->initialized)
        return -1;

    /* Fork safety check (§5) */
    if (getpid() != st->seed_pid) {
        if (csprng_reseed(st) != 0)
            return -1;
    }

    /* Reseed schedule check (§4) */
    if (st->outputs_since_reseed >= RESEED_INTERVAL) {
        if (csprng_reseed(st) != 0)
            return -1;
    }

    size_t done = 0;
    while (done < len) {
        size_t avail = CHACHA_BUF_BYTES - st->buf_pos;
        size_t take  = (len - done < avail) ? (len - done) : avail;

        memcpy(out + done, st->buf + st->buf_pos, take);
        st->buf_pos += (uint32_t)take;
        done += take;

        if (st->buf_pos >= CHACHA_BUF_BYTES) {
            /* Refill buffer */
            chacha20_block(st->key, st->counter, st->buf);
            increment_counter(st->counter);
            st->buf_pos = 0;
        }
    }

    st->outputs_since_reseed += len;
    return 0;
}
```

---

## 4. Reseed Schedule

### 4.1 Periodic Reseed

The CSPRNG reseeds every 2^20 (1,048,576) output bytes, as specified in
`doc/03-cryptography.md` line 43.  This bounds the damage window from a
state compromise: at most 2^20 bytes of output are predictable.

### 4.2 Event-Driven Reseeds

In addition to the periodic schedule, the CSPRNG reseeds on:

| Trigger | Detection | Rationale |
|---------|-----------|-----------|
| Fork detected | `getpid() != seed_pid` | Parent and child must diverge immediately |
| Suspend/resume | Clock jump > threshold (§6.3) | VM snapshot could have been cloned |
| VM clone | boot_id change (§6.1) | New boot instance with same state |
| Explicit request | Application calls `csprng_reseed()` | Post-compromise recovery |

### 4.3 Reseed Implementation

```c
int csprng_reseed(struct csprng_state *st) {
    uint8_t fresh_entropy[CHACHA_KEY_BYTES];

    /* Draw 32 bytes of fresh kernel entropy */
    if (entropy_read(fresh_entropy, CHACHA_KEY_BYTES) != 0) {
        /* FATAL: cannot reseed.  Abort rather than continue with
         * potentially compromised state. */
        explicit_bzero(st->key, CHACHA_KEY_BYTES);
        st->initialized = 0;
        explicit_bzero(fresh_entropy, sizeof(fresh_entropy));
        return -1;
    }

    /* new_key = HKDF-Extract(key=old_key, data=fresh_entropy)
     * This ensures backtracking resistance (§7). */
    uint8_t new_key[CHACHA_KEY_BYTES];
    hkdf_extract_sha512(st->key, CHACHA_KEY_BYTES,
                        fresh_entropy, CHACHA_KEY_BYTES,
                        new_key);

    /* Zero old key before overwriting */
    explicit_bzero(st->key, CHACHA_KEY_BYTES);
    memcpy(st->key, new_key, CHACHA_KEY_BYTES);
    explicit_bzero(new_key, sizeof(new_key));
    explicit_bzero(fresh_entropy, sizeof(fresh_entropy));

    /* Reset counter to 0 */
    memset(st->counter, 0, CHACHA_CTR_BYTES);

    /* Clear and refill output buffer */
    explicit_bzero(st->buf, CHACHA_BUF_BYTES);
    chacha20_block(st->key, st->counter, st->buf);
    increment_counter(st->counter);
    st->buf_pos = 0;

    /* Reset bookkeeping */
    st->outputs_since_reseed = 0;
    st->seed_pid = getpid();
    read_boot_id(st->boot_id, sizeof(st->boot_id));

    return 0;
}
```

### 4.4 Haskell Reseed

```haskell
reseedCSPRNG :: CSPRNGState -> IO ()
reseedCSPRNG st = do
    freshEntropy <- getEntropy 32
    oldKey <- readIORef (csprngKey st)

    -- new_key = HKDF-Extract(key=old_key, data=fresh_entropy)
    let newKey = hkdfExtractSHA512 oldKey freshEntropy

    -- Zero old key (overwrite IORef contents)
    writeIORef (csprngKey st) newKey
    zeroize oldKey

    -- Reset counter
    writeIORef (csprngCounter st) 0

    -- Clear and refill buffer
    buf <- readIORef (csprngBuf st)
    zeroize buf
    let newBuf = chacha20Block newKey (encode128 0)
    writeIORef (csprngBuf st) newBuf
    writeIORef (csprngBufPos st) 0

    -- Reset bookkeeping
    writeIORef (csprngOutputCount st) 0
    pid <- getPID
    writeIORef (csprngSeedPid st) pid
    bootId <- readBootId
    writeIORef (csprngBootId st) bootId

    zeroize freshEntropy
```

---

## 5. Fork Safety

### 5.1 Threat Model

After `fork()`, the child process inherits an exact copy of the parent's
CSPRNG state.  If both parent and child continue generating output without
reseeding, they produce identical byte streams.  Every key, nonce, and
random value is shared, enabling trivial cryptanalysis.

### 5.2 Detection: PID Check Before Every Output

Every call to `csprng_generate()` compares the current PID to the PID
recorded at the last seed/reseed.  On mismatch, the CSPRNG reseeds
before producing any output.

```c
/* Called at the top of csprng_generate() — see §3.4 */
if (getpid() != st->seed_pid) {
    if (csprng_reseed(st) != 0)
        return -1;
}
```

### 5.3 getpid() Caching Issues

**Historical problem:** glibc cached `getpid()` and did not always
invalidate the cache after `fork()` in multithreaded programs.  This was
fixed in glibc 2.25 (2017).

**Requirement:** The implementation MUST either:

1. Use glibc ≥ 2.25 (where `getpid()` always issues the syscall), or
2. Call `syscall(SYS_getpid)` directly to bypass any userspace cache.

```c
#include <sys/syscall.h>
#include <unistd.h>

static inline pid_t safe_getpid(void) {
    return (pid_t)syscall(SYS_getpid);
}
```

### 5.4 Buffer Clearing on Fork Reseed

On fork-triggered reseed, the output buffer MUST be zeroed before refill.
This prevents the child from serving any bytes that the parent might also
serve:

```c
/* Inside csprng_reseed(), the buffer is unconditionally cleared: */
explicit_bzero(st->buf, CHACHA_BUF_BYTES);
```

### 5.5 pthread_atfork() as Defence in Depth

As a secondary defence, register a `pthread_atfork()` handler that marks
the CSPRNG as requiring reseed:

```c
static void csprng_atfork_child(void) {
    /* Force reseed on next generate call.  We cannot reseed here
     * because the child's signal mask and lock state are undefined
     * immediately after fork in a multithreaded parent. */
    global_csprng.seed_pid = 0;  /* guaranteed mismatch */
}

/* During library initialization: */
pthread_atfork(NULL, NULL, csprng_atfork_child);
```

---

## 6. VM Clone Detection

### 6.1 boot_id Comparison

`/proc/sys/kernel/random/boot_id` is a UUID generated fresh at every
kernel boot.  If a VM snapshot is restored on a different host (or the
same host at a different boot), boot_id changes.

```c
static int read_boot_id(uint8_t *out, size_t out_len) {
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t r = read(fd, out, out_len);
    close(fd);
    return (r > 0) ? 0 : -1;
}

/* Check for VM clone: compare current boot_id against cached value.
 * Returns 1 if boot_id has changed (VM clone detected), 0 otherwise. */
static int detect_boot_id_change(struct csprng_state *st) {
    uint8_t current_boot_id[37];
    if (read_boot_id(current_boot_id, sizeof(current_boot_id)) != 0)
        return 0;  /* cannot read — no detection possible */
    return memcmp(current_boot_id, st->boot_id, 36) != 0;
}
```

**Limitation:** boot_id does NOT change when a VM is cloned and resumed
on the same boot instance.  This scenario requires additional detection.

### 6.2 RDTSC-Based Detection

On x86/x86_64, the TSC (Time Stamp Counter) increments monotonically.
A VM snapshot/restore creates a detectable discontinuity: the TSC after
restore is either reset or jumps forward by an anomalous amount.

```c
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>

static uint64_t last_tsc = 0;

/* Returns 1 if a TSC anomaly is detected (possible VM clone/resume). */
static int detect_tsc_anomaly(void) {
    uint64_t now = __rdtsc();
    if (last_tsc == 0) {
        last_tsc = now;
        return 0;
    }

    uint64_t prev_tsc = last_tsc;
    last_tsc = now;
    uint64_t delta = now - prev_tsc;

    /* Normal inter-call delta: < 2^{32} cycles (~1 second at 4 GHz).
     * A suspend/resume or clone causes delta >> 2^{32} or wraps. */
    if (delta > (1ULL << 40) || now < prev_tsc) {
        return 1;  /* anomaly detected */
    }
    return 0;
}
#endif
```

### 6.3 Clock Jump Detection

Monitor `CLOCK_MONOTONIC` for jumps that exceed a configurable threshold
(default: 60 seconds since the last CSPRNG call).  A jump indicates
suspend/resume:

```c
#include <time.h>

#define CLOCK_JUMP_THRESHOLD_NS (60ULL * 1000000000ULL)  /* 60 seconds */

static struct timespec last_clock = {0, 0};

static int detect_clock_jump(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (last_clock.tv_sec == 0 && last_clock.tv_nsec == 0) {
        last_clock = now;
        return 0;
    }

    int64_t delta_ns = (int64_t)(now.tv_sec - last_clock.tv_sec) * 1000000000LL
                     + (int64_t)(now.tv_nsec - last_clock.tv_nsec);
    last_clock = now;

    /* Negative delta: clock went backwards (VM restore with older snapshot) */
    if (delta_ns < 0 || (uint64_t)delta_ns > CLOCK_JUMP_THRESHOLD_NS) {
        return 1;
    }
    return 0;
}
```

### 6.4 Integrated Clone/Resume Check

```c
/* Called at the top of csprng_generate(), after PID check */
static int check_vm_clone(struct csprng_state *st) {
    int needs_reseed = 0;

    if (detect_boot_id_change(st))
        needs_reseed = 1;

#if defined(__x86_64__) || defined(__i386__)
    if (detect_tsc_anomaly())
        needs_reseed = 1;
#endif

    if (detect_clock_jump())
        needs_reseed = 1;

    if (needs_reseed)
        return csprng_reseed(st);

    return 0;
}
```

---

## 7. Backtracking Resistance

### 7.1 Definition

Backtracking resistance (NIST SP 800-90A §8.8): after a reseed, an
adversary who compromises the current CSPRNG state cannot recover any
output generated before the most recent reseed.

### 7.2 Mechanism

At reseed, the new key is derived as:

```
new_key = HKDF-Extract(key = old_key, data = fresh_entropy)
```

The old key is then zeroed.  Recovering old_key from new_key requires
inverting HKDF-Extract, which is equivalent to inverting HMAC-SHA-512 —
infeasible under assumption A4.

### 7.3 Formal Statement

**Theorem 7.1 (Backtracking Resistance).**

Let S_i denote the CSPRNG state after the i-th reseed, and let O_i denote
the sequence of outputs between reseed i-1 and reseed i.  For any PPT
adversary A who learns S_i (the state after the i-th reseed):

```
|Pr[A(S_i) distinguishes O_{i-1} from random] - 1/2| ≤ Adv^PRF_{HMAC-SHA-512}(A')
```

**Proof.**

1. S_i.key = HKDF-Extract(S_{i-1}.key, e_i), where e_i is fresh entropy.
2. Under A4, HMAC-SHA-512 is a PRF.  Given fresh_entropy e_i (which has
   ≥ 256 bits of min-entropy from getrandom), the output of HKDF-Extract
   is computationally independent of the first argument (S_{i-1}.key)
   when modelled as a randomness extractor.
3. Therefore, knowing S_i.key reveals nothing about S_{i-1}.key.
4. Outputs O_{i-1} were generated as ChaCha20(S_{i-1}.key, counter),
   which is a PRF of S_{i-1}.key (assumption A6).
5. Without S_{i-1}.key, A's distinguishing advantage is at most
   Adv^PRF_{HMAC-SHA-512}(A').  □

### 7.4 Zeroing Protocol

After reseed, the following memory regions are unconditionally zeroed
via `explicit_bzero()` (which is immune to compiler dead-store
elimination):

1. The old key (32 bytes)
2. The fresh_entropy buffer (32 bytes)
3. The intermediate new_key buffer (32 bytes)
4. The old output buffer (64 bytes)

---

## 8. Prediction Resistance

### 8.1 Definition

Prediction resistance (NIST SP 800-90A §8.8): even if the adversary
knows the CSPRNG state at time t, they cannot predict outputs after the
next reseed at time t' > t, because the reseed mixes fresh entropy that
the adversary does not know.

### 8.2 Mechanism

At each reseed, fresh entropy from getrandom() — which draws from the
kernel's interrupt-driven entropy accumulator — is mixed into the state.
The adversary must predict the kernel entropy to predict post-reseed
output.

### 8.3 Formal Statement

**Theorem 8.1 (Prediction Resistance).**

Let S_i denote the state after reseed i, and suppose the adversary learns
S_{i-1} (the state before reseed i).  For any PPT adversary A:

```
|Pr[A(S_{i-1}) predicts any byte of O_i] - 1/256| ≤ Adv^PRF_{ChaCha20}(A') + 2^{-256}
```

where 2^{-256} bounds the probability of guessing the 256-bit fresh
entropy.

**Proof.**

1. At reseed i, the new key is S_i.key = HKDF-Extract(S_{i-1}.key, e_i).
2. The adversary knows S_{i-1}.key but not e_i (256 bits from getrandom).
3. HKDF-Extract is a PRF keyed by S_{i-1}.key.  Under A4, its output on
   unknown input e_i is indistinguishable from random.
4. Outputs O_i = ChaCha20(S_i.key, 0), ChaCha20(S_i.key, 1), ...
   Under A6 (ChaCha20 PRF), these are indistinguishable from random given
   a random key.
5. Total advantage: Adv^PRF_{HMAC}(A') + Adv^PRF_{ChaCha20}(A'') + 2^{-256}.
   The 2^{-256} term is the probability of guessing e_i.  □

### 8.4 Continuous Reseeding and Entropy Accumulation

The periodic reseed (every 2^20 outputs) ensures that even an adversary
who compromises the state recovers it for at most 2^20 bytes of output.
After the next reseed, prediction resistance is restored.

---

## 9. Output Bias Testing

### 9.1 NIST SP 800-22 Test Suite

Before deployment and during CI, the CSPRNG output MUST pass the NIST
SP 800-22 statistical test suite.  The following tests are mandatory:

| Test | Purpose | Failure Threshold |
|------|---------|-------------------|
| Frequency (Monobit) | Global bias towards 0 or 1 | p-value < 0.01 |
| Block Frequency | Per-block bias | p-value < 0.01 |
| Runs | Monotone run lengths | p-value < 0.01 |
| Longest Run of Ones | Maximum run in block | p-value < 0.01 |
| Serial | 2-bit pattern distribution | p-value < 0.01 |
| Approximate Entropy | Entropy rate estimation | p-value < 0.01 |
| Cumulative Sums | Cumulative deviation from expected | p-value < 0.01 |
| Random Excursions | Random walk properties | p-value < 0.01 |

**Test parameters:** 1,000,000 bits per test sequence, 100 sequences,
proportion of sequences passing each test must be ≥ 96%.

### 9.2 Runtime Health Checks

The CSPRNG performs continuous self-tests during operation:

```c
/* Stuck-output detection: check that consecutive 64-byte blocks differ */
static int health_check_stuck(const uint8_t *prev_buf,
                               const uint8_t *cur_buf) {
    /* If two consecutive blocks are identical, the CSPRNG is broken */
    if (memcmp(prev_buf, cur_buf, CHACHA_BUF_BYTES) == 0)
        return -1;  /* FATAL */
    return 0;
}

/* Repetition detection: check that no 32-bit word repeats more than
 * 5 times in the last 256 outputs (birthday threshold for 32-bit). */
static int health_check_repetition(const uint32_t *recent, size_t count) {
    /* Simple sorted-duplicate check over the last `count` words.
     * A more efficient approach uses a hash set. */
    for (size_t i = 0; i < count; i++) {
        int seen = 0;
        for (size_t j = i + 1; j < count; j++) {
            if (recent[i] == recent[j])
                seen++;
        }
        if (seen >= 5)
            return -1;  /* FATAL — statistical impossibility */
    }
    return 0;
}
```

**On health check failure:** The CSPRNG state is zeroed and the process
aborts.  There is no recovery — a stuck or heavily biased CSPRNG
indicates a fundamental implementation or hardware error.

### 9.3 Haskell Runtime Check

```haskell
-- | Verify that two consecutive ChaCha20 blocks differ.
-- A match indicates catastrophic CSPRNG failure.
healthCheckStuck :: ByteString -> ByteString -> IO ()
healthCheckStuck prev cur
    | prev == cur = die "FATAL: CSPRNG stuck — consecutive identical blocks"
    | otherwise   = pure ()
```

---

## 10. Thread Safety

### 10.1 Options

| Approach | Pros | Cons |
|----------|------|------|
| Locked global instance | Simple, one reseed schedule | Lock contention under load |
| Per-thread instances | No contention, linear scaling | Each thread needs independent seeding; N × memory |
| Striped pool (N instances, thread hashes to slot) | Reduced contention, bounded memory | More complex; partial contention |

### 10.2 Recommendation: Per-Thread Instances

UmbraVox SHOULD use per-thread CSPRNG instances.  Each thread initializes
its own `csprng_state` from `getrandom()` at thread creation.  This
eliminates lock contention entirely and guarantees that no two threads
share CSPRNG state, even momentarily.

```c
#include <pthread.h>

static pthread_key_t csprng_key;
static pthread_once_t csprng_once = PTHREAD_ONCE_INIT;

static void csprng_thread_destroy(void *ptr) {
    struct csprng_state *st = (struct csprng_state *)ptr;
    explicit_bzero(st, sizeof(*st));
    free(st);
}

static void csprng_init_key(void) {
    pthread_key_create(&csprng_key, csprng_thread_destroy);
}

struct csprng_state *csprng_get_thread_local(void) {
    pthread_once(&csprng_once, csprng_init_key);

    struct csprng_state *st = pthread_getspecific(csprng_key);
    if (st == NULL) {
        st = calloc(1, sizeof(*st));
        if (st == NULL || csprng_init(st) != 0) {
            die("FATAL: cannot initialize per-thread CSPRNG");
        }
        pthread_setspecific(csprng_key, st);
    }
    return st;
}
```

### 10.3 Haskell Thread Safety

In Haskell, use a thread-local `CSPRNGState` stored in an `IORef` accessed
via `unsafePerformIO`-initialized `ThreadId`-keyed `Map`, or more
idiomatically, pass the CSPRNG state through the application monad:

```haskell
-- | Thread-local CSPRNG via the application monad.
newtype UmbraVoxM a = UmbraVoxM (ReaderT CSPRNGState IO a)
    deriving (Functor, Applicative, Monad, MonadIO)

-- | Run an action with a fresh per-thread CSPRNG.
withCSPRNG :: UmbraVoxM a -> IO a
withCSPRNG (UmbraVoxM action) = do
    st <- initCSPRNG  -- seeds from getrandom()
    runReaderT action st

-- | Get random bytes within the UmbraVoxM monad.
getRandomBytes :: Int -> UmbraVoxM ByteString
getRandomBytes n = UmbraVoxM $ do
    st <- ask
    liftIO $ generateCSPRNG st n
```

### 10.4 Fork + Threads Interaction

`fork()` in a multithreaded process is inherently dangerous (only the
calling thread survives; all mutexes are in undefined state).  UmbraVox
nodes SHOULD NOT fork after creating threads.  If fork is unavoidable,
the `pthread_atfork()` child handler (§5.5) forces reseed on the next
CSPRNG call, and the per-thread instances of dead threads are abandoned
(their memory is leaked — acceptable for a post-fork child that will
typically exec() or exit()).

---

## 11. Failure Modes and Recovery

### 11.1 Failure Classification

| Failure | Severity | Action |
|---------|----------|--------|
| `getrandom()` returns `ENOSYS` | Fatal | Process abort — kernel too old |
| `getrandom()` returns `EFAULT` | Fatal | Process abort — memory corruption |
| `getrandom()` interrupted (`EINTR`) | Transient | Retry (handled in `entropy_read()` loop) |
| `getrandom()` returns short read | Transient | Loop until full (handled in `entropy_read()`) |
| ChaCha20 produces identical consecutive blocks | Fatal | Zero state, abort |
| Counter overflow (2^128 blocks without reseed) | Impossible | 2^128 blocks at 64 bytes each = 2^134 bytes — cannot happen |
| State corruption (bit flip in key or counter) | Detected by health checks | Zero state, abort |
| `/proc/sys/kernel/random/boot_id` unreadable | Degraded | Lose VM clone detection; log warning, continue |

### 11.2 Fatal Failure Protocol

On any fatal failure:

```c
static _Noreturn void csprng_fatal(struct csprng_state *st,
                                    const char *reason) {
    /* 1. Zero all sensitive state */
    if (st != NULL)
        explicit_bzero(st, sizeof(*st));

    /* 2. Log the reason (no secrets in the message) */
    fprintf(stderr, "CSPRNG FATAL: %s\n", reason);

    /* 3. Abort — do not attempt recovery */
    abort();
}
```

### 11.3 What MUST NOT Happen

The following fallback strategies are explicitly prohibited:

1. **Time-based seeding:** `seed = time(NULL)` gives ~30 bits of entropy
   (seconds since epoch, predictable to within a day).  This is broken
   by brute force in under a second.

2. **PID-based seeding:** PIDs are 15–22 bits, fully enumerable.

3. **Reduced output on degraded entropy:** If entropy quality cannot be
   verified, the correct response is to block or abort, never to emit
   output with a disclaimer.

4. **Silent degradation:** The CSPRNG MUST NOT continue operating after
   any failure that could compromise output quality.  Crash-fail is the
   only safe mode.

---

## 12. Formal Entropy Accumulation Proof

### 12.1 Setup

Let the CSPRNG undergo k reseeds.  At reseed i, the fresh entropy e_i
drawn from `getrandom()` has min-entropy H_∞(e_i) ≥ h bits (where h = 256
under normal kernel operation).

The reseed operation is:

```
key_i = HKDF-Extract(key_{i-1}, e_i)
```

where HKDF-Extract(salt, ikm) = HMAC-SHA-512(salt, ikm).

### 12.2 Entropy Accumulation Lemma

**Lemma 12.1 (Single Reseed Entropy).**

If e_i has min-entropy ≥ h and HMAC-SHA-512 is modelled as a
(t, ε_ext)-strong randomness extractor with seed key_{i-1}, then:

```
H_∞^comp(key_i) ≥ min(256, h) - log(1/ε_ext)
```

where H_∞^comp denotes computational min-entropy (HILL entropy).

**Proof.**

HKDF-Extract is instantiated as HMAC-SHA-512(key_{i-1}, e_i).  By the
leftover hash lemma applied to HMAC as a universal hash family keyed by
the salt (Krawczyk 2010, Theorem 1):

1. The output PRK = HMAC(key_{i-1}, e_i) is ε_ext-close to uniform over
   {0,1}^{512} when H_∞(e_i) ≥ 256 + 2·log(1/ε_ext).

2. We truncate PRK to 256 bits (the ChaCha20 key).  Truncation can only
   increase statistical distance by at most a factor of 1.

3. With h = 256 bits of min-entropy from getrandom() and ε_ext = 2^{-128}
   (target security parameter):

   Required: h ≥ 256 + 2·128 = 512 bits.

   The kernel provides h = 256 bits, which is less than the theoretical
   512-bit requirement for the leftover hash lemma with a 256-bit
   extractor output and 128-bit security.  However, under the
   computational assumption A4 (HMAC-SHA-512 is a PRF), we invoke the
   computational extractor argument:

4. Under A4, HMAC-SHA-512(key, ·) is a PRF.  For any input with
   min-entropy ≥ h, the PRF output is (t, ε)-computationally
   indistinguishable from uniform, where:

   ```
   ε ≤ 2^{-h} + Adv^PRF_{HMAC}(t)
   ```

5. With h = 256 and Adv^PRF_{HMAC} ≤ 2^{-127} (from Proof-01 §2):

   ```
   ε ≤ 2^{-256} + 2^{-127} ≈ 2^{-127}
   ```

Therefore H_∞^comp(key_i) ≥ 256 - log(1/2^{-127}) = 256 - 127 > 128 bits.

Under the PRF assumption, each reseed yields a key with ≥ 128 bits of
computational entropy, meeting the security target.  □

### 12.3 Multi-Reseed Entropy Accumulation

**Theorem 12.1 (Entropy Accumulation over k Reseeds).**

After k reseeds, each injecting h ≥ 256 bits of independent entropy, the
CSPRNG key has:

```
H_∞^comp(key_k) ≥ min(256, h) = 256 bits
```

with computational distance at most k · 2^{-127} from uniform.

**Proof.**

By induction on k:

**Base case (k = 0):** key_0 is drawn directly from getrandom() with
h ≥ 256 bits of min-entropy (after supplemental mixing via HKDF).
H_∞^comp(key_0) ≥ 256 with distance ε_0 = 0 (direct entropy source).

**Inductive step:** Assume key_{k-1} has H_∞^comp ≥ 256 bits with
distance ε_{k-1} from uniform.

At reseed k:
```
key_k = HKDF-Extract(key_{k-1}, e_k)
```

By Lemma 12.1, even if key_{k-1} is adversarially chosen (worst case for
the extractor), the fresh entropy e_k with h ≥ 256 bits ensures:

```
H_∞^comp(key_k) ≥ 256  with distance ε_k ≤ ε_{k-1} + 2^{-127}
```

The additional 2^{-127} comes from the PRF distinguishing advantage at
each reseed step.

After k reseeds:
```
ε_k ≤ k · 2^{-127}
```

For any practical k (even k = 2^{64} reseeds over the lifetime of the
universe), ε_k = 2^{64} · 2^{-127} = 2^{-63}, which is negligible.

For the UmbraVox reseed interval of 2^{20} outputs and a maximum node
lifetime of 2^{40} outputs (~10 years of continuous operation),
k ≤ 2^{20}, giving:

```
ε ≤ 2^{20} · 2^{-127} = 2^{-107}
```

This is well within the λ = 128 security target (the total distinguishing
advantage is below 2^{-100}).  □

### 12.4 Degraded Entropy Scenario

If the kernel entropy source is partially degraded and provides only
h' < 256 bits per reseed:

**Corollary 12.2.** After k independent reseeds each providing h' bits
of entropy:

```
H_∞^comp(key_k) ≥ min(256, h')
```

The entropy does NOT accumulate additively across reseeds when each reseed
independently provides sufficient entropy.  However, if each reseed
provides insufficient entropy (h' < 128), the CSPRNG is below the security
target regardless of k.

**This is why blocking at getrandom() until the kernel is fully seeded is
mandatory** — there is no way to "make up" for a low-entropy initial seed
through repeated low-entropy reseeds when using a PRF-based extractor.

---

## Appendix A: Complete Generate Path (Pseudocode)

```
FUNCTION csprng_generate(state, output_buffer, length):
    ASSERT state.initialized

    -- Fork safety (§5)
    IF safe_getpid() ≠ state.seed_pid THEN
        csprng_reseed(state) OR ABORT

    -- VM clone detection (§6)
    IF detect_boot_id_change(state) OR detect_tsc_anomaly() OR detect_clock_jump() THEN
        csprng_reseed(state) OR ABORT

    -- Reseed schedule (§4)
    IF state.outputs_since_reseed ≥ 2^20 THEN
        csprng_reseed(state) OR ABORT

    -- Generate output from buffered keystream (§3.4)
    WHILE bytes_remaining > 0 DO
        copy min(remaining, buffer_available) bytes
        IF buffer exhausted THEN
            prev_buf ← copy of state.buf
            state.buf ← ChaCha20(state.key, state.counter)
            increment(state.counter)
            health_check_stuck(prev_buf, state.buf) OR ABORT  -- §9.2
            zero(prev_buf)

    state.outputs_since_reseed += length
```

---

## Appendix B: Security Properties Summary

| Property | Mechanism | Formal Guarantee |
|----------|-----------|-----------------|
| Entropy quality | getrandom(flags=0) blocks until kernel seeded | ≥ 256 bits min-entropy |
| Backtracking resistance | HKDF(old_key, fresh) + zero old_key | Theorem 7.1: ≤ Adv^PRF_{HMAC} |
| Prediction resistance | Fresh entropy at each reseed | Theorem 8.1: ≤ Adv^PRF_{ChaCha20} + 2^{-256} |
| Fork safety | PID check + immediate reseed | Deterministic detection |
| VM clone safety | boot_id + RDTSC + clock jump | Best-effort detection |
| Thread safety | Per-thread instances | No shared mutable state |
| Output quality | NIST SP 800-22 + runtime health checks | Statistical + operational |
| Entropy accumulation | k reseeds with h-bit entropy each | Theorem 12.1: ε ≤ k · 2^{-127} |
| Failure mode | Crash-fail only — never degrade | No silent compromise |
