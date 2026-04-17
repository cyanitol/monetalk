# Hardening Spec 05: Ratchet State Protection

**Status:** Implementation specification
**Applies to:** `UmbraVox.Crypto.Signal.Ratchet`, `UmbraVox.Crypto.PQ.Wrapper`
**References:** `doc/03-cryptography.md` lines 122--145, `doc/10-security.md` line 23, `doc/proof-02-protocol-security.md` Theorems 2.1--2.2

---

## 1. State Inventory

The ratchet state contains the following sensitive fields. Every field
listed here MUST be treated as secret material subject to all protections
in this specification.

### 1.1 Signal Double Ratchet State

```haskell
data RatchetState = RatchetState
  { rsDHSend      :: !(X25519SecretKey, X25519PublicKey)
      -- ^ Current sending DH keypair.  Secret key is 32 bytes.
      --   Compromise: attacker can compute all future sending chain keys
      --   until next DH ratchet step.

  , rsDHRecv      :: !X25519PublicKey
      -- ^ Peer's current DH public key.  32 bytes.
      --   Not secret per se, but integrity-critical: tampering enables
      --   MITM on next ratchet step.

  , rsRootKey     :: !ByteString
      -- ^ Root key.  32 bytes.
      --   Compromise: attacker can derive all future chain keys
      --   (breaks forward secrecy completely for the session).

  , rsSendChain   :: !ByteString
      -- ^ Current sending chain key.  32 bytes.
      --   Compromise: attacker can derive all future sending message
      --   keys in the current chain (until next DH ratchet step).

  , rsRecvChain   :: !ByteString
      -- ^ Current receiving chain key.  32 bytes.
      --   Compromise: attacker can derive all future receiving message
      --   keys in the current chain (until next DH ratchet step).

  , rsSendN       :: !Word32
      -- ^ Sending message counter.  Monotonically increasing.
      --   Integrity-critical: replay if decremented.

  , rsRecvN       :: !Word32
      -- ^ Receiving message counter.  Monotonically increasing.
      --   Integrity-critical: replay if decremented.

  , rsPrevChainN  :: !Word32
      -- ^ Message count in previous sending chain.
      --   Integrity-critical for skipped key derivation.

  , rsSkippedKeys :: !(Map (X25519PublicKey, Word32) ByteString)
      -- ^ Cached message keys for out-of-order decryption.
      --   Each value is a 32-byte message key.
      --   Bounded: max 1,000 entries, evicted after 500 ratchet steps.
      --   Compromise: attacker can decrypt the specific skipped messages.
  }
```

### 1.2 PQ Outer Wrapper State

```haskell
data PQWrapperState = PQWrapperState
  { pqChainKey     :: !ByteString
      -- ^ Current PQ chain key.  32 bytes.
      --   Compromise: attacker can derive message keys for up to 50
      --   messages until next PQ ratchet refresh.

  , pqSendCounter  :: !Word32
      -- ^ Per-direction send counter for PQ ratchet refresh trigger.
      --   Integrity-critical: must reach 50 to trigger refresh.

  , pqRecvCounter  :: !Word32
      -- ^ Per-direction receive counter.

  , pqPeerEncapsKey :: !MLKEMPublicKey
      -- ^ Peer's current ML-KEM-768 public key.  1,184 bytes.
      --   Integrity-critical: tampering enables PQ MITM.

  , pqLocalDecapsKey :: !MLKEMSecretKey
      -- ^ Local ML-KEM-768 secret key.  2,400 bytes.
      --   Compromise: attacker can decapsulate incoming PQ ciphertexts.
  }
```

### 1.3 Combined Session State

```haskell
data SessionState = SessionState
  { ssSessionId   :: !ByteString     -- 32-byte unique session identifier
  , ssRatchet     :: !RatchetState
  , ssPQWrapper   :: !PQWrapperState
  , ssCreatedAt   :: !Word64         -- epoch timestamp
  , ssVersion     :: !Word16         -- serialization format version
  }
```

### 1.4 Sensitivity Classification

| Field | Confidentiality | Integrity | Size (bytes) |
|-------|:-:|:-:|--:|
| `rsDHSend` (secret key) | CRITICAL | CRITICAL | 32 |
| `rsDHSend` (public key) | LOW | CRITICAL | 32 |
| `rsDHRecv` | LOW | CRITICAL | 32 |
| `rsRootKey` | CRITICAL | CRITICAL | 32 |
| `rsSendChain` | CRITICAL | CRITICAL | 32 |
| `rsRecvChain` | CRITICAL | CRITICAL | 32 |
| `rsSendN` | LOW | CRITICAL | 4 |
| `rsRecvN` | LOW | CRITICAL | 4 |
| `rsPrevChainN` | LOW | CRITICAL | 4 |
| `rsSkippedKeys` (values) | HIGH | CRITICAL | 32 each |
| `pqChainKey` | CRITICAL | CRITICAL | 32 |
| `pqSendCounter` | LOW | CRITICAL | 4 |
| `pqRecvCounter` | LOW | CRITICAL | 4 |
| `pqPeerEncapsKey` | LOW | CRITICAL | 1,184 |
| `pqLocalDecapsKey` | CRITICAL | CRITICAL | 2,400 |

Total sensitive material per session (excluding skipped keys): ~3,828 bytes.
Maximum with 1,000 skipped keys: ~3,828 + 68,000 = ~71,828 bytes.

---

## 2. At-Rest Encryption

### 2.1 Key Derivation from User Passphrase

The storage encryption key is NEVER the passphrase itself. Derivation
uses a two-stage process:

```
Stage 1: Argon2id stretching
  passphrase_key = Argon2id(
    password  = user_passphrase,
    salt      = salt,           -- 16 bytes, from /dev/urandom
    t         = 3,              -- 3 iterations
    m         = 262144,         -- 256 MiB memory
    p         = 1,              -- 1 lane (single-threaded)
    tag_len   = 64              -- 64-byte output
  )

Stage 2: HKDF expansion for domain separation
  enc_key  = HKDF-Expand(
    PRK  = passphrase_key,
    info = "UmbraVox_RatchetStore_Enc_v1",
    L    = 32                   -- AES-256-GCM key
  )
  mac_key  = HKDF-Expand(
    PRK  = passphrase_key,
    info = "UmbraVox_RatchetStore_Mac_v1",
    L    = 32                   -- HMAC-SHA-256 key
  )
```

The Argon2id salt is stored in plaintext alongside the encrypted state
file. It does not need to be secret but MUST be unique per user and
regenerated on every passphrase change.

### 2.2 Encryption Scheme

```
Serialize:
  plaintext = CBOR.encode(SessionState)

Encrypt:
  nonce     = random 12 bytes from CSPRNG
  (ct, tag) = AES-256-GCM(enc_key, nonce, plaintext, aad="")

Authenticate:
  mac_input = version_byte || salt || nonce || ct || tag
  mac       = HMAC-SHA-256(mac_key, mac_input)

On-disk format:
  +--------+------+-------+----+-----+-----+
  | ver(1) | salt | nonce | ct | tag | mac |
  |  0x01  | (16) | (12)  |var | (16)|(32) |
  +--------+------+-------+----+-----+-----+
```

The version byte (`0x01`) is included in the MAC input and enables
future format migration (Section 8).

### 2.3 Decryption and Verification

```
1. Read file.  Parse version byte.
2. Verify HMAC:
     mac_input = version_byte || salt || nonce || ct || tag
     expected  = HMAC-SHA-256(mac_key, mac_input)
     if mac != expected: REJECT (integrity failure, Section 4.3)
3. Decrypt:
     plaintext = AES-256-GCM-Open(enc_key, nonce, ct, tag, aad="")
     if decryption fails (tag mismatch): REJECT
4. Deserialize:
     state = CBOR.decode(plaintext)
     Verify invariants (Section 10)
```

### 2.4 Passphrase Change

On passphrase change:
1. Decrypt state with old passphrase-derived keys.
2. Generate new salt from CSPRNG.
3. Derive new `enc_key`, `mac_key` from new passphrase + new salt.
4. Re-encrypt and re-MAC.
5. Atomic write (Section 5).
6. Securely erase old key material from memory.

---

## 3. In-Memory Protection

### 3.1 Memory Locking

All buffers containing CRITICAL or HIGH sensitivity fields (Section 1.4)
MUST be locked into physical memory to prevent paging to swap.

```c
// C FFI helper: allocate and lock a sensitive buffer
void* UmbraVox_secure_alloc(size_t len) {
    // Allocate with guard pages (Section 3.2)
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t alloc_size = len + 2 * page_size;  // guard pages on both sides
    alloc_size = ((alloc_size + page_size - 1) / page_size) * page_size;

    void* base = mmap(NULL, alloc_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;

    // Install guard pages: PROT_NONE at both ends
    mprotect(base, page_size, PROT_NONE);
    mprotect((char*)base + alloc_size - page_size, page_size, PROT_NONE);

    void* usable = (char*)base + page_size;
    size_t usable_size = alloc_size - 2 * page_size;

    // Lock into RAM
    if (mlock(usable, usable_size) != 0) {
        munmap(base, alloc_size);
        return NULL;  // Cannot guarantee no swap; fail hard
    }

    // Prevent core dumps of this region
    madvise(usable, usable_size, MADV_DONTDUMP);

    // Write canary (Section 3.3)
    install_canary(usable, usable_size);

    return usable;
}
```

```haskell
-- Haskell FFI binding
foreign import ccall "UmbraVox_secure_alloc"
    c_secure_alloc :: CSize -> IO (Ptr Word8)

foreign import ccall "UmbraVox_secure_free"
    c_secure_free :: Ptr Word8 -> CSize -> IO ()

-- Wrapper that ensures cleanup on exception
withSecureBuffer :: Int -> (Ptr Word8 -> IO a) -> IO a
withSecureBuffer len action = bracket
    (c_secure_alloc (fromIntegral len))
    (\ptr -> c_secure_free ptr (fromIntegral len))
    action
```

### 3.2 Guard Pages

Each sensitive allocation is surrounded by guard pages (PROT_NONE
regions) that trigger SIGSEGV on any access. This detects:
- Linear buffer overflows (write past end hits upper guard page)
- Underflows (write before start hits lower guard page)

The guard pages are installed in `UmbraVox_secure_alloc` above.

### 3.3 Canary Values

A 16-byte random canary is placed at the end of each usable region,
inside the allocation but after the declared data length. The canary is
checked on every access and on deallocation.

```c
#define CANARY_SIZE 16

static void install_canary(void* buf, size_t usable_size) {
    // Canary occupies last CANARY_SIZE bytes of the usable region.
    // Caller must account for this in their length calculations.
    uint8_t* canary_pos = (uint8_t*)buf + usable_size - CANARY_SIZE;
    // Fill with random bytes from CSPRNG
    csprng_fill(canary_pos, CANARY_SIZE);
    // Store expected value in a separate (non-sensitive) tracking structure
    canary_table_insert(buf, canary_pos, CANARY_SIZE);
}

static int verify_canary(void* buf) {
    const uint8_t* expected = canary_table_lookup(buf);
    if (expected == NULL) return -1;  // unknown buffer
    size_t usable_size = alloc_table_get_size(buf);
    const uint8_t* actual = (const uint8_t*)buf + usable_size - CANARY_SIZE;
    // Constant-time comparison
    return ct_memcmp(expected, actual, CANARY_SIZE);
}
```

Canary verification failure triggers:
1. Immediate session termination.
2. Secure erasure of all session state.
3. Logging of a CANARY_VIOLATION event (no secret data in the log).
4. Forced re-establishment of the session (Section 4.3).

### 3.4 Secure Erasure on Free

```c
void UmbraVox_secure_free(void* usable, size_t len) {
    if (usable == NULL) return;

    // Verify canary before erasure (detect corruption)
    if (verify_canary(usable) != 0) {
        // Log corruption event; do NOT abort before erasing
    }

    // Overwrite with zeros -- use volatile to prevent optimization
    volatile uint8_t* p = (volatile uint8_t*)usable;
    for (size_t i = 0; i < len; i++) {
        p[i] = 0;
    }

    // Memory barrier to ensure writes complete
    __asm__ __volatile__("" ::: "memory");

    // Unlock and unmap
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void* base = (char*)usable - page_size;
    size_t rounded = ((len + 2 * page_size + page_size - 1) / page_size) * page_size;
    munlock(usable, len);
    munmap(base, rounded);

    canary_table_remove(usable);
}
```

### 3.5 GHC Runtime Considerations

The GHC garbage collector can copy Haskell heap objects during
compaction, leaving copies of sensitive data in freed heap regions.
Mitigations:

1. **All CRITICAL fields are stored in C-allocated pinned buffers**
   via the FFI, never as regular Haskell `ByteString` values on the
   GC heap.
2. The Haskell `RatchetState` record holds `ForeignPtr Word8` pointers
   to C-managed memory, not inline `ByteString` values.
3. `ForeignPtr` finalizers call `UmbraVox_secure_free`.

```haskell
-- Sensitive key wrapper
newtype SecureKey = SecureKey (ForeignPtr Word8)

mkSecureKey :: ByteString -> IO SecureKey
mkSecureKey bs = do
    let len = BS.length bs
    ptr <- c_secure_alloc (fromIntegral (len + CANARY_SIZE))
    when (ptr == nullPtr) $ fail "secure_alloc failed: cannot lock memory"
    BS.useAsCStringLen bs $ \(src, srcLen) ->
        copyBytes ptr (castPtr src) srcLen
    fptr <- newForeignPtr c_secure_free_funptr ptr
    return (SecureKey fptr)
```

---

## 4. Integrity Verification

### 4.1 On-Disk HMAC

Every persisted state file carries an HMAC-SHA-256 tag computed over
the entire ciphertext (Section 2.2). This is verified on every load
BEFORE decryption.

### 4.2 In-Memory Integrity

On every ratchet operation (encrypt, decrypt, DH ratchet step, PQ
refresh), the following checks run:

```haskell
verifyStateIntegrity :: SessionState -> Either IntegrityError ()
verifyStateIntegrity st = do
    -- Counter overflow check (Section 10, Invariant 1)
    when (rsSendN (ssRatchet st) >= maxBound) $
        Left CounterOverflow

    -- Skipped key bound
    when (Map.size (rsSkippedKeys (ssRatchet st)) > 1000) $
        Left SkippedKeyOverflow

    -- Key length checks
    when (BS.length (rsRootKey (ssRatchet st)) /= 32) $
        Left InvalidKeyLength

    when (BS.length (rsSendChain (ssRatchet st)) /= 32) $
        Left InvalidKeyLength

    when (BS.length (rsRecvChain (ssRatchet st)) /= 32) $
        Left InvalidKeyLength

    when (BS.length (pqChainKey (ssPQWrapper st)) /= 32) $
        Left InvalidKeyLength

    -- Canary verification for all C-backed buffers
    -- (performed via FFI call to verify_canary)
```

### 4.3 Corruption Detection and Recovery

If any integrity check fails (HMAC mismatch, canary violation,
invariant violation, deserialization failure):

```
1. LOG corruption event with:
     - session_id (not secret: it is a hash, not a key)
     - failure_type enum
     - timestamp
   NO secret material is logged.

2. ERASE all in-memory state for the affected session:
     - Call UmbraVox_secure_free on every SecureKey
     - Zero the SessionState record

3. DELETE the corrupted on-disk state file (after secure deletion
   per Section 9).

4. MARK the session as TERMINATED.

5. REQUIRE new PQXDH key agreement to re-establish the session.
   The peer is notified via a SESSION_RESET message (unauthenticated,
   since keys are gone -- the peer must verify via identity key
   fingerprint comparison out-of-band).
```

There is no "partial recovery" or "rollback to last good state."
Any corruption is treated as a potential compromise and the session
is destroyed.

---

## 5. Atomic State Updates

### 5.1 Problem

A crash during state write can leave a partially-written file. If the
old state is lost and the new state is incomplete, the session is
unrecoverable. Worse, a half-written state could violate invariants
(e.g., counter advanced but chain key not updated), leading to
key reuse.

### 5.2 Rename-Based Atomic Writes

```
Write procedure:
  1. Serialize and encrypt new state to a temporary file in the
     same directory:
       path_tmp = state_dir </> session_id <> ".tmp." <> random_suffix

  2. fsync(fd_tmp)  -- ensure data reaches durable storage

  3. rename(path_tmp, path_final)  -- atomic on POSIX filesystems
     path_final = state_dir </> session_id <> ".state"

  4. fsync(state_dir_fd)  -- ensure directory entry is durable
```

```c
int atomic_state_write(const char* dir, const char* session_id,
                       const uint8_t* data, size_t len) {
    char tmp_path[PATH_MAX];
    char final_path[PATH_MAX];
    uint8_t suffix[8];

    csprng_fill(suffix, sizeof(suffix));
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%016llx",
             dir, session_id, *(uint64_t*)suffix);
    snprintf(final_path, sizeof(final_path), "%s/%s.state",
             dir, session_id);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;

    ssize_t written = write(fd, data, len);
    if (written != (ssize_t)len) { close(fd); unlink(tmp_path); return -1; }

    if (fsync(fd) != 0) { close(fd); unlink(tmp_path); return -1; }
    close(fd);

    if (rename(tmp_path, final_path) != 0) { unlink(tmp_path); return -1; }

    // fsync the directory
    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) { fsync(dir_fd); close(dir_fd); }

    return 0;
}
```

### 5.3 Write-Ahead Sequencing

Each state write carries a monotonic sequence number:

```haskell
data StateEnvelope = StateEnvelope
  { seqNum  :: !Word64       -- monotonically increasing per session
  , payload :: !ByteString   -- encrypted SessionState
  }
```

On load, if two files exist (`.state` and `.tmp.*`), the one with the
higher `seqNum` (after successful HMAC verification) wins. The loser
is deleted. If neither verifies, the session is terminated (Section 4.3).

### 5.4 Ratchet-Then-Persist Ordering

State MUST be persisted BEFORE the ratchet output (plaintext or
ciphertext) is returned to the application layer. This ensures:
- If the process crashes after persisting but before delivering the
  plaintext, the state reflects the advanced ratchet. The message can
  be re-decrypted by the peer retransmitting.
- If the process crashes before persisting, the old state is intact
  and the ratchet step is retried on the retransmitted message.

Key reuse (same message key encrypting two different plaintexts) is
impossible under this ordering because the chain key advances
atomically with the persist.

---

## 6. Backup and Recovery

### 6.1 What Can Be Recovered

| Scenario | Recovery |
|----------|----------|
| State file intact, passphrase known | Normal load and resume |
| State file lost, passphrase known | Session CANNOT be recovered; new PQXDH required |
| State file intact, passphrase lost | Session CANNOT be recovered; new PQXDH required |
| State file corrupted | Session terminated; new PQXDH required |

Ratchet state is ephemeral by design. Loss of ratchet state is
equivalent to loss of session: the peer must be contacted and a
fresh PQXDH key agreement performed.

### 6.2 No Plaintext Backups

Ratchet state MUST NEVER be backed up in plaintext form:
- System backup tools (rsync, Time Machine, etc.) MUST exclude the
  state directory.
- The state directory SHOULD be placed on an encrypted filesystem
  (e.g., dm-crypt/LUKS) as a defense-in-depth measure.
- Cloud sync (Dropbox, iCloud, etc.) MUST be disabled for the state
  directory.

### 6.3 Encrypted Backup (Optional)

If the user explicitly opts into encrypted state backup:
1. The backup is encrypted with a separate backup key derived from
   a separate passphrase (NOT the storage passphrase).
2. The backup key derivation uses the same Argon2id parameters as
   Section 2.1 but with a distinct info string:
   `"UmbraVox_RatchetBackup_Enc_v1"`.
3. The backup is a point-in-time snapshot. Restoring from backup
   rewinds the ratchet, which means:
   - Messages sent between backup and restore are lost.
   - The peer's ratchet has advanced past the backup point,
     causing desynchronization.
   - A SESSION_RESET and new PQXDH are almost always required anyway.
4. Backup frequency: at most once per 24 hours. More frequent backups
   increase the window for replay attacks.

---

## 7. Multi-Device Considerations

### 7.1 Ratchet State Is Device-Specific

Ratchet state CANNOT be shared across devices. Sharing would:
- Break forward secrecy: two devices holding the same chain key means
  compromise of either device reveals the same messages.
- Break ratchet synchronization: two devices advancing the same chain
  independently will diverge, producing key mismatches.
- Violate counter monotonicity: two devices incrementing the same
  counter independently will produce colliding (message_counter,
  ratchet_public_key) pairs, causing nonce reuse in AES-GCM.

### 7.2 Sesame Protocol for Multi-Device

Multi-device support uses the Sesame protocol (Signal's multi-device
architecture):

```
Device model:
  - Each device has its own identity key, prekey bundle, and ratchet state.
  - A user's "identity" is the set of device identity keys, linked by
    a signed device list.
  - Sending a message to a user means encrypting it N times, once per
    device, each with an independent ratchet session.

Per-device session:
  Alice_phone  <-> Bob_phone    (independent ratchet)
  Alice_phone  <-> Bob_laptop   (independent ratchet)
  Alice_laptop <-> Bob_phone    (independent ratchet)
  Alice_laptop <-> Bob_laptop   (independent ratchet)

Scaling:  O(sender_devices * recipient_devices) sessions.
```

### 7.3 Device Revocation

When a device is lost or compromised:
1. The user publishes a KEY_REVOKE transaction listing the revoked
   device's identity key.
2. All peers terminate sessions with the revoked device.
3. No ratchet state migration occurs -- the revoked device's state
   is considered compromised and abandoned.

---

## 8. State Migration

### 8.1 Versioned Serialization

Every on-disk state file begins with a version byte (Section 2.2).
The current version is `0x01`.

```haskell
data StateVersion
  = V1   -- Initial format: CBOR-encoded SessionState
  -- Future versions added here
  deriving (Eq, Ord, Show)

parseVersion :: Word8 -> Maybe StateVersion
parseVersion 0x01 = Just V1
parseVersion _    = Nothing
```

### 8.2 Migration Procedure

When the software version expects format V(n+1) but reads V(n):

```
1. Decrypt the file using V(n) format parser.
2. Validate all invariants (Section 10) against V(n) schema.
3. Transform V(n) state into V(n+1) state:
     - New fields receive defined default values.
     - Removed fields are discarded after extracting any needed data.
     - Field type changes apply documented conversion functions.
4. Re-encrypt under V(n+1) format.
5. Atomic write (Section 5).
6. Securely delete V(n) file (Section 9).
```

### 8.3 Migration Rules

- Migrations are forward-only. Downgrading is not supported.
- Each migration step is a pure function: `migrate_vN_to_vN1 :: StateVN -> StateVN1`.
- Migration functions are retained in the codebase indefinitely to
  support upgrades from any prior version.
- If migration fails (invariant violation in the transformed state),
  the session is terminated and new PQXDH is required.

### 8.4 Example Migration: V1 to V2

```haskell
-- Hypothetical: V2 adds a PQ ratchet epoch counter
data SessionStateV2 = SessionStateV2
  { ssV2SessionId   :: !ByteString
  , ssV2Ratchet     :: !RatchetState      -- unchanged
  , ssV2PQWrapper   :: !PQWrapperStateV2  -- adds pqEpoch field
  , ssV2CreatedAt   :: !Word64
  , ssV2Version     :: !Word16            -- = 2
  }

migrateV1toV2 :: SessionState -> SessionStateV2
migrateV1toV2 v1 = SessionStateV2
  { ssV2SessionId  = ssSessionId v1
  , ssV2Ratchet    = ssRatchet v1
  , ssV2PQWrapper  = addEpoch (ssPQWrapper v1)
  , ssV2CreatedAt  = ssCreatedAt v1
  , ssV2Version    = 2
  }
  where
    addEpoch pq = PQWrapperStateV2
      { pqV2ChainKey      = pqChainKey pq
      , pqV2SendCounter   = pqSendCounter pq
      , pqV2RecvCounter   = pqRecvCounter pq
      , pqV2PeerEncapsKey = pqPeerEncapsKey pq
      , pqV2LocalDecapsKey = pqLocalDecapsKey pq
      , pqV2Epoch         = 0  -- default: epoch 0
      }
```

---

## 9. Secure Deletion

### 9.1 File System Challenges

Secure deletion on modern file systems and storage hardware is
fundamentally unreliable:

| Medium | Problem |
|--------|---------|
| ext4 (journaling) | Journal may retain old data blocks; `data=journal` mode copies data blocks to journal before writing |
| Btrfs/ZFS (COW) | Old data persists in previous snapshots and COW blocks |
| SSD (wear leveling) | Controller remaps logical blocks; overwritten logical block does not erase the physical NAND cell |
| SSD (TRIM) | TRIM hints are advisory; controller may defer or ignore |
| tmpfs | No persistence concern but swap may capture pages (mitigated by mlock in Section 3) |

### 9.2 Encrypted Container Approach

Because reliable overwrite-in-place is impossible on modern storage,
the primary defense is that ratchet state is NEVER stored in plaintext
on disk:

```
Defense in depth (layered):

Layer 1: Application-level encryption (Section 2)
  State is AES-256-GCM encrypted with passphrase-derived key.
  Even if old ciphertext blocks persist in journal/COW/wear-leveling
  remnants, they are encrypted.

Layer 2: Full-disk encryption (recommended, not enforced)
  dm-crypt/LUKS, FileVault, BitLocker.
  Remnant ciphertext blocks from Layer 1 are additionally encrypted.

Layer 3: Best-effort overwrite before unlink
  Overwrite file contents with random data before unlinking.
  This is NOT reliable (see table above) but costs nothing.
```

### 9.3 Best-Effort Deletion Procedure

```c
int secure_delete_file(const char* path) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return -1; }
    size_t len = (size_t)st.st_size;

    // Overwrite with random data (single pass -- multi-pass is
    // security theater on modern drives)
    uint8_t buf[4096];
    size_t remaining = len;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(buf) ? remaining : sizeof(buf);
        csprng_fill(buf, chunk);
        write(fd, buf, chunk);
        remaining -= chunk;
    }

    fsync(fd);
    close(fd);

    // Unlink the file
    unlink(path);

    // Overwrite the buf on stack
    volatile uint8_t* vbuf = (volatile uint8_t*)buf;
    for (size_t i = 0; i < sizeof(buf); i++) vbuf[i] = 0;

    return 0;
}
```

### 9.4 SSD TRIM Consideration

After `unlink()`, issue `FITRIM` on the containing filesystem mount
to hint the SSD controller that the blocks are no longer needed.
This is advisory -- the controller may or may not erase the NAND cells.
The encrypted container approach (Section 9.2) is the actual defense.

---

## 10. Formal Invariants

The following invariants MUST hold at every observable state transition.
Violation of any invariant triggers session termination (Section 4.3).

### Invariant 1: Counter Monotonicity

```
For all state transitions S -> S':
  rsSendN(S') >= rsSendN(S)
  rsRecvN(S') >= rsRecvN(S)
  pqSendCounter(S') >= pqSendCounter(S)
  pqRecvCounter(S') >= pqRecvCounter(S)
  seqNum(S') > seqNum(S)      -- on-disk sequence number is strictly increasing
```

Counters NEVER decrease. A decrement indicates replay, corruption,
or rollback attack.

### Invariant 2: Key Freshness

```
After a DH ratchet step producing state S':
  rsDHSend(S') != rsDHSend(S)         -- new keypair generated
  rsRootKey(S') != rsRootKey(S)       -- root key advanced
  rsSendChain(S') != rsSendChain(S)   -- new chain key derived

After a PQ ratchet refresh producing state S':
  pqChainKey(S') != pqChainKey(S)     -- new PQ chain key derived
```

Key freshness ensures that the ratchet actually advances. A stale key
after a ratchet step indicates a failure in key derivation.

### Invariant 3: Chain Consistency

```
For sending chain:
  rsSendChain(S) is derived from rsRootKey(S) and the DH output
  of rsDHSend(S) x rsDHRecv(S).

For receiving chain:
  rsRecvChain(S) is derived from rsRootKey(S) and the DH output
  of rsDHRecv(S) x rsDHSend(S).

Formally:
  Let (RK', CK_send) = HKDF(rsRootKey, X25519(dh_send_secret, rsDHRecv))
  Then rsRootKey(S') = RK' and rsSendChain(S') = CK_send
```

This invariant cannot be checked by inspecting the state alone (it
requires remembering the DH output). It is enforced structurally: the
ratchet step function is the ONLY code path that modifies chain keys,
and it always derives them from the DH output.

### Invariant 4: Skipped Key Bounds

```
|rsSkippedKeys(S)| <= 1000

For all (pk, n) in keys(rsSkippedKeys(S)):
  rsRecvN(S) - n <= 500       -- eviction window
```

### Invariant 5: PQ Refresh Cadence

```
pqSendCounter(S) < 50   -- reset to 0 after each refresh
pqRecvCounter(S) < 50
```

If a counter reaches 50 without a refresh having occurred, the
PQ wrapper MUST refuse to encrypt/decrypt until the refresh completes.

### Invariant 6: Session Version Consistency

```
ssVersion(S) == CURRENT_FORMAT_VERSION
```

A loaded state with a version higher than the software's current
version indicates a downgrade and is rejected.

---

## 11. Attack Scenarios

### 11.1 Threat Model

The attacker obtains a copy of the ratchet state at time T. We analyze
what they gain and how quickly the system recovers.

### 11.2 Scenario Matrix

| Scenario | Attacker gains | Window | Recovery |
|----------|---------------|--------|----------|
| **State at rest (encrypted file stolen)** | Nothing without passphrase. Offline brute-force against Argon2id (256 MiB, t=3). At 100 hashes/sec on GPU cluster: ~3.17e29 years for 128-bit passphrase. | Permanent if passphrase is weak | Use strong passphrase (>=128 bits entropy) |
| **State at rest (plaintext, no encryption)** | All current session keys. Can decrypt all messages in current chain (both directions). Can compute all future chain keys until next DH ratchet step. | Until next DH ratchet step (next message exchange) | Immediate session termination + new PQXDH |
| **In-memory state captured (cold boot, DMA)** | Same as plaintext at-rest: full current session keys | Until next DH ratchet step | Immediate session termination + new PQXDH |
| **Root key compromise only** | Can derive ALL future chain keys and message keys. Complete session break. | Permanent for this session | Session must be terminated + new PQXDH |
| **Send chain key compromise only** | Can derive all future sending message keys until next DH ratchet step. Cannot read received messages. | Until next DH ratchet step (attacker sends a message triggering DH ratchet on peer) | 1 round-trip message exchange |
| **Receive chain key compromise only** | Can derive all future receiving message keys until next DH ratchet step. Cannot forge sent messages. | Until next DH ratchet step | 1 round-trip message exchange |
| **Skipped keys compromise** | Can decrypt the specific out-of-order messages whose keys are cached. At most 1,000 messages, all within 500 ratchet steps of current state. | One-time (keys are for past messages) | No recovery needed; damage is bounded |
| **PQ chain key compromise only** | Can decrypt PQ wrapper for up to 50 messages. Inner Signal encryption is intact; attacker sees Signal ciphertext, not plaintext. | Until next PQ ratchet refresh (<=50 messages) | Automatic: next PQ refresh (Theorem 5.1, proof-02) |
| **PQ decapsulation key compromise** | Can decapsulate future PQ ratchet refreshes directed to this device. Combined with PQ chain key: can break PQ layer indefinitely. Signal inner layer still protects plaintext. | Until ML-KEM key rotation (next session re-establishment) | Session termination + new PQXDH with fresh ML-KEM keypair |
| **DH secret key + PQ chain key (both layers)** | Full plaintext access for current chain. Can read and forge messages until both layers ratchet. | Until DH ratchet step AND PQ refresh both occur | 1 round-trip + up to 50 messages |
| **Full state compromise (all fields)** | Complete session takeover. Can read all current/future messages, impersonate both parties to each other (if attacker is active MITM). | Until both parties independently detect anomaly or session is re-established | Session termination + new PQXDH + out-of-band identity verification |

### 11.3 Recovery Timeline

```
Time (messages exchanged after compromise)
  |
  0  Compromise occurs
  |  Attacker can read all messages in both directions.
  |
  1  First message exchanged (either direction)
  |  DH ratchet step occurs.
  |  -> Send chain key refreshed (post-compromise security begins).
  |  -> Attacker can still read with root key if root key was compromised.
  |
  2  Both parties have sent at least one message
  |  Both chain keys refreshed via independent DH ratchet steps.
  |  -> If root key was NOT compromised: recovery complete for Signal layer.
  |  -> If root key WAS compromised: recovery impossible without new PQXDH.
  |
  50 PQ ratchet refresh occurs
  |  -> PQ layer recovers (Theorem 5.1, proof-02).
  |  -> If only PQ layer was compromised: full recovery.
  |
  --  If root key was compromised:
  |  NO automatic recovery. Session MUST be terminated and re-established.
```

### 11.4 Detection Mechanisms

| Detection method | Detects |
|------------------|---------|
| Canary violation | Buffer overflow / memory corruption |
| HMAC verification failure | On-disk tampering or corruption |
| Counter regression | Rollback or replay attack |
| Duplicate message key usage | Active MITM replaying messages |
| MAC verification failure on received message | Active tampering or desynchronized ratchet |
| Unexpected SESSION_RESET from peer | Possible compromise of peer's state |

### 11.5 Recommendations for Operators

1. Set `RLIMIT_CORE` to 0 to prevent core dumps containing sensitive
   state. The `MADV_DONTDUMP` flag (Section 3.1) provides per-allocation
   protection, but a process-wide core dump limit is defense-in-depth.

2. Disable swap entirely (`swapoff -a`) on nodes handling ratchet state,
   or use encrypted swap. The `mlock()` protection (Section 3.1) prevents
   specific pages from swapping but cannot protect against kernel bugs
   or misconfiguration.

3. Use full-disk encryption (dm-crypt/LUKS) as Layer 2 defense
   (Section 9.2).

4. Monitor for CANARY_VIOLATION and HMAC_FAILURE log events. Any
   occurrence should trigger incident response.

5. Enforce minimum passphrase entropy of 128 bits for ratchet state
   encryption. The Argon2id parameters (256 MiB, t=3) provide
   approximately 2^20 slowdown factor (~10^6 hash evaluations per
   second on commodity GPU), which is insufficient for passphrases
   below ~80 bits of entropy.

---

## Appendix A: Summary of Cryptographic Bindings

| Operation | Algorithm | Key size | Reference |
|-----------|-----------|----------|-----------|
| State encryption | AES-256-GCM | 256-bit | FIPS 197 + NIST SP 800-38D |
| State authentication | HMAC-SHA-256 | 256-bit | RFC 2104 |
| Key derivation (passphrase) | Argon2id | N/A | RFC 9106 |
| Key derivation (domain separation) | HKDF-SHA-512 | N/A | RFC 5869 |
| Ratchet DH | X25519 | 256-bit | RFC 7748 |
| PQ encapsulation | ML-KEM-768 | FIPS 203 | FIPS 203 |

## Appendix B: File Layout

```
~/.UmbraVox/
  sessions/
    <session_id_hex>.state      -- encrypted SessionState (Section 2.2)
    <session_id_hex>.state.bak  -- optional encrypted backup (Section 6.3)
  salt                          -- Argon2id salt (16 bytes, plaintext)
```

File permissions: `0600` (owner read/write only).
Directory permissions: `0700` (owner only).
