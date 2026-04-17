# Hardening Spec 09: Memory Forensics Defense

**Status:** Required for v1
**Applies to:** All UmbraVox node deployments in hostile physical environments
**References:** `doc/03-cryptography.md`, `doc/10-security.md`, `doc/proof-07-cryptanalysis-resistance.md` Section 7
**DO-178C Traceability:** REQ-SEC-MFD-001 through REQ-SEC-MFD-045

---

## 1. Threat Model

### 1.1 Adversary Profile

The adversary has **physical access** to a running or recently-powered-off machine. This covers border crossings, law enforcement raids, office intrusions, device theft, and evil-maid attacks. The adversary is assumed to possess:

- Forensic memory imaging tools (e.g., Volatility, Rekall, WinPMEM, LiME)
- Cold boot attack capability (compressed air or liquid nitrogen to extend DRAM remanence)
- DMA attack hardware (malicious Thunderbolt/FireWire/PCIe devices, PCILeech)
- Ability to induce hibernation or capture suspend-to-disk images
- Core dump collection capability (via crash injection or post-mortem access)

### 1.2 DRAM Remanence Characteristics

Per Halderman et al. (2008):

| Condition | Remanence Window |
|-----------|-----------------|
| Room temperature, powered off | 2-10 seconds |
| Case cooling (compressed air) | 30-60 seconds |
| Liquid nitrogen (-196 C) | Minutes to hours |
| DDR4/DDR5 at room temp | Shorter than DDR3 (higher density, faster decay) |

Within the remanence window, 256-bit keys are recoverable with high probability. Partial key recovery (with bit errors) is correctable via key schedule redundancy in AES-256 (Halderman et al. demonstrated full AES-256 key recovery with up to 30% bit error rate).

### 1.3 DMA Attack Vectors

| Vector | Risk | Notes |
|--------|------|-------|
| Thunderbolt 1/2 | Critical | Direct PCIe access, no IOMMU by default |
| Thunderbolt 3/4 | High | IOMMU support exists but may be disabled |
| FireWire (IEEE 1394) | Critical | Direct DMA, no protection mechanism |
| ExpressCard / CardBus | Critical | Direct PCIe/CardBus DMA |
| Malicious PCIe device | Critical | Evil-maid insertion of rogue hardware |
| USB4 | High | Tunnels PCIe, inherits Thunderbolt risks |

DMA attacks can read arbitrary physical memory while the machine is running and the screen is locked. No software-only defense is sufficient without IOMMU enforcement.

---

## 2. Hardware Memory Encryption

### 2.1 Platform-Level Encryption

**REQ-SEC-MFD-001:** At startup, the UmbraVox node MUST detect and report the availability of hardware memory encryption.

| Platform | Technology | Protection |
|----------|-----------|------------|
| AMD EPYC / Ryzen Pro | SME (Secure Memory Encryption) | Encrypts all DRAM with ephemeral AES-128 key in SoC |
| AMD EPYC | SEV / SEV-ES / SEV-SNP | Per-VM memory encryption with attestation |
| Intel (11th gen+) | TME (Total Memory Encryption) | AES-XTS encryption of all DRAM |
| Intel (Xeon 3rd gen+) | MKTME (Multi-Key TME) | Per-page encryption keys |
| Apple M-series | Always-on memory encryption | Hardware AES engine on memory bus |

**REQ-SEC-MFD-002:** If no hardware memory encryption is detected, the node MUST log a warning at startup:

```
[WARN] No hardware memory encryption detected. DRAM contents are vulnerable
       to cold boot and DMA attacks. See doc/hardening/09-memory-forensics-defense.md.
```

**REQ-SEC-MFD-003:** The node MUST expose a status query (`/status/memory-protection`) reporting the active hardware memory encryption state.

### 2.2 Application-Level Key Encryption in RAM

Hardware memory encryption may be unavailable or insufficient (e.g., SME uses a single key for all memory; an adversary with kernel access can still read plaintext). Application-level defense is required regardless of hardware support.

**REQ-SEC-MFD-004:** All long-lived secret keys in memory (identity key, signed prekey private key, ratchet root keys, chain keys, PQ decapsulation keys) MUST be stored encrypted in RAM when not actively in use.

**REQ-SEC-MFD-005:** The RAM encryption key (referred to as the **sentinel key**) MUST be:

- 256 bits, generated from the CSPRNG at process startup
- Held exclusively in CPU registers during encryption/decryption operations
- Stored in a dedicated, `mlock`-ed, single-page allocation when not in a register
- Never written to any data structure that could be swapped, dumped, or paged

**REQ-SEC-MFD-006:** The encryption scheme for keys-in-RAM MUST be AES-256-CTR (not GCM; integrity is not required for this layer since the keys have independent integrity checks via the ratchet protocol). The nonce is a monotonic counter per-slot, incremented on each re-encryption.

**REQ-SEC-MFD-007:** The implementation MUST use the following pattern:

```
decrypt_key_to_register(slot) -> perform_crypto_operation -> re_encrypt_key(slot) -> scrub_registers
```

The plaintext key MUST NOT persist in addressable memory beyond the scope of the cryptographic operation.

---

## 3. Minimizing Key Exposure Window

**REQ-SEC-MFD-008:** Secret keys MUST be decrypted (from their RAM-encrypted form) only for the duration of the cryptographic operation that requires them. The maximum exposure window for each key type:

| Key Type | Maximum Exposure | Trigger |
|----------|-----------------|---------|
| Identity key (IK) | Single signature operation | SPK signing, transaction signing |
| Signed prekey (SPK) private | Single DH computation | PQXDH session setup |
| Ratchet DH private key | Single DH computation | Ratchet step |
| Chain key (CK) | Single HMAC computation | Message key derivation |
| Message key (MK) | Single AES-GCM encrypt/decrypt | Message processing |
| ML-KEM decapsulation key | Single decapsulation | PQ key exchange / ratchet refresh |

**REQ-SEC-MFD-009:** After each cryptographic operation completes, the implementation MUST:

1. Re-encrypt the key in its RAM slot (if the key persists, e.g., identity key)
2. Overwrite the plaintext key material in the working buffer with zeroes
3. Issue a compiler memory barrier (`asm volatile("" ::: "memory")` in C, or equivalent FFI call) to prevent the compiler from eliding the wipe
4. Overwrite relevant CPU registers used for the computation (where platform ABI permits)

**REQ-SEC-MFD-010:** The pure Haskell path (used for testing only, per `doc/03-cryptography.md` Section "Deployment Model") is exempt from register-level controls but MUST still perform buffer zeroing via FFI. GHC's garbage collector does not guarantee timely overwrite of unreachable `ByteString` contents; an explicit `memset` via FFI is required before the buffer is released.

---

## 4. mlock and MADV_DONTDUMP

**REQ-SEC-MFD-011:** All memory allocations containing secret key material MUST be pinned in physical memory using `mlock(2)` (POSIX) or `VirtualLock` (Windows). This prevents the operating system from swapping key material to disk.

**REQ-SEC-MFD-012:** The node MUST check the return value of `mlock`. If `mlock` fails (e.g., `ENOMEM` due to `RLIMIT_MEMLOCK`), the node MUST:

1. Log a critical warning identifying the failing allocation
2. Attempt to raise `RLIMIT_MEMLOCK` via `setrlimit(2)` if running with sufficient privilege
3. If still failing: refuse to start and print guidance on configuring `RLIMIT_MEMLOCK` (e.g., `/etc/security/limits.conf` or systemd `LimitMEMLOCK=`)

**REQ-SEC-MFD-013:** All `mlock`-ed allocations MUST also be marked with `madvise(MADV_DONTDUMP)` to exclude them from core dumps generated by the kernel (Linux 3.4+).

**REQ-SEC-MFD-014:** The node process MUST set `prctl(PR_SET_DUMPABLE, 0)` at startup to prevent core dump generation entirely, unless explicitly overridden by a `--enable-coredumps` flag (for development/debugging only; this flag MUST NOT be present in release builds).

**REQ-SEC-MFD-015:** On Linux, the node SHOULD set `/proc/self/coredump_filter` to `0x00` to exclude all memory mappings from any core dump that might be generated despite `PR_SET_DUMPABLE=0` (defense in depth).

### 4.1 Secure Allocator

**REQ-SEC-MFD-016:** The implementation MUST provide a `SecureAlloc` module (or equivalent) that encapsulates:

- `mlock` on allocation
- `MADV_DONTDUMP` on allocation
- Mandatory `memset(0)` on deallocation (with compiler barrier)
- Guard pages (see Section 5)

All secret key storage MUST use this allocator. General-purpose `malloc`/GHC heap allocations MUST NOT hold secret key material.

---

## 5. Guard Pages

**REQ-SEC-MFD-017:** Every `SecureAlloc` allocation MUST be surrounded by guard pages: one unmapped page immediately before and one immediately after the allocation.

**REQ-SEC-MFD-018:** Guard pages MUST be created by calling `mmap` with `PROT_NONE` (no read, write, or execute permission). Any access to a guard page triggers `SIGSEGV`, which the node catches to log a security event before terminating.

**REQ-SEC-MFD-019:** The minimum allocation granularity for `SecureAlloc` is one page (typically 4096 bytes). Allocations smaller than one page still consume a full page plus two guard pages (3 pages total, 12 KiB on 4K-page systems).

**REQ-SEC-MFD-020:** Guard pages serve two purposes:

1. **Overflow/underflow detection:** A buffer overflow or underflow from adjacent memory cannot silently corrupt key material.
2. **Spatial isolation:** Limits the damage radius of a memory disclosure vulnerability. A read primitive that scans linearly from a non-secret buffer will hit an unmapped page before reaching key material.

---

## 6. Panic / Duress Wipe

### 6.1 Panic Wipe

**REQ-SEC-MFD-021:** The node MUST support an immediate **panic wipe** triggered by any of:

- A designated keyboard shortcut (configurable, default: Ctrl+Alt+Shift+W)
- A Unix signal (default: `SIGUSR1`)
- An authenticated local API call (`POST /api/panic-wipe` with local auth token)
- A hardware panic button (if the platform exposes one via evdev or equivalent)

**REQ-SEC-MFD-022:** On panic wipe, the following actions MUST execute in order, with a total time budget of **under 100 milliseconds**:

1. Overwrite all `SecureAlloc` regions with zeroes (single pass is sufficient; DRAM is volatile)
2. Overwrite the sentinel key (Section 2.2) with zeroes
3. Zero the CSPRNG state (seed, counter, buffer)
4. Zero all ratchet states for all active sessions
5. Zero all skipped message keys
6. Unlink (delete) the encrypted key store file from disk
7. Call `munlock` and `munmap` on all secure allocations
8. Terminate the process with `_exit(0)` (not `exit()`, to bypass atexit handlers that might log sensitive state)

**REQ-SEC-MFD-023:** The panic wipe code path MUST NOT allocate memory, acquire locks held by other threads, or perform any operation that could block. The wipe sequence must be pre-planned: a list of (pointer, length) pairs for all secure allocations is maintained at all times.

**REQ-SEC-MFD-024:** The panic wipe MUST be tested in CI with a dedicated test that:

1. Initializes a node with a known key
2. Triggers panic wipe
3. Reads the process memory image (via `/proc/self/mem` before `_exit`, or via a coredump of a test variant)
4. Asserts that no key material remains

### 6.2 Duress Passphrase

**REQ-SEC-MFD-025:** The node MUST support a **duress passphrase** — a secondary passphrase that, when entered instead of the real passphrase, triggers a panic wipe instead of unlocking the key store.

**REQ-SEC-MFD-026:** The duress passphrase MUST be configured during initial node setup. It MUST be stored as a separate Argon2id hash in the key store metadata. The node MUST NOT reveal whether a given passphrase is the real passphrase or the duress passphrase until after the wipe decision is made internally.

**REQ-SEC-MFD-027:** When the duress passphrase is entered:

1. The node MUST display normal "unlocking..." UI feedback (indistinguishable from real unlock)
2. Execute the full panic wipe (Section 6.1, steps 1-8)
3. Display a plausible error message: "Key store corrupted. Node cannot start."
4. The node MUST NOT display any indication that a duress wipe occurred

**REQ-SEC-MFD-028:** The duress mechanism MUST be timing-indistinguishable from normal unlock. Both paths MUST perform the same Argon2id computation. The duress path performs the wipe after the Argon2id computation completes, matching the timing profile of the real unlock path (which performs key derivation after Argon2id).

---

## 7. Screen Lock Integration

**REQ-SEC-MFD-029:** The node MUST support an optional **screen lock key wipe** mode (disabled by default, enabled via `--wipe-on-lock` flag or configuration).

**REQ-SEC-MFD-030:** When screen lock key wipe is enabled and the operating system reports a screen lock event:

1. All ephemeral session keys (ratchet DH private keys, chain keys, message keys, PQ chain state) are wiped from memory
2. The identity key and signed prekey remain in RAM-encrypted form (Section 2.2)
3. The sentinel key is wiped
4. Active sessions are marked as "suspended — re-auth required"

**REQ-SEC-MFD-031:** On screen unlock, the user MUST re-enter their passphrase to:

1. Re-derive the sentinel key from the passphrase via HKDF(Argon2id(passphrase))
2. Decrypt the identity key and signed prekey from disk
3. Re-establish ratchet states from the last persisted checkpoint (losing at most the messages received since the last checkpoint)

**REQ-SEC-MFD-032:** Screen lock detection MUST use platform-specific mechanisms:

- **Linux (D-Bus):** `org.freedesktop.ScreenSaver.ActiveChanged` or `org.gnome.ScreenSaver.ActiveChanged`
- **macOS:** `com.apple.screenIsLocked` distributed notification
- **Windows:** `WTS_SESSION_LOCK` via `WTSRegisterSessionNotification`

**REQ-SEC-MFD-033:** If screen lock detection is unavailable (e.g., headless server, Wayland compositor without D-Bus), the node MUST log a warning and disable the feature gracefully. The node MUST NOT crash or refuse to start.

---

## 8. IOMMU and DMA Protection

**REQ-SEC-MFD-034:** At startup, the node MUST check whether an IOMMU is active and report the result.

Detection methods (Linux):

1. Check for `/sys/class/iommu/` entries
2. Parse `dmesg` or `/var/log/kern.log` for `DMAR: IOMMU enabled` (Intel VT-d) or `AMD-Vi: IOMMU` (AMD-Vi)
3. Check for `intel_iommu=on` or `amd_iommu=on` in `/proc/cmdline`

**REQ-SEC-MFD-035:** If no IOMMU is detected or if IOMMU is detected but not in strict mode, the node MUST log:

```
[WARN] IOMMU not active or not in strict mode. DMA attacks via Thunderbolt,
       FireWire, or rogue PCIe devices can read memory contents directly.
       Recommendation: enable IOMMU in BIOS and add 'intel_iommu=on iommu=strict'
       (or 'amd_iommu=on iommu=strict') to kernel command line.
```

**REQ-SEC-MFD-036:** The IOMMU check is advisory only. The node MUST NOT refuse to start if IOMMU is absent. Users in hostile physical environments should treat an IOMMU-absent machine as unsuitable.

**REQ-SEC-MFD-037:** On macOS, the node SHOULD check for Thunderbolt security level via `system_profiler SPThunderboltDataType` and warn if the security level allows untrusted devices without user approval.

---

## 9. Hibernation and Suspend

### 9.1 Hibernation (Suspend-to-Disk)

**REQ-SEC-MFD-038:** Hibernation writes the full contents of RAM to the swap partition or hibernation file, including all key material. This completely defeats all in-memory protections.

The node MUST detect hibernation attempts and respond:

- **Linux:** Register an `inhibitor` via `org.freedesktop.login1.Manager.Inhibit` with reason "UmbraVox: key material in memory". This presents a warning to the user but does not block hibernation (the user can override).
- **Alternative (Linux):** Monitor for `PrepareForSleep` signal from `org.freedesktop.login1.Manager`. If `arg0=true` (entering sleep), execute key wipe (same as screen lock wipe, Section 7) before the system completes hibernation.

**REQ-SEC-MFD-039:** On resume from hibernation, the node MUST require full re-authentication (same as screen lock recovery, Section 7, steps 1-3). The node MUST assume all ephemeral keys were compromised.

### 9.2 Suspend (Suspend-to-RAM)

**REQ-SEC-MFD-040:** Suspend-to-RAM preserves DRAM contents with power. An adversary with physical access to a suspended machine can perform cold boot attacks or DMA attacks against live memory.

On suspend detection (`PrepareForSleep` with `arg0=true`):

1. Wipe all ephemeral session keys (same set as screen lock wipe)
2. Keep RAM-encrypted identity key and signed prekey (they are encrypted under the sentinel key)
3. Wipe the sentinel key
4. On resume: require re-authentication to restore sentinel key and session state

---

## 10. Full Disk Encryption Dependency

**REQ-SEC-MFD-041:** UmbraVox's on-disk key store, ratchet checkpoints, and database are encrypted with a passphrase-derived key. However, application-level encryption does not protect against:

- Swap file/partition containing paged-out key material (mitigated by `mlock`, but defense in depth requires FDE)
- Temporary files created by the OS or runtime
- Core dumps that bypass `PR_SET_DUMPABLE` (kernel bugs, hypervisor-level dumps)
- Hibernation images (Section 9.1)
- Filesystem journal / write-ahead log containing partial key store writes

**REQ-SEC-MFD-042:** At startup, the node MUST check whether the root filesystem (or the filesystem containing the UmbraVox data directory) is on an encrypted block device.

Detection methods (Linux):

1. Resolve the block device for the data directory via `stat` and `/proc/mounts`
2. Check if the device is a `dm-crypt` / LUKS device via `/sys/block/*/dm/uuid` (prefix `CRYPT-`)
3. Alternatively, check `lsblk -o NAME,TYPE` for type `crypt`

**REQ-SEC-MFD-043:** If the filesystem is not encrypted, the node MUST log:

```
[WARN] Data directory is on an unencrypted filesystem. UmbraVox's on-disk key
       store is application-encrypted, but swap, temp files, and hibernation
       images may leak key material. Full disk encryption (LUKS/dm-crypt,
       FileVault, BitLocker) is strongly recommended.
```

**REQ-SEC-MFD-044:** The FDE check is advisory only. The node MUST NOT refuse to start on an unencrypted filesystem.

---

## 11. Post-Compromise Recovery

**REQ-SEC-MFD-045:** If a user suspects or confirms that physical access to their machine occurred while the node was running or within the DRAM remanence window after power-off, ALL of the following MUST be assumed compromised:

- Identity key (IK)
- All signed prekey private keys (current and any in-memory historical)
- All active ratchet states (root keys, chain keys, DH private keys)
- All skipped message keys
- ML-KEM decapsulation keys
- CSPRNG state (allowing prediction of future random outputs until reseed)

### 11.1 Required Recovery Actions

The user MUST perform a full identity rotation:

1. **Generate a new identity key** on a known-clean machine
2. **Publish a KEY_REGISTER transaction** with the new identity, new SPK, and fresh OPK/PQPK bundles
3. **Notify all contacts** via an out-of-band channel that the old identity key is compromised and should be marked as untrusted
4. **Establish new sessions** with every contact (the old sessions are irrecoverable and must be considered fully compromised in both directions — past messages decryptable, future messages interceptable until new session)
5. **Revoke the old identity** by publishing a KEY_REVOKE transaction signed with the old identity key (if the old key is still available) or by social proof (contacts manually confirm the rotation)

### 11.2 Automated Compromise Response

**REQ-SEC-MFD-046:** The node MUST provide a `--assume-compromised` startup flag that:

1. Generates a fresh identity key, SPK, OPK bundle, and PQPK bundle
2. Publishes KEY_REGISTER for the new identity
3. Attempts to publish KEY_REVOKE for the old identity (if the old key material is available from an encrypted backup)
4. Clears all session state
5. Logs the old identity key fingerprint and new identity key fingerprint for user communication to contacts

### 11.3 Forward Secrecy Limitation

Per `doc/proof-07-cryptanalysis-resistance.md` Section 7.1: a memory compromise captures the **current** ratchet state. Forward secrecy protects past messages (keys for already-decrypted messages have been ratcheted away). However:

- Messages received but not yet decrypted (in the skipped keys buffer) are compromised
- All future messages in the current ratchet chain are compromised until a new DH ratchet step occurs with a non-compromised peer
- The PQ layer does not independently recover until the next PQ ratchet refresh (up to 50 messages)

Full recovery requires new session establishment, not merely waiting for ratchet advancement, because the adversary holds the current DH private key and can track all subsequent ratchet steps.

---

## 12. Implementation Checklist

| # | Requirement | Module | Priority |
|---|-------------|--------|----------|
| 1 | SecureAlloc with mlock + MADV_DONTDUMP + guard pages | `UmbraVox.System.SecureAlloc` | P0 |
| 2 | RAM key encryption with sentinel key | `UmbraVox.Crypto.KeyStore` | P0 |
| 3 | Panic wipe (SIGUSR1, API, hotkey) | `UmbraVox.System.PanicWipe` | P0 |
| 4 | Duress passphrase | `UmbraVox.System.Auth` | P0 |
| 5 | PR_SET_DUMPABLE=0 at startup | `UmbraVox.System.Init` | P0 |
| 6 | Buffer zeroing with compiler barrier (FFI) | `UmbraVox.System.SecureAlloc` | P0 |
| 7 | Hardware memory encryption detection | `UmbraVox.System.PlatformCheck` | P1 |
| 8 | IOMMU detection and warning | `UmbraVox.System.PlatformCheck` | P1 |
| 9 | FDE detection and warning | `UmbraVox.System.PlatformCheck` | P1 |
| 10 | Screen lock key wipe | `UmbraVox.System.ScreenLock` | P1 |
| 11 | Suspend/hibernate detection and wipe | `UmbraVox.System.PowerEvents` | P1 |
| 12 | Post-compromise `--assume-compromised` flow | `UmbraVox.System.Recovery` | P1 |
| 13 | CI test: panic wipe leaves no key residue | `test/security/PanicWipeTest` | P0 |
| 14 | CI test: duress passphrase timing equivalence | `test/security/DuressTimingTest` | P1 |

---

## 13. References

- Halderman, J.A. et al. (2008). "Lest We Remember: Cold Boot Attacks on Encryption Keys." USENIX Security.
- Boileau, A. (2006). "Hit by a Bus: Physical Access Attacks with Firewire." Ruxcon.
- Maartmann-Moe, C. (2011). "Inception: Physical Memory Manipulation and Hacking Tool." (PCILeech predecessor)
- AMD. "AMD Memory Encryption." AMD SEV-SNP White Paper.
- Intel. "Intel Total Memory Encryption." Intel Architecture Specification.
- Muller, T. et al. (2011). "TRESOR: Runs Encryption Securely Outside RAM." USENIX Security. (Register-only key storage)
- Simakov, N. (2014). "AES Key Schedule Redundancy and Cold Boot Recovery." (Key schedule redundancy enabling recovery from partial bit errors)
