# Hardening-20: Session Resumption Security

**Status:** Draft
**Depends on:** `doc/03-cryptography.md` (PQXDH, Double Ratchet, skipped key limits), `doc/proof-02-protocol-security.md` (CK model, forward secrecy proofs), `doc/11-node-architecture.md` (storage layout, key store encryption)
**Cross-references:** `doc/hardening/05-ratchet-state-protection.md` (encrypted state on disk)
**References:** RFC 7748 (X25519), RFC 8032 (Ed25519), FIPS 203 (ML-KEM-768), Signal Double Ratchet specification

---

## 1. Session Establishment

### 1.1 PQXDH Handshake

Session establishment follows the PQXDH protocol defined in `doc/03-cryptography.md` lines 91-109. The complete handshake produces the following state artifacts:

```
PQXDH_Establish(alice_ik, bob_bundle):
  1. Verify bob_bundle.spk_sig via Ed25519 (or HybridVerify post-migration)
  2. ek_a = X25519_KeyGen()                    -- ephemeral keypair
  3. dh1  = X25519(alice_ik.secret, bob_bundle.spk)
  4. dh2  = X25519(ek_a.secret, bob_bundle.ik.public)
  5. dh3  = X25519(ek_a.secret, bob_bundle.spk)
  6. dh4  = X25519(ek_a.secret, bob_bundle.opk)   -- omitted if OPK exhausted
  7. (pq_ct, pq_ss) = ML_KEM_Encaps(bob_bundle.pqpk)
  8. MS   = HKDF(salt=0x00*32,
                 ikm=0xFF*32 || dh1 || dh2 || dh3 || [dh4] || pq_ss,
                 info="UmbraVox_PQXDH_v1")
  9. Erase: ek_a.secret, dh1, dh2, dh3, dh4, pq_ss   -- immediate
 10. Initialize Double Ratchet with MS
 11. Initialize PQ outer wrapper chain with pq_ss
 12. Erase: MS                                          -- after ratchet init
```

### 1.2 Initial Ratchet State Created

After successful PQXDH, the following state is instantiated:

```haskell
data SessionState = SessionState
  { ssSessionId     :: !SessionId           -- 32 bytes, see Section 6.2
  , ssPeerIK        :: !X25519PublicKey      -- 32 bytes, peer identity key
  , ssCreatedAt     :: !Word64              -- POSIX timestamp, seconds
  , ssLastActivity  :: !Word64              -- updated on send/receive
  , ssRatchet       :: !RatchetState        -- see doc/03-cryptography.md line 122
  , ssPQChainKey    :: !ByteString          -- 32 bytes, PQ wrapper chain key
  , ssPQSendCount   :: !Word32             -- per-direction PQ ratchet counter (send)
  , ssPQRecvCount   :: !Word32             -- per-direction PQ ratchet counter (recv)
  , ssDHRatchetN    :: !Word64             -- total DH ratchet steps performed
  , ssStatus        :: !SessionStatus
  , ssIntegrityMAC  :: !ByteString          -- 32 bytes, HMAC over serialised state
  }

data SessionStatus
  = Active
  | Suspended        -- peer unresponsive for >24 hours
  | PendingReset     -- reset initiated, awaiting re-handshake
  | Expired          -- exceeded max lifetime or ratchet depth
  deriving (Eq, Show)
```

### 1.3 State Created on Disk

On successful handshake completion, the session state is serialised and encrypted to:

```
$UmbraVox_DATA/sessions/signal/<session_id_hex>.enc
$UmbraVox_DATA/sessions/pq/<session_id_hex>.enc
```

Encryption uses AES-256-GCM with a storage key derived per Section 3.1. The ephemeral key material (ek_a.secret, all DH intermediaries, pq_ss, MS) is erased from memory before the function returns. Only the derived ratchet state persists.

---

## 2. Session Persistence

### 2.1 Encrypted State on Disk

Session state is stored encrypted at rest. The encryption mechanism follows `doc/11-node-architecture.md` line 16:

```
Storage key derivation:
  passphrase     -- user-provided, never stored
  salt           -- 16 random bytes, stored in plaintext alongside file
  storage_key    = Argon2id(passphrase, salt, t=3, m=256MB, p=1)  -- 32 bytes
  session_key    = HKDF(salt=0x00*32,
                        ikm=storage_key,
                        info="UmbraVox_SessionStore_v1" || session_id)
```

Each session file is independently encrypted with a session-specific key derived from the storage key via HKDF with the session ID as domain separator. This ensures that a bug in one session's serialisation cannot affect other sessions' confidentiality.

### 2.2 File Format

```
Session file wire format:
  [12 bytes]  nonce          -- random, unique per write
  [4 bytes]   version        -- file format version (uint32 big-endian), currently 0x00000001
  [4 bytes]   payload_len    -- encrypted payload length (uint32 big-endian)
  [N bytes]   ciphertext     -- AES-256-GCM(session_key, nonce, payload)
  [16 bytes]  gcm_tag        -- GCM authentication tag
```

The payload (before encryption) is the CBOR-serialised `SessionState` structure.

### 2.3 Atomic Write Protocol

Session state updates use atomic file replacement to prevent corruption from crashes:

```
WriteSession(session_id, state):
  1. Serialise state to CBOR
  2. Compute integrity MAC: HMAC-SHA-256(session_key, serialised_state)
  3. Set state.ssIntegrityMAC = mac
  4. Re-serialise with MAC included
  5. Generate fresh 12-byte nonce
  6. Encrypt with AES-256-GCM
  7. Write to temporary file: <session_id_hex>.enc.tmp (fsync)
  8. Rename temporary file to <session_id_hex>.enc (atomic on POSIX)
  9. fsync parent directory
```

This guarantees that the session file is always in a consistent state: either the old version or the new version, never a partial write.

### 2.4 Write Triggers

Session state is persisted to disk after every state-modifying event:

| Event | State fields modified |
|-------|----------------------|
| Message sent | rsSendN, rsSendChain, ssPQSendCount, ssLastActivity |
| Message received | rsRecvN, rsRecvChain, rsSkippedKeys, ssPQRecvCount, ssLastActivity |
| DH ratchet step | rsDHSend, rsDHRecv, rsRootKey, rsSendChain, rsRecvChain, rsPrevChainN, ssDHRatchetN |
| PQ ratchet refresh | ssPQChainKey, ssPQSendCount or ssPQRecvCount |
| Session status change | ssStatus |

Cross-reference: `doc/hardening/05-ratchet-state-protection.md` for additional disk-level protections (file permissions, encrypted filesystem recommendations, secure deletion).

---

## 3. Session Resumption

### 3.1 Loading Encrypted State

On application restart, session resumption proceeds as follows:

```
ResumeAllSessions(passphrase):
  1. storage_key = Argon2id(passphrase, stored_salt, t=3, m=256MB, p=1)
  2. For each file in $UmbraVox_DATA/sessions/signal/*.enc:
     a. session_id  = filename_to_session_id(file)
     b. session_key = HKDF(salt=0x00*32,
                           ikm=storage_key,
                           info="UmbraVox_SessionStore_v1" || session_id)
     c. Read file: nonce || version || payload_len || ciphertext || gcm_tag
     d. Verify version == 0x00000001 (reject unknown versions)
     e. plaintext = AES-256-GCM-Decrypt(session_key, nonce, ciphertext, gcm_tag)
     f. If decryption fails: log error, skip session (see Section 3.3)
     g. state = CBOR-Deserialise(plaintext)
     h. Verify integrity MAC (Section 3.2)
     i. Load corresponding PQ state from sessions/pq/<session_id>.enc
     j. Register session in memory: session_map[peer_ik] = state
  3. Erase storage_key from memory after all sessions loaded
```

### 3.2 Integrity Verification

After decryption and deserialisation, the integrity MAC is verified:

```
VerifySessionIntegrity(session_key, state):
  1. saved_mac = state.ssIntegrityMAC
  2. state.ssIntegrityMAC = 0x00 * 32      -- zero out for recomputation
  3. reserialised = CBOR-Serialise(state)
  4. expected_mac = HMAC-SHA-256(session_key, reserialised)
  5. If NOT constant_time_equal(saved_mac, expected_mac):
       log "Session integrity check failed for session <session_id>"
       discard session
       mark as PendingReset
  6. Restore state.ssIntegrityMAC = saved_mac
```

The integrity MAC provides defence-in-depth beyond GCM authentication. GCM protects against external tampering; the HMAC protects against logic errors in serialisation/deserialisation that could silently corrupt state.

### 3.3 Resumption Failure Handling

| Failure mode | Action |
|-------------|--------|
| GCM decryption failure (wrong passphrase) | Prompt user to re-enter passphrase; do not delete file |
| GCM decryption failure (file corrupted) | Log corruption event; discard session; mark PendingReset |
| Integrity MAC mismatch | Log integrity failure; discard session; mark PendingReset |
| Unknown file format version | Log version mismatch; skip session (preserve file for future upgrade) |
| CBOR deserialisation failure | Log parse error; discard session; mark PendingReset |
| PQ state file missing (signal file exists) | Log orphaned session; discard signal state; mark PendingReset |

All PendingReset sessions will trigger re-handshake on next communication attempt with that peer (Section 5).

---

## 4. Stale Session Detection

### 4.1 Problem Statement

A session becomes stale when the peer has lost their ratchet state (device loss, reinstallation, data corruption) but the local node still holds the old session. Messages sent using the old session will be undecryptable by the peer.

### 4.2 Detection Mechanisms

**Mechanism 1: Decryption failure on received messages.**

```
OnReceiveMessage(peer_ik, encrypted_msg):
  session = session_map[peer_ik]
  result  = DoubleRatchet_Decrypt(session.ssRatchet, encrypted_msg)

  If result == DecryptionFailure:
    session.ssConsecutiveFailures += 1
    If session.ssConsecutiveFailures >= 5:
      mark session as Suspended
      notify user: "Messages from <peer> cannot be decrypted.
                    They may have reset their device."
    -- Do NOT auto-reset: could be transient network issue or reordering

  If result == Success:
    session.ssConsecutiveFailures = 0
```

**Mechanism 2: Unacknowledged message detection.**

The protocol does not have explicit ACKs, but the DH ratchet advances when the peer responds. If a peer's DH ratchet public key has not changed after sending more than 100 messages, the peer may have lost state:

```
OnSendMessage(peer_ik):
  session = session_map[peer_ik]
  If session.rsSendN - session.rsLastRecvDHRatchetAtSendN > 100:
    log "Peer <peer_ik> has not ratcheted after 100 sent messages"
    mark session as Suspended
    notify user
```

**Mechanism 3: Peer key bundle change detection.**

When a peer publishes a new KEY_REGISTER transaction on-chain (new identity key or new prekey bundle with reset state), all existing sessions with that peer are stale:

```
OnKeyRegistryUpdate(peer_ik, new_bundle):
  If session_map contains peer_ik:
    existing_session = session_map[peer_ik]
    If new_bundle.ik != existing_session.ssPeerIK:
      -- Peer has a new identity key: definitely a new device/install
      mark session as PendingReset
      notify user: "Contact <peer> has a new identity key.
                    Verify their safety number before continuing."
```

### 4.3 Ratchet Desync Detection

A ratchet desync occurs when both peers have valid sessions but their ratchet states have diverged (e.g., one peer restored from a backup). Detection:

```
Desync indicators:
  - Received message has a DH ratchet public key that is OLDER than the
    current expected key (regression in ratchet state)
  - Message counter (rsRecvN) is LESS than the last successfully
    decrypted counter for the same DH ratchet key
  - More than MAX_SKIP (1000) skipped messages would be needed to
    reach the received message's counter
```

On desync detection, the session is marked PendingReset and the user is notified.

---

## 5. Session Reset Protocol

### 5.1 Reset Triggers

A session MUST be discarded and re-established via fresh PQXDH handshake when any of the following conditions are met:

| Trigger | Threshold | Rationale |
|---------|-----------|-----------|
| Skipped messages exceed limit | >1,000 skipped keys would be needed | Memory exhaustion prevention; likely desync |
| Ratchet desync detected | Any regression in DH ratchet key or counter | State corruption or backup restore |
| User-initiated reset | User explicitly requests session reset | User preference or suspected compromise |
| Session expired | See Section 9 (max lifetime / max ratchet depth) | Limit session drift |
| Peer identity key changed | New KEY_REGISTER on-chain | Peer has new device/installation |
| Consecutive decryption failures | >= 5 consecutive failures | Likely peer state loss |
| Integrity verification failure | On session load from disk | Corrupted local state |

### 5.2 Reset State Machine

```
                    +--------+
                    | Active |<---------+
                    +--------+          |
                       |                |
            (trigger condition)    (PQXDH success)
                       |                |
                       v                |
                  +-----------+         |
                  | Suspended |         |
                  +-----------+         |
                       |                |
              (user confirms reset      |
               OR auto-reset trigger)   |
                       |                |
                       v                |
                +--------------+        |
                | PendingReset |--------+
                +--------------+
                       |
              (PQXDH fails or
               peer unreachable)
                       |
                       v
                 +---------+
                 | Expired |
                 +---------+
```

### 5.3 Reset Procedure

```
ResetSession(peer_ik, reason):
  1. old_session = session_map[peer_ik]

  -- Secure erasure of old state
  2. Erase old_session.ssRatchet (all keys) from memory
  3. Erase old_session.ssPQChainKey from memory
  4. Overwrite session files on disk with random bytes, then delete:
       overwrite($UmbraVox_DATA/sessions/signal/<session_id>.enc, urandom)
       delete($UmbraVox_DATA/sessions/signal/<session_id>.enc)
       overwrite($UmbraVox_DATA/sessions/pq/<session_id>.enc, urandom)
       delete($UmbraVox_DATA/sessions/pq/<session_id>.enc)

  -- Log reset event (no secrets in log)
  5. log "Session reset: peer=<peer_ik_fingerprint>, reason=<reason>,
         ratchet_depth=<ssDHRatchetN>, age=<now - ssCreatedAt>"

  -- Remove from session map
  6. delete session_map[peer_ik]

  -- Initiate re-establishment
  7. Fetch peer's current prekey bundle from on-chain key registry
  8. If bundle available:
       new_session = PQXDH_Establish(local_ik, peer_bundle)
       session_map[peer_ik] = new_session
       WriteSession(new_session.ssSessionId, new_session)
     Else:
       queue re-establishment for next bundle availability
       -- Peer may have not yet published a new bundle
```

### 5.4 User Notification

Session resets are security-relevant events. The user MUST be notified with:

- Peer identity (display name and public key fingerprint)
- Reset reason (human-readable)
- Whether the peer's identity key has changed (critical security signal)
- Prompt to verify safety number if identity key changed (Section 10)

Automatic silent re-establishment without user notification is NOT permitted for identity key changes. For other reset reasons (ratchet overflow, expiry), the session may be re-established automatically with an informational notification.

---

## 6. Multi-Session Management

### 6.1 One Session Per Peer Pair

The protocol maintains exactly ONE active session per peer pair (local identity key, peer identity key). If multiple sessions exist for the same peer (e.g., due to concurrent handshake attempts), the session with the most recent `ssCreatedAt` timestamp is retained and all others are discarded.

```
RegisterSession(new_session):
  peer_ik = new_session.ssPeerIK
  If session_map contains peer_ik:
    old = session_map[peer_ik]
    If new_session.ssCreatedAt > old.ssCreatedAt:
      EraseSession(old)
      session_map[peer_ik] = new_session
    Else:
      EraseSession(new_session)  -- keep existing, newer session
  Else:
    session_map[peer_ik] = new_session
```

### 6.2 Session ID Generation

```
SessionId = SHA-256(
  local_ik.public  ||   -- 32 bytes
  peer_ik.public   ||   -- 32 bytes
  ephemeral_key    ||   -- 32 bytes (Alice's EK from PQXDH)
  creation_timestamp    -- 8 bytes (uint64 big-endian, POSIX seconds)
)
```

The session ID is a 32-byte value that uniquely identifies a session instance. It is NOT secret (it contains no key material) but is used for:

- File naming on disk
- Session-specific key derivation (Section 2.1)
- Logging and diagnostics

### 6.3 Session ID Collision

Session ID collision probability is negligible (birthday bound on SHA-256: ~2^128 sessions required). No collision handling is implemented. If a collision were somehow detected (same session ID, different peer IK), the node logs a critical error and refuses to overwrite the existing session file.

### 6.4 Session Lookup

Sessions are indexed in memory by peer identity public key:

```haskell
type SessionMap = Map X25519PublicKey SessionState
```

Lookup is O(log n) where n is the number of active sessions. For a typical node with fewer than 1,000 active sessions, this is negligible.

On-disk, sessions are located by session ID (filename). The mapping from peer public key to session ID is maintained in an in-memory index rebuilt at startup by loading and decrypting all session files.

---

## 7. Concurrent Message Handling

### 7.1 Out-of-Order Delivery

The UmbraVox blockchain does not guarantee message ordering within a block. Transactions within a block are sorted by transaction hash for deterministic ordering (`doc/03-cryptography.md` line 194), but this order bears no relation to send order. Messages from different blocks may also arrive out of order due to network propagation delays.

The Double Ratchet handles out-of-order delivery via skipped key management.

### 7.2 Skipped Key Management

When a received message has a counter greater than the expected next counter, intermediate message keys are derived and cached:

```
ReceiveMessage(session, header, ciphertext):
  If header.dh_pub != session.rsDHRecv:
    -- New DH ratchet key: skip remaining keys in current receiving chain
    skip_count = header.prev_chain_n - session.rsRecvN
    If skip_count > MAX_SKIP:
      return Error(TooManySkippedKeys)    -- trigger session reset
    StoreSkippedKeys(session, session.rsDHRecv, session.rsRecvN, header.prev_chain_n)
    PerformDHRatchetStep(session, header.dh_pub)

  -- Skip keys in current chain up to header.msg_n
  skip_count = header.msg_n - session.rsRecvN
  If skip_count > MAX_SKIP:
    return Error(TooManySkippedKeys)
  If TotalSkippedKeys(session) + skip_count > MAX_SKIP:
    return Error(SkippedKeyStorageFull)
  StoreSkippedKeys(session, session.rsDHRecv, session.rsRecvN, header.msg_n)

  -- Derive and use message key
  mk = DeriveMessageKey(session.rsRecvChain)
  AdvanceReceivingChain(session)
  plaintext = AES-256-GCM-Decrypt(mk, ciphertext)
  Erase(mk)
  return plaintext
```

### 7.3 Skipped Key Storage Limits

Per `doc/03-cryptography.md` lines 139-145:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| MAX_SKIP | 1,000 | Prevent memory exhaustion from adversarial gaps |
| Eviction threshold | 500 ratchet steps | Bound forward secrecy exposure window |
| Memory bound | ~64 KB per session | 1,000 entries * (32 + 4 + 32) bytes |

### 7.4 Concurrent Access Serialisation

Within a single node, all ratchet operations for a given session are serialised via an STM `TMVar` (mutual exclusion per session):

```haskell
type SessionLock = TMVar ()

-- One lock per active session
type SessionLockMap = TVar (Map X25519PublicKey SessionLock)

withSessionLock :: SessionLockMap -> X25519PublicKey -> IO a -> IO a
withSessionLock lockMap peerIK action = do
  lock <- atomically $ do
    m <- readTVar lockMap
    case Map.lookup peerIK m of
      Just l  -> return l
      Nothing -> do
        l <- newTMVar ()
        modifyTVar lockMap (Map.insert peerIK l)
        return l
  atomically (takeTMVar lock)
  result <- action `onException` atomically (putTMVar lock ())
  atomically (putTMVar lock ())
  return result
```

This prevents race conditions where two concurrent message receipts could corrupt ratchet state. Send and receive operations on the same session are fully serialised.

---

## 8. Session Migration

### 8.1 Cross-Device Migration: NOT Supported

Session migration between devices is explicitly NOT supported. Transferring session state to a new device would require:

1. Exporting the full ratchet state (including all chain keys)
2. Transmitting it to the new device
3. Importing it on the new device

This fundamentally breaks forward secrecy: the exported state contains all current chain keys, and any interception of the export would compromise all future messages in the session. Additionally, if both devices retain the state, ratchet desync is inevitable on the first message.

### 8.2 New Device Procedure

When a user moves to a new device:

```
NewDeviceProcedure:
  1. Generate new identity key pair (IK) on new device
  2. Publish new KEY_REGISTER transaction with new IK + prekey bundle
  3. All peers detect the new IK via on-chain key registry
  4. Each peer's node marks existing sessions as PendingReset (Section 4.2, Mechanism 3)
  5. Peers establish fresh sessions via PQXDH with the new IK
  6. User verifies safety numbers with contacts (Section 10)
```

The old device's sessions are abandoned. If the old device is still accessible, its session files should be securely deleted (overwrite + delete).

### 8.3 Same Identity Key, New Installation

If a user reinstalls on the same device and restores their identity key from backup but NOT their session state:

- The identity key is unchanged, so peers do not see a KEY_REGISTER change
- Peers' existing sessions will fail: sent messages are undecryptable
- Detection occurs via Mechanism 1 (Section 4.2): consecutive decryption failures
- After 5 consecutive failures, session is marked Suspended
- User or peer initiates reset (Section 5)

This scenario is unavoidable without session backup, which is deliberately not supported (Section 8.1).

---

## 9. Session Expiry

### 9.1 Expiry Conditions

Sessions have a maximum lifetime to prevent unbounded state drift and to periodically refresh all cryptographic material from scratch:

| Condition | Threshold | Rationale |
|-----------|-----------|-----------|
| Maximum wall-clock age | 30 days | Force periodic re-handshake with fresh prekeys |
| Maximum DH ratchet depth | 100,000 steps | Bound cumulative security reduction from ratchet chain |
| Maximum total messages | 500,000 | Prevent counter overflow risks (Word32 counters) |
| Inactivity timeout | 7 days | Reclaim resources for dormant sessions |

### 9.2 Expiry Check

```
CheckSessionExpiry(session, now):
  age = now - session.ssCreatedAt

  If age > 30 * 86400:                          -- 30 days in seconds
    return Expired("max_age_exceeded")

  If session.ssDHRatchetN > 100000:
    return Expired("max_ratchet_depth")

  total_msgs = session.ssRatchet.rsSendN + session.ssRatchet.rsRecvN
  If total_msgs > 500000:
    return Expired("max_messages")

  inactivity = now - session.ssLastActivity
  If inactivity > 7 * 86400 AND session.ssStatus == Active:
    return Expired("inactivity_timeout")

  return NotExpired
```

### 9.3 Expiry Handling

When a session expires:

1. Mark session as `Expired`
2. Persist the status change to disk
3. Notify user: "Session with <peer> has expired and will be refreshed on next message."
4. On next send attempt to this peer: execute full session reset (Section 5.3) and re-establish via PQXDH
5. On next receive from this peer: if decryption succeeds (peer's session still valid), continue with the old session until the current message exchange completes, then reset

### 9.4 Graceful Expiry vs. Hard Expiry

**Graceful expiry** (max age, inactivity): the session remains usable for receiving messages until the next send attempt triggers re-establishment. This prevents message loss.

**Hard expiry** (max ratchet depth, max messages): the session is immediately invalidated. No further send or receive operations are permitted. Re-handshake is mandatory. This protects against counter overflow and cumulative security degradation.

---

## 10. Peer Key Verification

### 10.1 Safety Number Computation

A safety number (fingerprint) is computed for each session to allow out-of-band verification:

```
SafetyNumber(local_ik, peer_ik):
  -- Concatenate in canonical order (lexicographic sort of public keys)
  If local_ik.public < peer_ik.public:        -- byte comparison
    combined = local_ik.public || peer_ik.public
  Else:
    combined = peer_ik.public || local_ik.public

  hash = SHA-256(
    "UmbraVox_SafetyNumber_v1" ||              -- domain separator
    combined                                    -- 64 bytes
  )

  -- Encode as 12 groups of 5 digits (60 digits total)
  -- Each group: interpret 2 bytes as uint16, mod 100000
  safety_number = ""
  For i in 0..11:
    val = uint16_be(hash[2*i .. 2*i+1]) * 65536
        + uint16_be(hash[2*i+16 .. 2*i+17])    -- use upper and lower halves
    group = val mod 100000
    safety_number += zero_pad(group, 5) ++ " "

  return safety_number     -- e.g., "12345 67890 11111 22222 ..."
```

The canonical ordering ensures both peers compute the same safety number regardless of who initiated the session.

### 10.2 Key Change Notification

When a peer's identity key changes (detected via on-chain KEY_REGISTER), the user MUST be notified with a prominent, non-dismissible alert:

```
Key Change Alert:
  "The security key for <peer_display_name> has changed.
   This could mean:
     - They reinstalled the application
     - They switched to a new device
     - Someone may be intercepting your messages

   Verify the new safety number with your contact
   before sending sensitive messages.

   New safety number: <new_safety_number>
   Previous safety number: <old_safety_number>"
```

### 10.3 Verification State

Each session tracks whether the safety number has been verified:

```haskell
data VerificationState
  = Unverified                  -- never verified by user
  | Verified !Word64            -- verified at timestamp
  | ChangedSinceVerification    -- key changed after prior verification
```

A verified session that undergoes a key change reverts to `ChangedSinceVerification`, which is displayed more prominently than `Unverified` to alert the user to a potential MITM attack.

---

## 11. Session State Size Management

### 11.1 Bounded State Growth

Session state growth is bounded by the following limits:

| Component | Maximum size | Bound mechanism |
|-----------|-------------|-----------------|
| Skipped keys cache | 64 KB (1,000 entries) | MAX_SKIP = 1,000 |
| DH ratchet keypair | 64 bytes | Fixed size, replaced on each step |
| Root key | 32 bytes | Fixed size |
| Chain keys (send + recv) | 64 bytes | Fixed size, advanced in place |
| PQ chain key | 32 bytes | Fixed size |
| Counters and metadata | ~100 bytes | Fixed size |
| **Total per session** | **~64.3 KB max** | |

### 11.2 Skipped Key Eviction

Skipped keys are evicted on every ratchet advance:

```
EvictStaleSkippedKeys(session):
  current_step = session.ssDHRatchetN
  For each (dh_pub, counter) in session.rsSkippedKeys:
    step_age = current_step - LookupRatchetStep(dh_pub)
    If step_age > 500:
      Erase session.rsSkippedKeys[(dh_pub, counter)]
      -- Secure erase: overwrite key bytes with zeros before removal
```

### 11.3 Garbage Collection Schedule

Periodic garbage collection runs on a background timer:

```
SessionGarbageCollection (runs every 60 seconds):
  now = current_time()
  For each session in session_map:
    1. EvictStaleSkippedKeys(session)
    2. Check expiry (Section 9.2)
    3. If session.ssStatus == Expired AND
       (now - session.ssLastActivity) > 7 * 86400:
         -- Expired and inactive for 7 days: full cleanup
         SecureDeleteSessionFiles(session)
         Remove from session_map
    4. If session.ssStatus == PendingReset AND
       (now - session status change time) > 24 * 3600:
         -- Pending reset for >24 hours: peer likely unreachable
         Mark as Expired
```

### 11.4 Maximum Active Sessions

The node enforces a maximum of 10,000 concurrent active sessions. This bounds total session state memory to approximately 643 MB (10,000 * 64.3 KB). If the limit is reached:

1. Evict the least-recently-active Expired session
2. If no Expired sessions exist, evict the least-recently-active Suspended session
3. If no Suspended sessions exist, reject the new session with an error

---

## 12. Formal Session Security Model

### 12.1 CK Model Instantiation for Sessions

We define session security in terms of the Canetti-Krawczyk (CK) authenticated key exchange model, extending `doc/proof-02-protocol-security.md` Section 1.1.

**Session oracle.** Each session S between parties (A, B) is modelled as a stateful oracle that maintains the ratchet state and responds to Send/Receive queries.

```
Session Oracle S_{A,B}:
  State: (RatchetState, PQChainKey, Counters, Status)
  Queries:
    - Send(m): encrypt m using current send chain, advance state, return ciphertext
    - Receive(ct): decrypt ct using current recv chain (or skipped keys), advance state
    - Reveal: expose current session state
    - Corrupt(party): expose long-term key of party
```

### 12.2 Session Security Properties

**Property 1: Resumption preserves forward secrecy.**

*Claim:* Loading a session from encrypted disk state and resuming operation preserves the forward secrecy guarantee of Theorem 2.1 (`doc/proof-02-protocol-security.md`).

*Argument:* The persisted state contains the current ratchet state (chain keys, DH keys) but NOT any prior chain keys or message keys (these are erased after use). On resumption, the loaded state is identical to the in-memory state at the moment of the last successful persistence. Forward secrecy holds for all messages prior to the persisted state because their keys were erased before persistence.

The storage encryption (AES-256-GCM with Argon2id-derived key) ensures that an adversary with disk access but without the passphrase cannot extract the ratchet state. The security of the persisted state reduces to:

```
Adv^{state-recovery}(A) <= Adv^{CCA}_{AES-GCM}(B_1)
                          + Adv^{passphrase}_{Argon2id}(B_2)
```

where `Adv^{passphrase}_{Argon2id}` is the adversary's advantage in recovering the passphrase given the Argon2id parameters (t=3, m=256MB, p=1).

**Property 2: Resumption preserves post-compromise security.**

*Claim:* After session resumption, the post-compromise security guarantee of Theorem 2.2 (`doc/proof-02-protocol-security.md`) is preserved: the first DH ratchet step with a fresh ephemeral key after resumption restores confidentiality.

*Argument:* The resumed session generates a fresh ephemeral DH keypair on the next send operation, exactly as it would without interruption. The fresh DH secret is generated from the CSPRNG (reseeded from `/dev/urandom` on startup per `doc/03-cryptography.md` line 43). The CDH assumption ensures the new DH output is indistinguishable from random, restoring post-compromise security.

**Property 3: Session reset preserves all security properties.**

*Claim:* A session reset followed by fresh PQXDH re-establishment produces a session with security equivalent to the initial session.

*Argument:* The reset procedure (Section 5.3) erases all old session state (secure erasure of keys from memory, overwrite of disk files). The new session is established via a fresh PQXDH handshake with new ephemeral keys, new OPK (if available), and fresh ML-KEM encapsulation. By Theorem 1.1 (`doc/proof-02-protocol-security.md`), the new session key is indistinguishable from random under the hybrid CDH/Module-LWE assumption. The new session inherits no state from the old session.

**Property 4: Skipped key cache does not break session isolation.**

*Claim:* Skipped keys from session S1 (before reset) cannot be used to decrypt messages in session S2 (after reset).

*Argument:* Session reset erases all skipped keys (Section 5.3, step 2). Session S2 uses entirely new chain keys derived from a fresh master secret. Even if skipped keys from S1 were not erased (a bug), they are keyed to specific (DH_pub, counter) pairs from S1's ratchet chain. S2's DH ratchet uses fresh ephemeral keys, so no (DH_pub, counter) collision can occur (the DH public keys differ with overwhelming probability).

### 12.3 Formal Advantage Bound

**Theorem 12.1 (Session Lifecycle Security).** For any PPT adversary A who may:
- Observe all on-chain data
- Reveal session state at any point (state compromise)
- Trigger session resets
- Deliver messages out of order

the advantage of A in distinguishing a real session (including persistence, resumption, and reset cycles) from an ideal session (where all message keys are truly random) is bounded by:

```
Adv^{session}(A) <= Adv^{AKE}_{PQXDH}(A_1)        -- Theorem 1.1
                  + n * Adv^{PRF}_{HMAC}(A_2)       -- Theorem 2.1 (n = chain length)
                  + Adv^{CDH}(A_3)                   -- Theorem 2.2 (PCS)
                  + k * Adv^{CCA}_{ML-KEM}(A_4)     -- Theorem 3.1 (k = PQ refreshes)
                  + Adv^{CCA}_{AES-GCM}(A_5)        -- storage encryption
                  + Adv^{passphrase}_{Argon2id}(A_6) -- passphrase brute-force
                  + r * Adv^{AKE}_{PQXDH}(A_7)      -- r = number of resets
```

where r is the number of session resets during the session lifecycle. Each reset introduces an independent PQXDH security term because each re-establishment is a fresh key exchange.

### 12.4 Formal Verification Requirement

Per DO-178C DAL A / DO-333 requirements:

**Deliverable:** `test/evidence/formal-proofs/session-lifecycle-security.v`

The Coq proof must:
1. Model the session state machine (Active, Suspended, PendingReset, Expired) as an inductive type
2. Define the persistence and resumption operations as state transitions
3. Prove that each transition preserves the forward secrecy invariant
4. Prove that reset followed by re-establishment produces an independent session
5. State all assumptions (CDH, Module-LWE, PRF, Argon2id passphrase hardness) as explicit axioms

---

## 13. Implementation Checklist

| Task | Module | Dependency |
|------|--------|------------|
| Define `SessionState`, `SessionStatus` types | `UmbraVox.Signal.Session` | `doc/03-cryptography.md` |
| Implement `SessionMap` with `TMVar` locking | `UmbraVox.Signal.SessionMap` | STM |
| Session file encryption (write + read) | `UmbraVox.Signal.SessionStore` | AES-256-GCM, Argon2id |
| Atomic write (tmp + rename + fsync) | `UmbraVox.Signal.SessionStore` | POSIX |
| Session resumption on startup | `UmbraVox.Signal.SessionStore` | SessionStore |
| Integrity MAC (HMAC-SHA-256) on session state | `UmbraVox.Signal.SessionStore` | HMAC |
| Stale session detection (3 mechanisms) | `UmbraVox.Signal.SessionHealth` | SessionMap |
| Session reset protocol (secure erasure + re-handshake) | `UmbraVox.Signal.SessionReset` | SessionStore, PQXDH |
| Session expiry checks (age, depth, inactivity) | `UmbraVox.Signal.SessionHealth` | SessionMap |
| Safety number computation | `UmbraVox.Signal.SafetyNumber` | SHA-256 |
| Key change notification | `UmbraVox.Signal.KeyChange` | On-chain key registry |
| Skipped key eviction (500-step window) | `UmbraVox.Signal.Ratchet` | RatchetState |
| Session garbage collection (background timer) | `UmbraVox.Signal.SessionGC` | SessionMap |
| Per-session concurrency lock (`TMVar`) | `UmbraVox.Signal.SessionMap` | STM |
| Session state size bounds enforcement | `UmbraVox.Signal.SessionMap` | Config |
| Formal proof: session lifecycle security (Coq) | `test/evidence/formal-proofs/` | Proof artifact |
