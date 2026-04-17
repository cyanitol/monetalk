# Hardening-07: GCM Nonce Safety

**Severity:** CATASTROPHIC if violated
**Scope:** All AES-256-GCM encryption in Signal Double Ratchet and PQ outer wrapper
**Source requirements:** NIST SP 800-38D Section 8.2; Proof-07 Section 5.2; `doc/03-cryptography.md` lines 126-158

---

## Threat Summary

GCM nonce reuse under the same key allows an adversary to:

1. Recover the GHASH authentication key H = AES(K, 0^{128}) via polynomial GCD over GF(2^{128})
2. Forge arbitrary (ciphertext, tag) pairs for any associated data
3. Recover XOR of plaintexts encrypted under the reused nonce

This is the single most critical implementation invariant in the entire cryptographic stack. Every other security property -- confidentiality, integrity, authentication -- collapses if a (key, nonce) pair repeats.

---

## 1. Nonce Construction

### 1.1 Byte Layout

The 12-byte (96-bit) GCM nonce is constructed deterministically from the ratchet state:

```
Byte offset:  0   1   2   3   4   5   6   7   8   9  10  11
            |---- chain_id ----|------- message_number ------|
            [  4 bytes, BE     ] [  4 bytes, BE              ]
                                          [ 4 bytes zero-pad ]

Full layout:
  nonce[0..3]  = chain_id       (big-endian uint32)
  nonce[4..7]  = message_number (big-endian uint32)
  nonce[8..11] = 0x00 0x00 0x00 0x00
```

### 1.2 Field Definitions

| Field | Type | Source | Semantics |
|-------|------|--------|-----------|
| `chain_id` | `Word32` | Truncated hash of the sending chain key: `truncate32(SHA-256(send_chain_key))` | Identifies the ratchet chain. Changes on every DH ratchet step. |
| `message_number` | `Word32` | `rsSendN` or `rsRecvN` from `RatchetState` | Per-chain monotonic counter. Starts at 0 for each new chain. |
| padding | fixed | Constant `0x00000000` | Reserved. Ensures full 96-bit nonce width. |

### 1.3 Endianness

All multi-byte integers are encoded **big-endian** (network byte order). This is a fixed convention; implementations MUST NOT use platform-native endianness.

### 1.4 Pseudocode

```haskell
buildNonce :: ByteString -> Word32 -> ByteString
buildNonce sendChainKey messageNumber =
  let chainId    = truncate32 (sha256 sendChainKey)  -- first 4 bytes of hash
      nonceBytes = toBE32 chainId
                <> toBE32 messageNumber
                <> BS.pack [0x00, 0x00, 0x00, 0x00]
  in assert (BS.length nonceBytes == 12) nonceBytes

-- toBE32 encodes a Word32 as 4 bytes, most significant byte first.
toBE32 :: Word32 -> ByteString
toBE32 w = BS.pack
  [ fromIntegral (w `shiftR` 24)
  , fromIntegral (w `shiftR` 16)
  , fromIntegral (w `shiftR` 8)
  , fromIntegral w
  ]

-- truncate32 takes the first 4 bytes of a ByteString as a Word32.
truncate32 :: ByteString -> Word32
truncate32 bs =
  let [b0, b1, b2, b3] = BS.unpack (BS.take 4 bs)
  in (fromIntegral b0 `shiftL` 24)
   .|. (fromIntegral b1 `shiftL` 16)
   .|. (fromIntegral b2 `shiftL` 8)
   .|. fromIntegral b3
```

### 1.5 PQ Outer Wrapper Nonce

The PQ outer wrapper uses an independent nonce counter (`pqSendN`) with the same 12-byte layout but a different `chain_id` derived from the PQ chain key:

```
pq_nonce[0..3]  = truncate32(SHA-256(pq_chain_key))  (big-endian)
pq_nonce[4..7]  = pqSendN                            (big-endian)
pq_nonce[8..11] = 0x00 0x00 0x00 0x00
```

The PQ wrapper key is always distinct from the Signal-layer message key (derived through independent HKDF branches), so even if the nonce bit patterns coincidentally collide, the (key, nonce) pair never repeats.

---

## 2. Monotonicity Invariant

### 2.1 Formal Statement

**Invariant MON-1 (Send Counter Monotonicity).**
For each session S and each ratchet chain C identified by a unique sending chain key `ck`, the send counter `n` satisfies:

```
For all encryptions E_i, E_j under (S, ck):
  i < j  ==>  n_i < n_j
```

Equivalently: the counter is strictly monotonically increasing. It is never decremented, never held constant across two encryptions, and never reset to a previously used value within the same chain.

**Invariant MON-2 (Receive Counter Monotonicity).**
The same property holds for the receive counter within each receive chain. Out-of-order messages use skipped-key storage (Section 2.3) rather than counter regression.

### 2.2 Implementation Rule

The counter increment is the FIRST operation in the encrypt path, performed BEFORE the plaintext is read or the ciphertext is computed:

```haskell
encryptMessage :: RatchetState -> ByteString -> IO (RatchetState, ByteString)
encryptMessage rs plaintext = do
  -- Step 1: Derive message key from current chain state
  let messageKey = hmac (rsSendChain rs) (BS.singleton 0x01)
      nextChain  = hmac (rsSendChain rs) (BS.singleton 0x02)
      currentN   = rsSendN rs

  -- Step 2: Build nonce from current counter (BEFORE incrementing)
  let nonce = buildNonce (rsSendChain rs) currentN

  -- Step 3: Encrypt
  let ciphertext = aes256gcmEncrypt messageKey nonce plaintext

  -- Step 4: Increment counter and advance chain (ATOMIC with step 3)
  let rs' = rs { rsSendChain = nextChain
               , rsSendN     = currentN + 1
               }

  -- Step 5: Persist new state BEFORE releasing ciphertext (see Section 3)
  persistRatchetState rs'

  return (rs', ciphertext)
```

### 2.3 Out-of-Order Messages

Decryption of out-of-order messages does NOT decrement `rsRecvN`. Instead:

1. If `message_number < rsRecvN`, look up the message key in `rsSkippedKeys`.
2. If found, decrypt with the stored key, then DELETE the key from `rsSkippedKeys`.
3. If not found, reject the message (the key was already evicted or never stored).

The receive counter only ever moves forward. Skipped keys are consumed exactly once.

---

## 3. Counter Persistence

### 3.1 The Crash-Reuse Problem

If the counter is incremented only in memory and the process crashes after encrypting but before persisting, the recovered state contains the old (pre-increment) counter value. The next encryption after recovery reuses the nonce. This is catastrophic.

### 3.2 Write-Before-Encrypt Protocol

**Invariant PERSIST-1.** The counter value N+1 MUST be durably persisted to stable storage BEFORE the encryption using counter value N is performed.

```haskell
encryptMessageSafe :: RatchetState -> ByteString -> IO (RatchetState, ByteString)
encryptMessageSafe rs plaintext = do
  let currentN   = rsSendN rs
      messageKey = hmac (rsSendChain rs) (BS.singleton 0x01)
      nextChain  = hmac (rsSendChain rs) (BS.singleton 0x02)
      nonce      = buildNonce (rsSendChain rs) currentN

  -- PRE-PERSIST: Write the NEXT counter value to disk BEFORE encrypting.
  -- If we crash after this point but before encrypting, we waste one
  -- counter value. This is harmless: a skipped counter means the nonce
  -- is never used, not used twice.
  let rs' = rs { rsSendChain = nextChain
               , rsSendN     = currentN + 1
               }
  persistRatchetStateDurable rs'
  -- persistRatchetStateDurable calls fsync() / fdatasync() to guarantee
  -- the write has reached stable storage before returning.

  -- NOW encrypt with the old counter value.
  let ciphertext = aes256gcmEncrypt messageKey nonce plaintext

  return (rs', ciphertext)
```

### 3.3 Persistence Mechanics

```haskell
persistRatchetStateDurable :: RatchetState -> IO ()
persistRatchetStateDurable rs = do
  let encoded = serializeRatchetState rs
  -- Write to a temporary file, then atomically rename.
  -- This prevents partial writes from corrupting state.
  BS.writeFile (stateFilePath <> ".tmp") encoded
  fdatasync (stateFilePath <> ".tmp")
  renameFile (stateFilePath <> ".tmp") stateFilePath
  fdatasync (parentDirectory stateFilePath)
```

The atomic rename pattern ensures that the state file is always either the old complete state or the new complete state, never a partial write.

### 3.4 Crash Recovery Analysis

| Crash point | State on disk | Counter in memory | Result |
|-------------|--------------|-------------------|--------|
| Before `persistRatchetStateDurable` | N | N | Next encrypt uses N. No reuse. |
| After `persistRatchetStateDurable`, before `aes256gcmEncrypt` | N+1 | N | Counter N was never used for encryption. N+1 will be used next. Counter N is wasted (harmless skip). |
| After `aes256gcmEncrypt`, before returning | N+1 | N+1 | Normal completion. Ciphertext may or may not have been transmitted; recipient handles missing messages via skipped-key mechanism. |

In all cases, no nonce is ever used twice. The worst case is wasting a counter value, which is safe because an unused nonce cannot cause a collision.

---

## 4. Counter Overflow

### 4.1 Overflow Threshold

The message counter is a `Word32` (unsigned 32-bit integer). The maximum value is 2^32 - 1 = 4,294,967,295.

### 4.2 Mandatory Ratchet on Overflow

**Invariant OVERFLOW-1.** When `rsSendN` reaches 2^32 - 1, the implementation MUST perform a DH ratchet step (generating a new ephemeral key and deriving a new chain key) before any further encryption. The counter MUST NEVER wrap to 0 under the same key.

```haskell
encryptWithOverflowCheck :: RatchetState -> ByteString -> IO (RatchetState, ByteString)
encryptWithOverflowCheck rs plaintext = do
  when (rsSendN rs >= maxCounter) $ do
    -- MANDATORY ratchet step. This produces a new chain key,
    -- making counter reset to 0 safe (different key).
    rs <- performDHRatchetStep rs
    return ()
  encryptMessageSafe rs plaintext

maxCounter :: Word32
maxCounter = 0xFFFFFFFF  -- 2^32 - 1
```

### 4.3 Why Not Wrap?

Wrapping the counter to 0 would produce a nonce identical to the one used for the first message in the same chain. Since the chain key (and hence the AES key) has not changed, this is a (key, nonce) repetition. Catastrophic. The mandatory ratchet step introduces a new key, making counter 0 safe again.

### 4.4 Practical Note

A single ratchet chain processing 2^32 messages (~4 billion) at 1 message/ms would take ~50 days. In practice, DH ratchet steps occur on every reply (alternating directions), so a chain rarely exceeds a few hundred messages. The overflow guard is defense in depth.

---

## 5. Multi-Threaded Safety

### 5.1 Threat Model

If two threads concurrently call `encryptMessageSafe` on the same `RatchetState`, both could read the same counter value N, both persist N+1, and both encrypt with nonce N. This is a nonce reuse.

### 5.2 Architecture: Single-Writer

**Invariant THREAD-1.** Each session's ratchet state is owned by exactly one thread (the session thread). All encrypt and decrypt operations for a given session are serialized through this single owner.

There is no concurrent access to ratchet state. The session thread processes messages sequentially from an inbound queue.

```
                     +-------------------+
  Plaintext msg ---> | Session Thread    | ---> Ciphertext
  Plaintext msg ---> | (single writer)   | ---> Ciphertext
                     | owns RatchetState |
                     +-------------------+
```

### 5.3 Enforcement

```haskell
data Session = Session
  { sessRatchet  :: !(IORef RatchetState)   -- Owned exclusively by session thread
  , sessThreadId :: !ThreadId               -- The owning thread
  , sessInbox    :: !(TQueue PlaintextMsg)  -- Inbound message queue
  }

-- Called only from the session thread. Asserts ownership.
withSessionState :: Session -> (RatchetState -> IO (RatchetState, a)) -> IO a
withSessionState sess action = do
  tid <- myThreadId
  when (tid /= sessThreadId sess) $
    error "FATAL: ratchet state accessed from non-owner thread. Terminating."
  rs <- readIORef (sessRatchet sess)
  (rs', result) <- action rs
  writeIORef (sessRatchet sess) rs'
  return result
```

### 5.4 Alternative: Atomic Increment (NOT Recommended)

If single-writer cannot be guaranteed, the fallback is atomic compare-and-swap on the counter:

```haskell
atomicGetAndIncrementCounter :: IORef Word32 -> IO Word32
atomicGetAndIncrementCounter ref = atomicModifyIORef' ref (\n -> (n + 1, n))
```

This prevents two threads from reading the same counter. However, it does NOT solve the broader problem: the chain key also advances, and concurrent encryption under the same chain key produces two ciphertexts with the same message key. Single-writer is the only correct architecture.

---

## 6. Ratchet Step Nonce Reset

### 6.1 Counter Reset on New Chain

When a DH ratchet step occurs, a new sending chain key is derived:

```
new_root_key, new_send_chain = HKDF(
  salt = current_root_key,
  ikm  = X25519(new_ephemeral_secret, peer_public),
  info = "UmbraVox_Ratchet_v1"
)
```

The send counter resets to 0:

```haskell
performDHRatchetStep :: RatchetState -> IO RatchetState
performDHRatchetStep rs = do
  (newSecret, newPublic) <- generateX25519Keypair
  let dhOutput = x25519 newSecret (rsDHRecv rs)
      (newRootKey, newSendChain) = hkdfRatchet (rsRootKey rs) dhOutput
  return rs
    { rsDHSend    = (newSecret, newPublic)
    , rsRootKey   = newRootKey
    , rsSendChain = newSendChain
    , rsSendN     = 0              -- RESET: safe because key is different
    , rsPrevChainN = rsSendN rs    -- Record how far the old chain went
    }
```

### 6.2 Why This Is Safe

The AES-256-GCM key for the new chain is derived from `newSendChain`, which is the output of HKDF keyed with fresh DH output. This key is computationally independent of any previous chain key (by the PRF property of HKDF, Proof-01 Section 3). Therefore:

- Old chain: key K_old, nonces 0, 1, 2, ..., N
- New chain: key K_new, nonces 0, 1, 2, ..., M

Since K_old != K_new (with overwhelming probability), the pairs (K_old, 0) and (K_new, 0) are distinct. GCM security is per-key; cross-key nonce collision is irrelevant.

### 6.3 PQ Ratchet Refresh

The PQ outer wrapper performs an analogous reset every 50 messages per direction. A fresh ML-KEM encapsulation produces a new PQ shared secret, from which a new PQ chain key is derived via HKDF. The PQ send counter resets to 0. The same safety argument applies: new key, so counter reset is safe.

---

## 7. Formal Proof of Uniqueness

### 7.1 State Machine Definition

Define the ratchet state machine as a tuple:

```
S = (K, n, direction, phase)
```

where:
- K: current AES-256-GCM key (derived from chain key via HMAC)
- n: message counter (Word32, range [0, 2^32 - 1])
- direction: SEND or RECV
- phase: ACTIVE or RATCHETING

Transitions:

```
T1 (Encrypt):  (K, n, SEND, ACTIVE) --> (K, n+1, SEND, ACTIVE)
               Precondition: n < 2^32 - 1
               Action: encrypt with nonce(K, n)

T2 (Overflow): (K, 2^32-1, SEND, ACTIVE) --> (K', 0, SEND, ACTIVE)
               Action: DH ratchet step, derive fresh K'
               Precondition: K' != K (guaranteed by HKDF with fresh DH)

T3 (DH Ratchet): (K, n, SEND, ACTIVE) --> (K', 0, SEND, ACTIVE)
                  Action: DH ratchet step triggered by incoming message
                  Precondition: K' derived from fresh DH, K' != K

T4 (PQ Refresh): (K_pq, n, SEND, ACTIVE) --> (K_pq', 0, SEND, ACTIVE)
                  Action: ML-KEM ratchet refresh (every 50 messages)
                  Precondition: K_pq' derived from fresh ML-KEM encapsulation
```

### 7.2 Uniqueness Theorem

**Theorem NONCE-UNIQUE.** For all reachable states in the ratchet state machine, no (key, nonce) pair is produced more than once.

**Proof.** By structural induction on the state transition sequence.

**Base case.** The initial state after PQXDH has counter n = 0 and a fresh key K_0 derived from the PQXDH master secret. No encryption has occurred. The set of used (key, nonce) pairs is empty. The invariant holds vacuously.

**Inductive step.** Assume the invariant holds after transition sequence T_1, ..., T_i. We show it holds after T_{i+1}.

**Case T1 (Encrypt):** The encryption uses (K, n) where n = current counter. By the inductive hypothesis, (K, n) has not been used before (since the counter was incremented after every prior encryption under K, and n is the current value which has not yet been used). After the transition, the counter becomes n+1. The pair (K, n) is now in the used set, and no future T1 transition under K can produce it (since the counter only increases and n+1 > n).

**Case T2 (Overflow):** The counter has reached 2^32 - 1. A DH ratchet step produces a new key K'. By the PRF property of HKDF with fresh DH input (Proof-01 Section 3), K' is computationally independent of all prior keys. The probability that K' equals any previously used key is at most q / 2^{256} where q is the number of prior keys (negligible). The counter resets to 0. Since K' is new, (K', 0) has never been used.

**Case T3 (DH Ratchet):** Identical argument to T2. Fresh DH output ensures a new key.

**Case T4 (PQ Refresh):** Fresh ML-KEM encapsulation produces a new shared secret. HKDF derivation with this secret produces a new PQ key K_pq'. By the IND-CCA2 security of ML-KEM-768 (Proof-01 Section 7), K_pq' is computationally independent of all prior PQ keys. Counter resets to 0 under the new key. Same argument as T2.

**Error paths:**

- **Decryption failure (invalid tag):** No state change. Counter not modified. No nonce consumed. Invariant preserved.
- **Skipped message processing:** Uses a stored key from `rsSkippedKeys`, not the current chain key. The skipped key is deleted after use, so it can never be used again. The nonce for the skipped message was determined at the time the key was stored and is unique by the same monotonicity argument applied to the sender's chain.
- **Session termination:** No further encryptions. Invariant trivially preserved.
- **Crash recovery:** By PERSIST-1 (Section 3), the persisted counter is always >= the highest counter value used for encryption. After recovery, the next encryption uses a counter value that has never been used for encryption under the current key (it may have been persisted but not encrypted with, which is safe).

**Conclusion.** The invariant holds for all reachable states and all transition paths, including error recovery. No (key, nonce) pair is ever repeated.  QED

### 7.3 Assumptions Required

The proof relies on:

1. **A4 (HMAC-SHA-512 PRF):** Ensures HKDF-derived keys are computationally independent.
2. **A1 (CDH on Curve25519):** Ensures DH ratchet steps produce unpredictable shared secrets.
3. **A2 (Module-LWE):** Ensures ML-KEM ratchet refreshes produce unpredictable shared secrets.
4. **PERSIST-1:** Counter is durably persisted before encryption.
5. **THREAD-1:** Single-writer access to ratchet state.

---

## 8. Testing Strategy

### 8.1 Property-Based Test: No (Key, Nonce) Pair Repeats

```haskell
-- QuickCheck / Hedgehog property: generate a random sequence of operations,
-- execute them against the ratchet state machine, collect all (key, nonce)
-- pairs, and verify uniqueness.

data RatchetOp
  = OpEncrypt               -- encrypt a message (advances counter)
  | OpDHRatchet             -- perform a DH ratchet step (new key, counter -> 0)
  | OpPQRefresh             -- perform PQ ratchet refresh (new PQ key, counter -> 0)
  | OpSkip Word8            -- skip 1-255 messages (advance counter without encrypting)
  | OpCrashRecover          -- simulate crash: reload state from last persist point
  deriving (Show)

genOps :: Gen [RatchetOp]
genOps = listOf1 $ frequency
  [ (70, pure OpEncrypt)
  , (10, pure OpDHRatchet)
  , (5,  pure OpPQRefresh)
  , (10, OpSkip <$> choose (1, 255))
  , (5,  pure OpCrashRecover)
  ]

prop_nonceUniqueness :: Property
prop_nonceUniqueness = forAll genOps $ \ops ->
  let pairs = executeAndCollect initialState ops
  in nub pairs == pairs  -- no duplicates

-- executeAndCollect: runs each operation against a simulated ratchet,
-- returns the list of (key, nonce) pairs actually used for encryption.
executeAndCollect :: RatchetState -> [RatchetOp] -> [(ByteString, ByteString)]
executeAndCollect _ [] = []
executeAndCollect rs (OpEncrypt : rest) =
  let key   = deriveMessageKey (rsSendChain rs)
      nonce = buildNonce (rsSendChain rs) (rsSendN rs)
      rs'   = rs { rsSendN = rsSendN rs + 1
                 , rsSendChain = advanceChain (rsSendChain rs)
                 }
  in (key, nonce) : executeAndCollect rs' rest
executeAndCollect rs (OpDHRatchet : rest) =
  let rs' = simulateDHRatchet rs  -- new chain key, counter = 0
  in executeAndCollect rs' rest
executeAndCollect rs (OpPQRefresh : rest) =
  let rs' = simulatePQRefresh rs  -- new PQ key, PQ counter = 0
  in executeAndCollect rs' rest
executeAndCollect rs (OpSkip n : rest) =
  let rs' = rs { rsSendN = rsSendN rs + fromIntegral n }
  in executeAndCollect rs' rest
executeAndCollect rs (OpCrashRecover : rest) =
  let rs' = loadPersistedState rs  -- simulates reload from disk
  in executeAndCollect rs' rest
```

### 8.2 Minimum Test Parameters

| Parameter | Value |
|-----------|-------|
| Number of random operation sequences | 100,000 |
| Maximum sequence length | 10,000 operations |
| Minimum sequence length | 100 operations |
| Counter values tested near overflow | Explicit test with `rsSendN = 0xFFFFFFFE` |
| Crash recovery sequences tested | At least 10,000 sequences with >= 1 crash |

### 8.3 Deterministic Edge Case Tests

```haskell
-- Test 1: Counter at overflow boundary
test_overflowBoundary :: Assertion
test_overflowBoundary = do
  let rs = initialState { rsSendN = 0xFFFFFFFE }
  -- Encrypt at 0xFFFFFFFE: should succeed
  (rs1, _) <- encryptMessageSafe rs "msg1"
  assertEqual (rsSendN rs1) 0xFFFFFFFF
  -- Next encrypt MUST trigger ratchet, not wrap
  (rs2, _) <- encryptWithOverflowCheck rs1 "msg2"
  assertEqual (rsSendN rs2) 1  -- new chain, started at 0, incremented to 1
  assertNotEqual (rsSendChain rs1) (rsSendChain rs2)

-- Test 2: Crash between persist and encrypt
test_crashAfterPersist :: Assertion
test_crashAfterPersist = do
  let rs = initialState { rsSendN = 42 }
  -- Simulate: persistRatchetStateDurable writes n=43, then crash
  persistRatchetStateDurable (rs { rsSendN = 43 })
  -- Recovery: load from disk
  rsRecovered <- loadRatchetState
  assertEqual (rsSendN rsRecovered) 43
  -- Counter 42 was never used for encryption. 43 will be used next.
  -- No reuse possible.

-- Test 3: Concurrent access detection
test_wrongThreadPanics :: Assertion
test_wrongThreadPanics = do
  sess <- createSession
  -- Attempt access from a different thread
  result <- try $ forkIO $ withSessionState sess (\rs -> return (rs, ()))
  assertThrows result
```

### 8.4 CI Integration

The nonce uniqueness property tests MUST run on every commit. They are included in the `test/crypto/` test suite with a dedicated module `test/crypto/NonceUniquenessSpec.hs`. Failure of any nonce uniqueness test is a build-breaking error.

---

## 9. Detection Mechanism (Defense in Depth)

### 9.1 Runtime Nonce Reuse Assertion

Even with structural guarantees, a runtime check provides defense in depth against implementation bugs, memory corruption, or cosmic ray bit flips.

```haskell
data NonceLog = NonceLog
  { nlLastNonce :: !(IORef Word32)   -- last counter value used for encryption
  , nlChainKey  :: !(IORef ByteString) -- chain key when nlLastNonce was set
  }

assertNonceNotReused :: NonceLog -> ByteString -> Word32 -> IO ()
assertNonceNotReused nl currentChainKey currentN = do
  lastN   <- readIORef (nlLastNonce nl)
  lastKey <- readIORef (nlChainKey nl)
  when (lastKey == currentChainKey && currentN <= lastN) $ do
    -- NONCE REUSE DETECTED. This should be structurally impossible.
    -- If we reach here, there is a critical bug.
    emergencySessionTermination
      "FATAL: GCM nonce reuse detected. Session terminated. All keys erased."
  -- Record current values
  writeIORef (nlLastNonce nl) currentN
  writeIORef (nlChainKey nl) currentChainKey
```

### 9.2 Invariant Check Placement

The assertion is placed immediately before the call to `aes256gcmEncrypt`:

```haskell
encryptMessageFinal :: Session -> RatchetState -> ByteString -> IO (RatchetState, ByteString)
encryptMessageFinal sess rs plaintext = do
  let messageKey = hmac (rsSendChain rs) (BS.singleton 0x01)
      nextChain  = hmac (rsSendChain rs) (BS.singleton 0x02)
      currentN   = rsSendN rs
      nonce      = buildNonce (rsSendChain rs) currentN

  -- Pre-persist (Section 3)
  let rs' = rs { rsSendChain = nextChain, rsSendN = currentN + 1 }
  persistRatchetStateDurable rs'

  -- DEFENSE IN DEPTH: assert nonce uniqueness before encrypting
  assertNonceNotReused (sessNonceLog sess) (rsSendChain rs) currentN

  -- Encrypt
  let ciphertext = aes256gcmEncrypt messageKey nonce plaintext

  return (rs', ciphertext)
```

### 9.3 Response to Detection

If `assertNonceNotReused` fires:

1. **Immediately halt all encryption** under the affected session.
2. **Erase all keys** in the session's ratchet state (overwrite with zeros).
3. **Terminate the session.** The session cannot be resumed.
4. **Log a CRITICAL alert** with: timestamp, session ID, chain key fingerprint, counter values (old and new). Do NOT log any key material.
5. **Notify the user** that the session has been terminated due to a critical security error and a new session must be established.

This is identical to the recovery procedure in Section 11.

---

## 10. Comparison with Alternatives

### 10.1 Random Nonces

**Approach:** Generate each 96-bit nonce uniformly at random.

**Why rejected:**

The birthday bound for collisions in a 96-bit space is approximately 2^{48} messages:

```
Pr[collision among q nonces] >= 1 - e^{-q^2 / (2 * 2^96)}

At q = 2^{48}: Pr >= 1 - e^{-1} approx 0.63
```

While 2^{48} messages per key is large, it is not astronomically large. A paranoid security posture rejects any design where the nonce uniqueness guarantee is probabilistic rather than deterministic. The deterministic counter approach provides a **mathematical guarantee** (not a probabilistic bound) that no collision occurs within 2^{32} messages per key, with mandatory re-keying at the boundary.

Additionally, random nonce generation requires a functioning CSPRNG at every encryption call. If the CSPRNG fails, degrades, or is improperly seeded (e.g., after fork without reseed), random nonces can collide silently. The deterministic counter has no such dependency.

### 10.2 AES-GCM-SIV (Nonce-Misuse Resistant)

**Approach:** Use AES-GCM-SIV (RFC 8452), which provides IND-CPA security even under nonce reuse.

**Why rejected:**

1. **Not in the UmbraVox primitive set.** The cryptographic architecture (`doc/03-cryptography.md`) specifies AES-256-GCM per NIST SP 800-38D. Adding AES-GCM-SIV would require implementing and certifying an additional primitive (the POLYVAL universal hash, double AES-ECB pass for tag derivation).

2. **Performance.** AES-GCM-SIV requires two passes over the plaintext (one for POLYVAL, one for AES-CTR encryption), compared to GCM's single pass. For a chat application with short messages this is marginal, but it doubles the AES invocations.

3. **Weaker guarantee on reuse.** AES-GCM-SIV provides IND-CPA (not IND-CCA2) under nonce reuse. An adversary can still detect if two messages are identical. With GCM and a guaranteed-unique nonce, full IND-CCA2 holds.

4. **False sense of safety.** Adopting a nonce-misuse-resistant cipher can lead to relaxed discipline around nonce management. The correct engineering response to "nonce reuse is catastrophic" is to make nonce reuse structurally impossible, not to weaken the consequences.

### 10.3 XChaCha20-Poly1305

**Approach:** Use XChaCha20-Poly1305 with 192-bit nonces, where the birthday bound is at 2^{96} messages.

**Why rejected:**

1. **Not in the primitive set.** Same rationale as AES-GCM-SIV.
2. **AES-NI advantage.** AES-256-GCM with hardware acceleration (AES-NI + PCLMULQDQ) is faster than ChaCha20-Poly1305 on modern x86 hardware. Since UmbraVox already requires AES-256 for the primitive set, there is no performance benefit.
3. **The deterministic counter already provides an absolute guarantee.** A 192-bit random nonce space makes collisions negligibly unlikely, but "negligibly unlikely" is strictly weaker than "structurally impossible."

---

## 11. Recovery from Nonce Reuse

### 11.1 If Nonce Reuse Is Detected

If the runtime assertion (Section 9) or any other mechanism detects that a (key, nonce) pair has been or would be reused:

```haskell
emergencySessionTermination :: String -> IO ()
emergencySessionTermination reason = do
  -- 1. Log the event (no key material in log)
  logCritical reason

  -- 2. Erase ALL session keys from memory
  --    Overwrite with zeros, then unmap.
  eraseRatchetState currentSession
  eraseSkippedKeys currentSession
  erasePQChainState currentSession

  -- 3. Erase persisted session state from disk
  secureDeleteFile (sessionStatePath currentSession)

  -- 4. Mark session as TERMINATED in the session registry
  markSessionTerminated (sessionId currentSession)

  -- 5. Alert the user
  notifyUser currentSession SecurityAlert
    { alertSeverity = CRITICAL
    , alertMessage  = "Session terminated: cryptographic safety violation. "
                   <> "A new secure session must be established. "
                   <> "Messages sent in this session should be considered "
                   <> "potentially compromised."
    , alertAction   = "Initiate new PQXDH handshake with peer."
    }

  -- 6. The session cannot be resumed. A new PQXDH handshake is required.
  --    The old session's identity key is NOT compromised (nonce reuse
  --    affects only the symmetric layer), so the same identity key
  --    can be reused for the new session.
```

### 11.2 What Is Compromised

If a nonce WAS reused (not merely detected before use):

| Asset | Status |
|-------|--------|
| GHASH key H = AES(K, 0^{128}) | **COMPROMISED** for the affected key K. Adversary can forge tags. |
| Plaintext XOR of the two messages | **LEAKED.** Adversary obtains m1 XOR m2 for the two messages encrypted with the reused nonce. |
| The AES key K itself | **Not directly compromised.** Nonce reuse leaks H and plaintext XOR, not the key. |
| Other ratchet chain keys | **Not compromised.** Keys are derived independently via HKDF. |
| Identity key (IK) | **Not compromised.** Asymmetric keys are unaffected by symmetric nonce reuse. |
| Messages under other keys in the same session | **Not compromised** unless those keys also suffered nonce reuse. |

### 11.3 Post-Incident Actions

1. Terminate the session (Section 11.1).
2. Require a new PQXDH handshake to establish a fresh session.
3. Investigate the root cause. Nonce reuse indicates a critical implementation bug: state corruption, concurrency violation, or persistence failure.
4. The bug MUST be fixed before any new session is allowed to proceed. If the root cause cannot be determined, the node should refuse to encrypt until the issue is resolved.

---

## Summary of Invariants

| ID | Invariant | Enforced By |
|----|-----------|-------------|
| MON-1 | Send counter strictly monotonically increases within each chain | Increment-before-return in encrypt path |
| MON-2 | Receive counter strictly monotonically increases; out-of-order via skipped keys | Skipped key lookup; counter never decremented |
| PERSIST-1 | Counter N+1 persisted to stable storage before encryption with counter N | Write-before-encrypt protocol with fsync + atomic rename |
| OVERFLOW-1 | Counter at 2^32-1 triggers mandatory ratchet step; never wraps | Pre-encrypt overflow check |
| THREAD-1 | Single-writer ownership of ratchet state per session | Session thread architecture with ownership assertion |
| NONCE-UNIQUE | No (key, nonce) pair ever repeats across all transitions including error paths | Structural proof (Section 7) + runtime assertion (Section 9) |
