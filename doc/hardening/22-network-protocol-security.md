# Hardening Spec 22: Network Protocol Security

**Status:** Required for v1
**Applies to:** All peer-to-peer communication between UmbraVox nodes
**References:** `doc/03-cryptography.md`, `doc/04-consensus.md`, `doc/10-security.md`, `doc/16-verification-plan.md`
**DO-178C Traceability:** REQ-NET-SEC-001 through REQ-NET-SEC-128

---

## 1. Threat Model

### 1.1 Network-Layer Adversary

Per `doc/10-security.md`, the adversary may control up to f' < 0.5 of network nodes. At the transport layer the adversary is assumed to possess:

- Full man-in-the-middle capability on any link (inject, drop, delay, modify, replay packets)
- Ability to enumerate all node IP addresses via network scanning or BGP monitoring
- Ability to open arbitrary numbers of TCP connections to any node (resource exhaustion)
- Ability to operate Sybil nodes with valid TCP/IP stacks and plausible network behavior
- Passive traffic analysis capability (packet sizes, timing, connection graphs)
- Access to historical network captures (harvest-now-analyze-later)

### 1.2 Security Goals

| Goal | Description |
|------|-------------|
| G-CONF | All peer-to-peer traffic is encrypted; passive observers learn nothing beyond connection existence and traffic volume |
| G-AUTH | Validator nodes are authenticated by their Ed25519 identity key; impersonation is impossible |
| G-INT | All messages are integrity-protected; modification is detected and the connection is terminated |
| G-AVAIL | The node remains operational under sustained connection flooding, bandwidth exhaustion, and gossip amplification attacks |
| G-PART | The node detects network partitions and automatically recovers connectivity when the partition heals |

---

## 2. Transport Encryption: Noise_IK Protocol

### 2.1 Cipher Suite

| Component | Algorithm | Reference |
|-----------|-----------|-----------|
| DH function | Curve25519 (X25519) | RFC 7748 |
| AEAD cipher | ChaCha20-Poly1305 | RFC 8439 |
| Hash function | SHA-256 | FIPS 180-4 |

This is the Noise `25519_ChaChaPoly_SHA256` cipher suite. All three primitives are already implemented per `doc/03-cryptography.md` (no new dependencies).

### 2.2 Noise Pattern: IK

The `IK` pattern is used because the initiator already knows the responder's static public key (obtained from the peer directory, DNS seeds, or prior connection). This provides mutual authentication in a single round trip.

```
IK:
  <- s
  ...
  -> e, es, s, ss
  <- e, ee, se
```

**Token definitions:**

| Token | Operation |
|-------|-----------|
| `e` | Generate ephemeral Curve25519 keypair; send public key |
| `s` | Send static public key (encrypted after first DH) |
| `es` | DH(initiator ephemeral, responder static) |
| `ss` | DH(initiator static, responder static) |
| `ee` | DH(initiator ephemeral, responder ephemeral) |
| `se` | DH(responder ephemeral, initiator static) |

### 2.3 Handshake State Machine

```
INITIATOR                                          RESPONDER
─────────                                          ─────────

State: INIT                                        State: LISTENING
  │                                                  │
  ├─ Generate ephemeral key e_I                      │
  ├─ DH: es = X25519(e_I.secret, s_R.public)        │
  ├─ DH: ss = X25519(s_I.secret, s_R.public)        │
  ├─ Encrypt s_I.public under current CipherState    │
  ├─ Encrypt payload_1 under current CipherState     │
  │                                                  │
  ├──── MSG_1: e_I.public ║ enc(s_I.public) ║ enc(payload_1) ────►│
  │                                                  │
  │                                        State: HANDSHAKE_RECV
  │                                          ├─ DH: es = X25519(s_R.secret, e_I.public)
  │                                          ├─ Decrypt s_I.public
  │                                          ├─ DH: ss = X25519(s_R.secret, s_I.public)
  │                                          ├─ Decrypt payload_1
  │                                          ├─ Validate initiator identity (Section 3)
  │                                          ├─ Generate ephemeral key e_R
  │                                          ├─ DH: ee = X25519(e_R.secret, e_I.public)
  │                                          ├─ DH: se = X25519(e_R.secret, s_I.public)
  │                                          ├─ Encrypt payload_2
  │                                          │
  │  ◄──── MSG_2: e_R.public ║ enc(payload_2) ─────┤
  │                                                  │
State: HANDSHAKE_RECV                      State: TRANSPORT
  ├─ DH: ee = X25519(e_I.secret, e_R.public)        │
  ├─ DH: se = X25519(s_I.secret, e_R.public)        │
  ├─ Decrypt payload_2                               │
  ├─ Split into transport CipherStates               │
  │                                                  │
State: TRANSPORT                                     │
```

After `Split`, two independent CipherStates exist: one for initiator-to-responder and one for responder-to-initiator. Each CipherState maintains an independent 64-bit nonce counter starting at 0.

### 2.4 Identity Binding

The static key `s` used in the Noise handshake is the node's **Curve25519 transport key**, derived deterministically from the node's Ed25519 identity key:

```
transport_x25519_secret = ed25519_secret_to_x25519(node_ed25519_secret)
transport_x25519_public = ed25519_public_to_x25519(node_ed25519_public)
```

This conversion follows RFC 7748 Section 4.1 (clamping) applied to the Ed25519 scalar. The identity binding ensures that authenticating via the Noise handshake is equivalent to authenticating via the Ed25519 identity key used in consensus.

### 2.5 Prologue

The Noise prologue binds the handshake to the UmbraVox protocol and chain revision:

```
prologue = "UmbraVox_Noise_v1" ║ chain_revision_uint32_be
```

This prevents cross-protocol attacks and ensures nodes on incompatible chain revisions fail the handshake immediately (MAC verification failure on MSG_1).

### 2.6 Nonce Exhaustion

Each CipherState nonce is a 64-bit counter. At 2^64 - 1 messages the connection MUST be terminated and re-established. In practice, at 10,000 messages per second, nonce exhaustion takes ~58 million years. No rekey protocol is required.

---

## 3. Peer Authentication

### 3.1 Validator Authentication

Validators are identified by their Ed25519 public key registered on-chain (the `bhIssuerVK` from `doc/04-consensus.md`). During the Noise_IK handshake:

1. The initiator encrypts its static Curve25519 public key in MSG_1.
2. The responder decrypts the initiator's static key and converts it back to an Ed25519 public key.
3. The responder checks whether this Ed25519 key is present in the current `stake_snapshot` (2-epoch delayed).
4. If the key is a known validator, the connection is marked `AUTHENTICATED_VALIDATOR`.
5. If the key is unknown, the connection is marked `AUTHENTICATED_PEER` (non-validator).

The `payload_1` in MSG_1 contains the initiator's claimed role and chain revision:

```
payload_1 = {
  protocol_version : uint16     -- current protocol version
  chain_revision   : uint32     -- must match responder's
  node_role        : uint8      -- 0x01 = validator, 0x02 = full node, 0x03 = light client
  timestamp        : int64      -- unix milliseconds, for handshake freshness
}
```

### 3.2 Non-Validator Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| Authenticated | Node presents a persistent Curve25519 static key | Full nodes, light clients with stable identity |
| Anonymous | Node uses a fresh ephemeral key as its static key each connection | Privacy-sensitive clients, Tor exit nodes |

Anonymous mode: the initiator generates a fresh Curve25519 keypair for `s_I` on each connection. The responder marks the connection as `ANONYMOUS`. Anonymous peers have lower bandwidth quotas and priority (Section 5.4).

### 3.3 Handshake Freshness

The `timestamp` in `payload_1` must be within +/- 30 seconds of the responder's local clock. This prevents replay of captured handshake messages. Combined with the Noise_IK pattern's ephemeral keys, replayed MSG_1 messages produce invalid MACs even without the timestamp check; the timestamp adds defense in depth.

### 3.4 Peer Identity Table

Each node maintains a peer identity table mapping Curve25519 public keys to connection metadata:

```haskell
data PeerIdentity = PeerIdentity
  { piStaticKey    :: !X25519PublicKey   -- 32 bytes
  , piEd25519Key   :: !(Maybe Ed25519PubKey)  -- derived, if convertible
  , piRole         :: !PeerRole         -- Validator | FullNode | LightClient | Anonymous
  , piFirstSeen    :: !Word64           -- unix timestamp
  , piLastSeen     :: !Word64
  , piBanScore     :: !Word32           -- misbehavior score (Section 5)
  , piBandwidthUsed :: !Word64          -- bytes this epoch
  }
```

---

## 4. Message Framing

### 4.1 Transport Frame Format

All messages over the Noise transport channel use length-prefixed framing:

```
┌──────────────────────────────────────────────────────────────┐
│  Length (4 bytes, big-endian uint32)  │  Encrypted Payload   │
└──────────────────────────────────────────────────────────────┘

Encrypted Payload = ChaCha20-Poly1305(nonce, key, plaintext_frame)

plaintext_frame:
┌─────────────────────────────────────────────────────────────────┐
│ msg_type (1 byte) │ msg_id (8 bytes) │ body (variable length)  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Message Types

| Type ID | Name | Direction | Description |
|---------|------|-----------|-------------|
| 0x01 | GOSSIP_TX | Bidirectional | Relay a transaction from mempool |
| 0x02 | GOSSIP_BLOCK | Bidirectional | Relay a full block |
| 0x03 | BLOCK_HEADER | Bidirectional | Relay block header only (header-first sync) |
| 0x04 | GET_BLOCK_BODY | Request | Request block body by header hash |
| 0x05 | BLOCK_BODY | Response | Block body in response to GET_BLOCK_BODY |
| 0x06 | GET_HEADERS | Request | Request header chain from a starting hash |
| 0x07 | HEADERS | Response | Batch of block headers |
| 0x08 | HEARTBEAT_RESP | Bidirectional | Heartbeat challenge response relay |
| 0x09 | PEER_EXCHANGE | Bidirectional | Exchange known peer addresses |
| 0x0A | PING | Request | Liveness check |
| 0x0B | PONG | Response | Liveness response |
| 0x0C | REJECT | Response | Rejection with reason code |
| 0x0D | DANDELION_TX | Bidirectional | Dandelion++ stem-phase transaction |
| 0xFF | DISCONNECT | Unidirectional | Graceful connection teardown |

### 4.3 Size Limits

| Constraint | Limit | Rationale |
|------------|-------|-----------|
| Maximum frame length | 4 MiB (4,194,304 bytes) | Largest valid block body with maximum transactions |
| Maximum plaintext message body | 4 MiB - 25 bytes (header overhead) | After subtracting framing |
| Maximum GOSSIP_TX body | 64 KiB (65,536 bytes) | Single transaction upper bound |
| Maximum HEADERS batch | 2,000 headers | Prevents memory exhaustion during sync |
| Maximum PEER_EXCHANGE entries | 1,000 addresses | Prevent peer table overflow |
| Minimum frame length | 9 bytes | msg_type (1) + msg_id (8) |

**Enforcement:** The length field is read first. If length > 4,194,304, the connection is immediately terminated with a REJECT message (reason: `OVERSIZE_MESSAGE`) and the peer's ban score is incremented by 50.

### 4.4 Memory Allocation Strategy

Message buffers are allocated from a fixed-size pool per connection:

```
Per-connection receive buffer pool: 8 MiB maximum
  - 1 frame buffer:    4 MiB (reused per message)
  - Reassembly buffer: 4 MiB (for multi-part responses)

Global receive buffer pool: min(num_peers * 8 MiB, 2 GiB)
```

If the global pool is exhausted, new incoming connections are rejected with a TCP RST until buffer space is freed. This provides a hard upper bound on memory consumption from network I/O.

---

## 5. DoS Resistance at Transport Layer

### 5.1 Connection Rate Limiting

```
Parameters:
  MAX_INBOUND_CONNECTIONS       = 125
  MAX_OUTBOUND_CONNECTIONS      = 12
  MAX_CONNECTIONS_PER_IP        = 3
  MAX_CONNECTIONS_PER_SUBNET_24 = 10
  NEW_CONNECTION_RATE           = 10 per second (token bucket)
  NEW_CONNECTION_BURST          = 20
```

**State machine for inbound connection acceptance:**

```
              ┌────────────┐
  TCP SYN ──► │ RATE_CHECK │
              └─────┬──────┘
                    │
          ┌────────┴────────┐
          │ Token available? │
          └────┬───────┬────┘
             Yes       No
              │         │
              ▼         ▼
        ┌──────────┐  ┌──────┐
        │ IP_CHECK │  │ DROP │
        └────┬─────┘  └──────┘
             │
    ┌────────┴─────────┐
    │ Per-IP/subnet OK? │
    └───┬──────────┬───┘
       Yes         No
        │           │
        ▼           ▼
  ┌───────────┐  ┌──────┐
  │ CAP_CHECK │  │ DROP │
  └─────┬─────┘  └──────┘
        │
  ┌─────┴──────────────┐
  │ Below MAX_INBOUND? │
  └───┬───────────┬────┘
     Yes           No
      │             │
      ▼             ▼
┌───────────┐  ┌──────────────┐
│ ACCEPT    │  │ PUZZLE_ADMIT │──► Section 5.2
└───────────┘  └──────────────┘
```

### 5.2 Puzzle-Based Admission Control

When the node is at connection capacity, new connections must solve a computational puzzle before being accepted. This raises the cost of Sybil connection flooding.

**Puzzle protocol:**

```
1. Node sends PUZZLE_CHALLENGE:
   ┌──────────────────────────────────────────────────────┐
   │ nonce (32 bytes, random) │ difficulty (1 byte, 0-32) │
   └──────────────────────────────────────────────────────┘

2. Connecting peer must find a 32-byte solution S such that:
   SHA-256(nonce ║ S) has `difficulty` leading zero bits

3. Peer sends PUZZLE_SOLUTION:
   ┌─────────────────────────┐
   │ solution S (32 bytes)   │
   └─────────────────────────┘

4. Node verifies in O(1), accepts or rejects.

Difficulty scaling:
  - At 100% capacity:  difficulty = 16 (~65,536 SHA-256 ops, ~1ms)
  - At 110% capacity:  difficulty = 20 (~1M ops, ~15ms)
  - At 125%+ capacity: difficulty = 24 (~16M ops, ~250ms)

Capacity beyond MAX_INBOUND_CONNECTIONS is allowed up to 150%
  only for peers that solve the puzzle. Beyond 150%, all new
  connections are rejected unconditionally.
```

**Puzzle freshness:** Each nonce is valid for 60 seconds. The node maintains a small ring buffer of the last 64 nonces to reject replayed solutions.

### 5.3 Bandwidth Quotas

```
Per-peer bandwidth limits (rolling 60-second window):

  Validator peer:
    Inbound:   2 MiB/s average, 8 MiB/s burst (1-second window)
    Outbound:  2 MiB/s average, 8 MiB/s burst

  Authenticated non-validator:
    Inbound:   512 KiB/s average, 2 MiB/s burst
    Outbound:  512 KiB/s average, 2 MiB/s burst

  Anonymous peer:
    Inbound:   128 KiB/s average, 512 KiB/s burst
    Outbound:  128 KiB/s average, 512 KiB/s burst

Enforcement:
  - Measured via token bucket (refill rate = average, capacity = burst * 1 second)
  - When a peer exceeds its budget: messages are dropped (not buffered)
  - If a peer exceeds 200% of average for >10 consecutive seconds:
    ban_score += 20
```

### 5.4 Ban Score System

```haskell
data BanAction
  = Warn              -- ban_score >= 50
  | Throttle          -- ban_score >= 75, reduce bandwidth quota by 50%
  | Disconnect        -- ban_score >= 100
  | Ban24h            -- ban_score >= 100, remembered for 24 hours
  | BanPermanent      -- ban_score >= 200, persisted to disk

-- Ban score increments:
-- +10: invalid message format (parse failure on well-formed length prefix)
-- +20: bandwidth quota exceeded (sustained)
-- +50: oversize message
-- +50: invalid block header (bad VRF proof, bad signature)
-- +100: equivocation detected (two blocks for same slot from same validator)
-- Ban score decays at 1 point per minute (floor 0)
```

---

## 6. Handshake Flooding Defense

### 6.1 Half-Open Connection Limits

```
MAX_HALF_OPEN_CONNECTIONS = 50       -- connections in handshake phase
MAX_HALF_OPEN_PER_IP      = 2
HANDSHAKE_TIMEOUT         = 10 seconds  -- from TCP accept to TRANSPORT state
```

If a connection does not complete the Noise_IK handshake within 10 seconds, it is terminated. The peer's IP is recorded; 5 consecutive handshake timeouts from the same IP result in a 5-minute IP-level block.

### 6.2 SYN Cookie Equivalent for Noise

The Noise_IK pattern requires the responder to perform DH operations on MSG_1 receipt. To avoid wasting CPU on spoofed connections, the responder implements a lightweight pre-handshake gate:

```
PRE-HANDSHAKE PROTOCOL:
  1. After TCP accept, responder sends a 40-byte COOKIE_CHALLENGE:
     ┌────────────────────────────────────────────────────────────┐
     │ "UMVX" (4 bytes) │ server_nonce (32 bytes) │ timestamp (4 bytes, unix seconds, BE) │
     └────────────────────────────────────────────────────────────┘

  2. Initiator must respond with a 72-byte COOKIE_RESPONSE:
     ┌──────────────────────────────────────────────────────────────┐
     │ server_nonce (32 bytes) │ client_nonce (32 bytes) │ HMAC (8 bytes, truncated) │
     └──────────────────────────────────────────────────────────────┘

     HMAC = HMAC-SHA-256(cookie_secret, server_nonce ║ client_nonce ║ client_ip)[0:8]
     cookie_secret: 32-byte key rotated every 120 seconds

  3. Responder verifies HMAC (O(1), no state stored for unverified connections).
     If valid: proceed to Noise_IK MSG_1.
     If invalid: TCP RST, no further processing.
```

This ensures the responder never performs any DH computation for IP-spoofed connections. The cookie_secret rotation ensures old cookies become invalid, and the truncated HMAC is sufficient for connection admission (it is not a security-critical MAC; the Noise handshake provides the real authentication).

### 6.3 Half-Open Connection State Machine

```
TCP ACCEPT
    │
    ▼
┌────────────────┐  timeout (3s)   ┌─────────┐
│ COOKIE_SENT    │ ───────────────► │ CLOSED  │
└───────┬────────┘                  └─────────┘
        │ valid cookie response
        ▼
┌────────────────┐  timeout (10s)  ┌─────────┐
│ NOISE_HANDSHAKE│ ───────────────► │ CLOSED  │
└───────┬────────┘                  └─────────┘
        │ handshake complete
        ▼
┌────────────────┐
│ TRANSPORT      │
└────────────────┘
```

---

## 7. Gossip Protocol Security

### 7.1 Gossip Message Validation

Every gossip message is validated BEFORE forwarding to other peers. This prevents amplification attacks where an attacker sends one invalid message that gets relayed to the entire network.

**Validation pipeline:**

```
RECEIVE gossip message
    │
    ▼
┌──────────────────┐
│ 1. DEDUP CHECK   │──► Already seen (by msg hash)? → DROP silently
└───────┬──────────┘
        │ new
        ▼
┌──────────────────┐
│ 2. SIZE CHECK    │──► Exceeds type-specific limit? → DROP + ban_score += 10
└───────┬──────────┘
        │ ok
        ▼
┌──────────────────┐
│ 3. TTL CHECK     │──► TTL == 0? → DROP silently
└───────┬──────────┘
        │ ok
        ▼
┌──────────────────┐
│ 4. SYNTAX CHECK  │──► CBOR parse failure? → DROP + ban_score += 10
└───────┬──────────┘
        │ ok
        ▼
┌──────────────────────────┐
│ 5. SEMANTIC VALIDATION   │──► Invalid signature / bad VRF / etc.?
│    (type-specific)       │    → DROP + ban_score += 50
└───────┬──────────────────┘
        │ valid
        ▼
┌──────────────────┐
│ 6. FORWARD       │──► Decrement TTL, relay to eligible peers
└──────────────────┘
```

### 7.2 Deduplication

Messages are deduplicated by a Bloom filter backed by an LRU exact-match cache:

```
Bloom filter:
  - Size: 2^20 bits (128 KiB)
  - Hash functions: 8 (independent slices of SHA-256 of message hash)
  - False positive rate: ~0.07% at 50,000 entries
  - Reset: every 2 epochs (24 hours)

LRU exact-match cache:
  - Capacity: 100,000 entries (message hash -> timestamp)
  - Eviction: least recently seen
  - Memory: ~4.8 MiB (48 bytes per entry)

Dedup procedure:
  1. Compute msg_hash = SHA-256(raw_message_bytes)
  2. If Bloom filter returns MAYBE_PRESENT:
       Check LRU cache for exact match → if found, DROP
  3. If Bloom filter returns NOT_PRESENT:
       Insert into both Bloom filter and LRU cache
       Proceed to validation
```

### 7.3 TTL Limits

| Message Type | Initial TTL | Rationale |
|-------------|-------------|-----------|
| GOSSIP_TX | 8 | Sufficient for ~10,000 node network diameter |
| GOSSIP_BLOCK | 12 | Blocks must reach all validators |
| HEARTBEAT_RESP | 6 | Time-sensitive, limited relay |
| PEER_EXCHANGE | 3 | Local neighborhood only |
| DANDELION_TX | N/A | Uses Dandelion++ stem/fluff phases (separate TTL logic per `doc/10-security.md`) |

TTL is decremented by each relaying node. Messages received with TTL = 0 are processed locally but not forwarded.

### 7.4 Gossip Fan-Out

```
Fan-out per message type:
  GOSSIP_TX:       relay to sqrt(num_peers) peers, minimum 4, maximum 12
  GOSSIP_BLOCK:    relay to ALL connected peers (blocks are critical)
  HEARTBEAT_RESP:  relay to sqrt(num_peers) peers, minimum 3, maximum 8
  PEER_EXCHANGE:   relay to 3 randomly selected peers
```

### 7.5 Anti-Amplification Invariant

**Invariant:** For any single inbound message M, the total outbound bytes generated in response to M is bounded by:

```
outbound_bytes(M) <= size(M) * fan_out(M.type) + constant_overhead

where constant_overhead = 128 bytes (framing, per-peer)
```

No message type triggers generation of additional messages beyond the relay. Request-response pairs (GET_BLOCK_BODY -> BLOCK_BODY) are rate-limited per peer (Section 5.3).

---

## 8. Block Propagation Security

### 8.1 Header-First Synchronization

Blocks are propagated using a header-first protocol. A node never downloads a block body without first validating the header:

```
BLOCK PROPAGATION STATE MACHINE:

  Peer announces block:
      │
      ▼
  ┌──────────────────┐
  │ RECEIVE HEADER   │
  └───────┬──────────┘
          │
          ▼
  ┌──────────────────────────────────┐
  │ VALIDATE HEADER                  │
  │  1. bhSlotNo <= current_slot + 1 │
  │  2. bhPrevHash matches known tip │
  │  3. VRF proof verifies           │
  │  4. VRF output passes threshold  │
  │  5. bhIssuerVK in stake_snapshot │
  │  6. Ed25519 signature valid      │
  │  7. Not a duplicate slot/issuer  │
  └───────┬──────────────────────────┘
          │
    ┌─────┴─────┐
   VALID     INVALID
    │           │
    ▼           ▼
  ┌──────────┐  ┌───────────────────────────────────────┐
  │ REQUEST  │  │ DROP + ban_score += 50 for that peer  │
  │ BODY     │  └───────────────────────────────────────┘
  └────┬─────┘
       │
       ▼
  ┌──────────────────────────────────┐
  │ RECEIVE BODY                     │
  │  Timeout: 30 seconds             │
  │  Max attempts: 3 (different peers)│
  └───────┬──────────────────────────┘
          │
          ▼
  ┌──────────────────────────────────┐
  │ VALIDATE BODY                    │
  │  1. SHA-256 Merkle root matches  │
  │     bhBodyHash                   │
  │  2. All transactions valid       │
  │  3. Body size <= 4 MiB           │
  └───────┬──────────────────────────┘
          │
    ┌─────┴─────┐
   VALID     INVALID
    │           │
    ▼           ▼
  ┌────────┐  ┌──────────────────────────────────┐
  │ ACCEPT │  │ DROP body, ban_score += 50       │
  │ BLOCK  │  │ Try next peer if attempts remain │
  └────────┘  └──────────────────────────────────┘
```

### 8.2 Equivocation Detection

If a node receives two valid block headers for the same `(bhSlotNo, bhIssuerVK)` pair with different content:

1. Both headers are stored as an **equivocation proof**.
2. The equivocation proof is gossiped to all peers (msg_type GOSSIP_BLOCK with a special equivocation flag).
3. The equivocating validator's `PunitiveFactor` is set to 0.0 via a protocol-level penalty transaction in the next block.
4. The peer that relayed the equivocation is NOT penalized (they are reporting, not equivocating).

### 8.3 Chain Sync Protocol

For initial block download (IBD) and catching up after downtime:

```
GET_HEADERS request:
  ┌─────────────────────────────────────────────────────────────┐
  │ start_hash (32 bytes) │ max_headers (uint16, max 2000)     │
  └─────────────────────────────────────────────────────────────┘

HEADERS response:
  ┌────────────────────────────────────────────────────────────────┐
  │ count (uint16) │ header_1 ║ header_2 ║ ... ║ header_N        │
  └────────────────────────────────────────────────────────────────┘

Rate limit: maximum 4 GET_HEADERS requests per peer per 10-second window.
Maximum headers per response: 2,000.
```

Bodies are then requested individually or in small batches (up to 16 concurrent GET_BLOCK_BODY requests per peer). This prevents a malicious peer from causing unbounded memory allocation by sending an enormous header chain followed by bodies.

---

## 9. Mempool Flooding Defense

### 9.1 Transaction Admission Rate Limiting

```
Per-peer transaction rate limits:

  Validator peer:           50 tx/second (token bucket, burst 100)
  Authenticated peer:       10 tx/second (token bucket, burst 20)
  Anonymous peer:            2 tx/second (token bucket, burst  5)

Global transaction admission:
  Max new transactions per second: 500 (across all peers)
  If exceeded: lowest-fee transactions are dropped first

Mempool capacity: 50,000 transactions (~50 MiB)
  (per doc/04-consensus.md)
```

### 9.2 Minimum Fee as DoS Protection

Per `doc/04-consensus.md`, every transaction must include a fee. The adaptive fee floor (`ap_fee_floor`, range [5, 100] MTK) ensures a minimum economic cost per transaction.

**Fee validation at mempool admission:**

```
1. tx.fee >= ap_fee_floor (currently active adaptive parameter)
2. If mempool is >80% full: tx.fee >= 2 * ap_fee_floor
3. If mempool is >95% full: tx.fee >= 5 * ap_fee_floor
4. tx.fee <= ap_fee_ceiling (reject absurdly high fees as likely errors)
```

Transactions failing fee checks are rejected with a REJECT message (reason: `INSUFFICIENT_FEE`) but do NOT increment the ban score (fee requirements may differ due to propagation delay of adaptive parameter updates).

### 9.3 Per-Peer Mempool Tracking

Each node tracks how many currently-in-mempool transactions were received from each peer:

```
Per-peer mempool tracking:
  max_mempool_contribution_per_peer = 2,000 transactions

  If a peer has contributed 2,000 transactions still in the mempool:
    New transactions from that peer are rejected with REJECT(PEER_MEMPOOL_FULL)
    No ban score increment (legitimate high-volume relayers may hit this)

  Eviction credit: when a peer's transaction is included in a block
    or evicted from mempool, the peer's contribution count decrements.
```

### 9.4 Transaction Validation Before Relay

A transaction is only relayed to other peers after passing:

1. CBOR syntax check (well-formed encoding)
2. Signature verification (Ed25519)
3. Nonce check (sequential per-account, per `doc/04-consensus.md`)
4. Fee check (meets current floor)
5. Sender balance check (sender has sufficient balance for fee + value)
6. Size check (<= 64 KiB)
7. Deduplication check (transaction hash not in Bloom filter / LRU cache)

---

## 10. DNS Seed Security

### 10.1 DNSSEC Enforcement

All DNS seed lookups MUST validate DNSSEC signatures. If DNSSEC validation fails, the DNS response is discarded entirely. Nodes MUST NOT fall back to non-DNSSEC-validated responses.

**DNS seed records:**

```
Seed hostnames:
  seed1.UmbraVox.network    -- Operator A (geographic region 1)
  seed2.UmbraVox.network    -- Operator B (geographic region 2)
  seed3.UmbraVox.network    -- Operator C (geographic region 3)

Record type: A and AAAA (IPv4 and IPv6)
TTL: 300 seconds (5 minutes)

Each seed returns up to 25 peer addresses (randomized from the seed's known-good peer set).
```

### 10.2 Hardcoded Fallback Peers

The node binary contains a hardcoded list of fallback peers used when:

- All DNS seeds are unreachable
- DNSSEC validation fails for all seeds
- The node is starting for the first time with no peer cache

```
Hardcoded peers: minimum 8 entries across at least 4 autonomous systems (ASNs)
  Format: (ipv4_or_ipv6, port, ed25519_pubkey_fingerprint)

  The fingerprint allows the node to verify the peer's identity during
  the Noise_IK handshake, preventing MITM by network-level attackers
  who redirect traffic to the hardcoded IPs.
```

### 10.3 Seed Operator Diversity

Requirements for DNS seed operators:

- Minimum 3 independent operators
- No two seeds hosted in the same autonomous system (ASN)
- No two seeds operated by the same legal entity
- Each seed must run an independent node and verify block validity (not just relay addresses)
- Seed software must validate peer liveness (TCP connect + Noise handshake + PING/PONG) before including a peer in DNS responses

### 10.4 Peer Discovery After Bootstrap

After initial bootstrap from seeds, nodes discover additional peers via:

1. **PEER_EXCHANGE messages** from connected peers (Section 4.2, type 0x09)
2. **Address gossip**: every 15 minutes, each node advertises its own address to 3 random peers
3. **Peer cache**: known peers are persisted to disk and loaded on restart

Target peer table size: 1,000 known addresses (excluding banned peers).

---

## 11. Protocol Message Fuzzing Resistance

### 11.1 Parser Safety Requirements

All message parsers (CBOR deserialization, Noise handshake message parsing, gossip message parsing) MUST satisfy the following properties when given arbitrary byte sequences:

| Property | Requirement |
|----------|-------------|
| No crash | Parser returns an error value; never panics, segfaults, or calls `error`/`undefined` |
| No unbounded allocation | Total heap allocation per parse call is bounded by `max_message_size + 1 MiB` overhead |
| No infinite loop | Parser completes within O(n) time where n = input length |
| No partial state mutation | On parse failure, no shared state is modified (parser is pure or uses rollback) |
| Deterministic | Same input always produces the same output (no dependence on uninitialized memory) |

### 11.2 Defensive Parsing Strategy

```
PARSE(raw_bytes):
  1. Check length <= type-specific maximum (fail fast)
  2. CBOR decode with depth limit = 16 and container size limit = 10,000 elements
  3. Type-check all decoded fields against expected schema
  4. Range-check all numeric fields (no negative where unsigned expected, no overflow)
  5. Validate all byte-string fields have expected lengths (e.g., pubkey == 32 bytes)
  6. Return (ParseSuccess value) | (ParseFailure reason)
```

### 11.3 Fuzzing Campaign Requirements

Cross-reference: `doc/16-verification-plan.md`, "Fuzzing Campaigns" section.

| Target | Fuzzer | Minimum Executions | Corpus |
|--------|--------|-------------------|--------|
| CBOR message parser | AFL + libFuzzer | 10^9 before release, 10^8 nightly | `test/evidence/fuzzing/cbor/` |
| Noise_IK handshake parser | AFL + libFuzzer | 10^9 before release, 10^8 nightly | `test/evidence/fuzzing/noise/` |
| Gossip message validators | AFL + libFuzzer | 10^9 before release, 10^8 nightly | `test/evidence/fuzzing/gossip/` |
| Block header parser | AFL + libFuzzer | 10^9 before release, 10^8 nightly | `test/evidence/fuzzing/block/` |
| Transaction parser | AFL + libFuzzer | 10^9 before release, 10^8 nightly | `test/evidence/fuzzing/tx/` |

All fuzzers run with AddressSanitizer and UndefinedBehaviorSanitizer enabled on the C FFI layer. Haskell-side fuzzing uses `+RTS -xc` for stack trace on exception.

### 11.4 Regression Test Integration

Every crash or hang discovered by fuzzing is:

1. Minimized to a minimal reproducing input
2. Added to the regression test suite as a permanent test case
3. Filed as a defect with severity "Critical" (crash) or "High" (hang/excessive allocation)
4. The fix must achieve 100% MC/DC coverage of the affected code path

---

## 12. Network Partition Healing

### 12.1 Partition Detection

A node suspects a network partition when:

```
Partition detection heuristics:
  1. BLOCK_STALL: No new valid blocks received for 60 consecutive slots (660 seconds)
     at any time during normal operation (not initial sync)

  2. PEER_LOSS: Connected peer count drops below 4 (minimum safe connectivity)

  3. EPOCH_STALL: Epoch boundary truncation fails due to <2/3 attestation
     (per doc/04-consensus.md, Truncation Failure Handling)

  4. CHAIN_DIVERGENCE: Received a block header with a prev_hash that does not
     match any known block, suggesting an alternate chain exists
```

### 12.2 Recovery Protocol

```
PARTITION RECOVERY STATE MACHINE:

  NORMAL ──[any detection heuristic triggers]──► PARTITION_SUSPECTED
    │                                                    │
    │                                                    ▼
    │                                          ┌─────────────────────┐
    │                                          │ EXPAND_PEER_SEARCH  │
    │                                          │  1. Re-query DNS seeds
    │                                          │  2. Connect to all hardcoded fallbacks
    │                                          │  3. Request PEER_EXCHANGE from all
    │                                          │     connected peers
    │                                          │  4. Attempt connections to all
    │                                          │     cached peers not currently connected
    │                                          └──────────┬──────────┘
    │                                                     │
    │                                                     ▼
    │                                          ┌─────────────────────┐
    │                                          │ CHAIN_COMPARISON    │
    │                                          │  For each new peer: │
    │                                          │  1. Exchange tip headers
    │                                          │  2. If peer's chain is longer:
    │                                          │     begin header-first sync
    │                                          │  3. Apply fork choice rule
    │                                          │     (density-based, per doc/04-consensus.md)
    │                                          └──────────┬──────────┘
    │                                                     │
    │                                          ┌──────────┴──────────┐
    │                                         chain    chain matches
    │                                         differs  (no partition)
    │                                          │              │
    │                                          ▼              ▼
    │                                  ┌─────────────┐  ┌──────────────┐
    │                                  │ REORG       │  │ CONNECTIVITY │
    │                                  │ Switch to   │  │ RECOVERY     │
    │                                  │ longer chain│  │ (just needed │
    │                                  └──────┬──────┘  │  more peers) │
    │                                         │         └───────┬──────┘
    │                                         │                 │
    │◄────────────────────────────────────────┴─────────────────┘
  NORMAL
```

### 12.3 Partition Recovery Parameters

```
PEER_SEARCH_INTERVAL      = 30 seconds (during PARTITION_SUSPECTED)
MAX_RECOVERY_DURATION     = 1 epoch (12 hours, per doc/04-consensus.md)
MIN_PEERS_FOR_NORMAL      = 4
REORG_DEPTH_LIMIT         = k_val = 22 blocks (value tier finality depth)
```

If a partition lasts longer than MAX_RECOVERY_DURATION, the node enters a safe mode where it stops producing blocks but continues attempting peer connections. Per `doc/04-consensus.md`, the minority partition cannot achieve 2/3+ attestation, so truncation stalls naturally until the partition heals.

### 12.4 Post-Partition Consistency

After a partition heals and the node completes reorg to the majority chain:

1. All transactions from the orphaned minority chain are re-evaluated against the majority chain's ledger state.
2. Transactions with valid nonces are resubmitted to the mempool.
3. Transactions with conflicting nonces are dropped.
4. The node's `epoch_nonce` and `stake_snapshot` are recalculated from the majority chain.

This procedure is consistent with `doc/04-consensus.md` "Network Partition Recovery."

---

## 13. Formal Network Security Model

### 13.1 Attacker Capabilities

The formal model defines a network-layer adversary A with the following capabilities:

```
Adversary A = (Control, Observe, Inject, Schedule)

  Control(links):
    A controls an arbitrary subset of network links.
    A can drop, delay (up to Δ_max), or reorder messages on controlled links.
    A cannot break cryptographic primitives (computationally bounded).

  Observe(traffic):
    A observes all ciphertext on controlled links.
    A observes message sizes, timing, and connection graphs.
    A does NOT observe plaintext (by G-CONF assumption, proven below).

  Inject(messages):
    A can inject arbitrary byte sequences on any controlled link.
    A can open TCP connections to any node.
    A can operate up to f' < 0.5 * N Sybil nodes with valid identities.

  Schedule(messages):
    A controls message delivery order on controlled links.
    A cannot prevent eventual delivery on uncontrolled links
    (partial synchrony assumption: Δ_max < ∞).
```

### 13.2 Theorem: Transport Encryption Prevents MITM

**Theorem 1.** Under the Computational Diffie-Hellman (CDH) assumption on Curve25519, the Noise_IK handshake with ChaCha20-Poly1305 provides:

(a) **Confidentiality**: A passive adversary observing the handshake and all subsequent transport messages learns nothing about the plaintext beyond message lengths.

(b) **Authentication**: An active adversary cannot impersonate a node whose Curve25519 static key it does not possess.

(c) **Integrity**: An active adversary cannot modify any transport message without detection (Poly1305 MAC failure terminates the connection).

**Proof sketch:**

1. **Confidentiality** follows from the Noise framework's security proof (Kobeissi et al., "Noise Explorer: Fully Automated Modeling and Verification for Arbitrary Noise Protocols", IEEE S&P 2019). The IK pattern provides confidentiality for both the initiator's static key (encrypted under `es`) and all transport payloads (encrypted under keys derived from `es`, `ss`, `ee`, `se`). Breaking confidentiality requires solving the CDH problem on Curve25519 to recover any of the four DH shared secrets.

2. **Authentication** follows from the `ss` and `se` DH computations. An adversary without `s_R.secret` cannot compute `ss = DH(s_I, s_R)` or forge the responder's MSG_2 (which includes `se = DH(e_R, s_I)` requiring knowledge of `e_R.secret`). Similarly for initiator authentication via `es` and `ss`.

3. **Integrity** follows from ChaCha20-Poly1305 being an AEAD scheme. Any modification of ciphertext is detected with probability 1 - 2^(-128) per message (Poly1305 tag length: 128 bits).

**Required deliverable:** Full machine-checked proof in `test/evidence/formal-proofs/noise-ik-security.tla` modeling the IK handshake as a state machine with adversarial message modification and injection.

### 13.3 Theorem: Gossip Protocol Prevents Amplification

**Theorem 2.** Under the gossip protocol rules defined in Section 7, an adversary controlling up to f' < 0.5 of network nodes cannot achieve an amplification factor greater than:

```
amplification(M) = fan_out(M.type) * (network_diameter)
```

where `network_diameter` is the maximum shortest path between any two honest nodes in the peer graph.

**Proof sketch:**

1. **Deduplication** (Section 7.2) ensures each message is forwarded at most once per node. A message with hash H is inserted into the Bloom filter and LRU cache on first receipt; subsequent copies are silently dropped.

2. **TTL limits** (Section 7.3) bound the maximum number of hops to `initial_TTL`. Since TTL is decremented on each forward and messages with TTL = 0 are not forwarded, the maximum relay chain length is `initial_TTL`.

3. **Validation before forwarding** (Section 7.1) ensures invalid messages are dropped at the first honest node that receives them. An adversary's invalid messages therefore reach at most the adversary's immediate honest neighbors, not the entire network.

4. **Fan-out limits** (Section 7.4) bound the branching factor at each hop.

5. Combining: total copies of a single valid message M in the network is bounded by `min(N_honest, fan_out^TTL)` where N_honest is the number of honest nodes. For invalid messages, the bound is `degree(adversary_node)` (the number of honest peers directly connected to the adversary).

**Required deliverable:** TLA+ model in `test/evidence/formal-proofs/gossip-amplification.tla` with model checking for networks of 20-100 nodes, verifying that the amplification bound holds under all adversary strategies.

### 13.4 Theorem: Partition Healing Convergence

**Theorem 3.** If a network partition heals (all honest nodes become reachable from each other within finite time), then all honest nodes converge to the same chain within O(k) slots, where k_val = 22 is the value-tier security parameter (k_msg = 11 for message tier).

**Proof sketch:**

1. After partition healing, honest nodes exchange tip headers (Section 12.2).
2. The fork choice rule (longest chain with density comparison, per `doc/04-consensus.md`) is deterministic: given the same set of candidate chains, all honest nodes select the same chain.
3. Within k slots of the healing point, the majority partition's chain has strictly higher density (it has more stake contributing to block production).
4. All honest nodes in the minority partition reorg to the majority chain within k slots.

This follows directly from the Ouroboros Praos common prefix property (David et al., Eurocrypt 2018, Theorem 2).

---

## 14. Version Negotiation

### 14.1 Protocol Version in Handshake

The `payload_1` of the Noise_IK handshake (Section 3.1) contains `protocol_version` and `chain_revision`. Version negotiation rules:

```
1. If chain_revision differs: REJECT with reason INCOMPATIBLE_REVISION.
   (Nodes on different chain revisions cannot communicate meaningfully.)

2. If protocol_version differs by more than 1 minor version:
   REJECT with reason INCOMPATIBLE_VERSION.

3. If protocol_version matches or differs by exactly 1 minor version:
   Both nodes use the lower of the two versions for this connection.
   This allows rolling upgrades where not all nodes upgrade simultaneously.
```

### 14.2 Unknown Message Types

If a node receives a message with an unrecognized `msg_type`:

1. The message is silently dropped (not forwarded).
2. No ban score increment (the peer may be running a newer protocol version).
3. A debug-level log entry is recorded.

This ensures forward compatibility: newer protocol versions can introduce new message types without disrupting older nodes.

---

## 15. Implementation Checklist

| # | Component | Module | REQ IDs |
|---|-----------|--------|---------|
| 1 | Noise_IK handshake (Curve25519 + ChaCha20-Poly1305 + SHA-256) | `UmbraVox.Network.Noise` | REQ-NET-SEC-001 to 015 |
| 2 | Peer authentication and identity table | `UmbraVox.Network.PeerAuth` | REQ-NET-SEC-016 to 025 |
| 3 | Length-prefixed message framing | `UmbraVox.Network.Framing` | REQ-NET-SEC-026 to 035 |
| 4 | Connection rate limiter + token bucket | `UmbraVox.Network.RateLimit` | REQ-NET-SEC-036 to 045 |
| 5 | Puzzle-based admission control | `UmbraVox.Network.Puzzle` | REQ-NET-SEC-046 to 052 |
| 6 | Bandwidth quota enforcement | `UmbraVox.Network.Bandwidth` | REQ-NET-SEC-053 to 060 |
| 7 | Ban score system | `UmbraVox.Network.BanScore` | REQ-NET-SEC-061 to 068 |
| 8 | Cookie-based handshake gate | `UmbraVox.Network.Cookie` | REQ-NET-SEC-069 to 075 |
| 9 | Gossip validation pipeline + dedup | `UmbraVox.Network.Gossip` | REQ-NET-SEC-076 to 088 |
| 10 | Header-first block sync | `UmbraVox.Network.BlockSync` | REQ-NET-SEC-089 to 098 |
| 11 | Mempool admission + per-peer tracking | `UmbraVox.Network.Mempool` | REQ-NET-SEC-099 to 108 |
| 12 | DNS seed resolver with DNSSEC | `UmbraVox.Network.DNS` | REQ-NET-SEC-109 to 115 |
| 13 | Partition detection and recovery | `UmbraVox.Network.Partition` | REQ-NET-SEC-116 to 122 |
| 14 | Message parser hardening + fuzz targets | `UmbraVox.Network.Parser` | REQ-NET-SEC-123 to 128 |

---

## 16. References

| Reference | Title |
|-----------|-------|
| Noise Protocol Framework | Perrin, "The Noise Protocol Framework", revision 34, 2018 |
| Noise Explorer | Kobeissi et al., "Noise Explorer: Fully Automated Modeling and Verification for Arbitrary Noise Protocols", IEEE S&P 2019 |
| RFC 7748 | Elliptic Curves for Security (Curve25519/X25519) |
| RFC 8439 | ChaCha20 and Poly1305 for IETF Protocols |
| FIPS 180-4 | Secure Hash Standard (SHA-2 family) |
| Ouroboros Praos | David et al., "Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain", Eurocrypt 2018 |
| Dandelion++ | Fanti et al., "Dandelion++: Lightweight Cryptocurrency Networking with Formal Anonymity Guarantees", ACM SIGMETRICS 2018 |
| DNSSEC | RFC 4033, 4034, 4035 |
| Halderman et al. | "Lest We Remember: Cold Boot Attacks on Encryption Keys", USENIX Security 2008 |
