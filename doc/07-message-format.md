# Message Format

## Serialization Convention

All multi-byte integers are big-endian (network byte order). All byte strings are raw (no length prefix in fixed-size fields).

## Single Message Block Layout (1024 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | version |
| 1 | 1 | msg_type (bit 7 reserved for compression in v2; must be 0 in v1) |
| 2 | 20 | sender_id — SHA-256(Ed25519_pubkey)[0..20], 20-byte truncated hash of sender's identity public key |
| 22 | 20 | recipient_id — SHA-256(Ed25519_pubkey)[0..20], 20-byte truncated hash of recipient's identity public key |
| 42 | 6 | timestamp (48-bit ms since epoch) |
| 48 | 2 | sequence_num |
| 50 | 8 | message_id (truncated SHA-256) |
| 58 | 32 | Signal ratchet pubkey — sender's current ephemeral X25519 DH ratchet public key; used by recipient to advance their receiving chain |
| 90 | 4 | prev_chain_length — number of messages sent on the previous sending chain before the DH ratchet step; used by recipient to compute skipped message keys |
| 94 | 4 | msg_number |
| 98 | 4 | signal_session_tag |
| 102 | 4 | reserved — reserved for future protocol extensions (e.g., group messaging flags, priority hints); must be set to 0x00 in v1; receivers must ignore non-zero values for forward compatibility |
| 106 | 12 | PQ wrapper nonce |
| 118 | 16 | PQ wrapper GCM auth tag |
| 134 | 2 | total_blocks |
| 136 | 2 | block_index |
| 138 | 2 | payload_length |
| 140 | 798 | payload (encrypted content) |
| 938 | 32 | HMAC-SHA256 — keyed with HKDF-Expand(message_key, info="UmbraVox_HMAC_v1", length=32); separate from encryption key to prevent key reuse |
| 970 | 54 | padding (random) |

**Overhead**: 226 bytes. **Usable plaintext**: ~782 bytes per block (after Signal's 16-byte GCM tag).

## Block Capacity

Each consensus block contains up to **4,444 message transactions**:

| Parameter | Value |
|-----------|-------|
| Messages per block | 4,444 |
| Message size | 1,024 bytes |
| Full block size | 4,444 × 1,024 = 4,550,656 bytes (~4.44 MB) |
| Compact block size | ~50-130 KB (with 95%+ mempool hit rate) |
| Block rate | ~1 block per 55 seconds (f=0.20, 11s slots) |
| Global throughput | ~80.8 messages/second (~6.98M/day) |

Compact block relay is mandatory at this block size. Without it, full ~4.44 MB blocks cannot propagate within the 11-second slot. See `doc/09-network.md` for the compact block relay protocol.

## Message Types

```
0x00  TEXT              -- UTF-8 text message
0x01  BINARY            -- File/binary transfer
0x02  KEY_EXCHANGE      -- PQXDH initial key exchange
0x03  PREKEY_BUNDLE     -- Publish prekey bundle to chain
0x04  RATCHET_REFRESH   -- PQ ratchet key refresh (~every 50 messages)
0x05  ACK               -- Delivery acknowledgment
0x06  CONTROL           -- Channel control (group management, etc.)
0xFF  DUMMY             -- Cover traffic dummy message (Dandelion++)
```

Bit 7 (0x80) is reserved for the compression flag (v2). In v1, bit 7 must be 0; receivers must ignore it for forward compatibility.

## Multi-Block Messages

Blocks belonging to the same message share the same `message_id`. The `total_blocks` and `block_index` fields enable ordered reassembly.

- Max blocks per message: 65,535 (uint16)
- Practical protocol cap: 1,024 blocks (~802 KB)
- Cost scales linearly: `Cost(message) = base_fee * ceil(size_bytes / 1024)` where base_fee is dynamic (10-10,000 MTK, EMA-adjusted per doc/06). Fixed fees apply in V1 for metadata privacy — all transactions pay identical amount.
- **Reassembly timeout**: recipient waits max 30 seconds for all blocks of a multi-block message. Missing blocks after timeout: discard all received blocks, log error. Sender may retry.

## Serialization: CBOR (hand-implemented)

CBOR arrays with positional semantics (no field names). ~15-20 bytes structural overhead per message.

## Transaction Envelope

```
Transaction = CBOR [tx_header, tx_body, tx_witness]
  tx_header: [version, chain_revision, tx_hash, fee, ttl]
  tx_body:   [sender_addr, nonce, msg_blocks[], dandelion_stem]
  tx_witness: [ed25519_signature]
```

`chain_revision` (uint16) identifies the epoch genesis revision the transaction targets. Nodes reject transactions whose `chain_revision` does not match the current epoch. This prevents replay of transactions across truncation boundaries.

**V1 Metadata Protection**: The `msg_type`, `timestamp`, `signal_ratchet_pubkey`, `msg_number`, and `total_blocks` fields are encrypted inside the payload in V1. On-chain, all message blocks appear as uniform-sized, uniform-fee encrypted data with one-time stealth addresses. See `doc/hardening/14-metadata-minimization.md`.

Single-block message on wire: ~1,198 bytes total.

## PQ Ciphertext Transmission

KEY_EXCHANGE (0x02) messages carry ML-KEM ciphertext (~1,088 bytes) across 2 blocks:

- **Block 0**: header (226 bytes) + first 782 bytes of PQ ciphertext + 16 bytes padding
- **Block 1**: remaining 306 bytes of PQ ciphertext + padding

RATCHET_REFRESH (0x04) uses the same 2-block format for fresh ML-KEM encapsulation.

Normal TEXT/BINARY messages incur only 28-byte PQ overhead (nonce + GCM tag in header).

## Compression (deferred to v2)

Per-message DEFLATE compression is deferred to v2. V1 sends all payloads uncompressed. The design intent for v2:

- **Algorithm**: DEFLATE (RFC 1951, hand-implemented, no external libraries)
- **Application order**: compress plaintext BEFORE encryption (compress, then encrypt)
- **Flag**: bit 7 of `msg_type` set when payload is compressed
- **Length**: `payload_length` reflects compressed size
- **Bypass**: if compressed size >= uncompressed size, send uncompressed (bit 7 = 0)
- **Context**: compression context reset per message (no shared dictionary)

## Nonce Collision Prevention

- **PQ wrapper nonce** (12 bytes) = `HKDF(pq_chain_key, "nonce" || message_counter)`
- `message_counter` is a 64-bit monotonic counter (uint64) per-session and never resets within a session
- At 1 message/second, overflow in ~585 billion years. If overflow ever occurs, session must be re-established.
- On PQ ratchet refresh: counter continues from its prior value (no reset)
- **Collision probability**: negligible (12-byte nonce + monotonic counter)

## CBOR Code Generation

- Message format schema defined declaratively in `codegen/Specs/MessageFormat.schema`
- CBOR encoder/decoder generated from schema (eliminates hand-coding bugs)
- Round-trip property: `decode(encode(msg)) == msg` for all valid messages
- Canonical encoding enforced (deterministic for hashing)
- Fuzz targets auto-generated: malformed CBOR leads to graceful rejection, never crash

## Standard References

- RFC 8949 — Concise Binary Object Representation (CBOR)
- RFC 1951 — DEFLATE Compressed Data Format Specification
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- NIST SP 800-38D — Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (AES-GCM)
- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM-768)
