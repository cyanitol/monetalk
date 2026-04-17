# Metadata Minimization Hardening Specification

**Risk rating**: LOW after V1 mitigations (pre-mitigation: HIGH; see doc/10-security.md threat matrix)
**Scope**: All on-chain metadata visible to full nodes, archival adversaries, and chain analysts

This document audits every piece of metadata exposed by the UmbraVox protocol on-chain, classifies each by residual risk, and specifies mitigations (implemented or planned).

---

## 1. Inventory of On-Chain Metadata

### 1.1 Transaction Envelope (all transaction types)

Per doc/07-message-format.md, every transaction has the following envelope visible to all full nodes:

| Field | Size | Visible to observers | Privacy impact |
|-------|------|---------------------|----------------|
| `version` | 1 byte | Yes | LOW -- protocol version, same across all txs |
| `chain_revision` | 2 bytes | Yes | LOW -- epoch identifier, same for all txs in epoch |
| `tx_hash` | 32 bytes | Yes | LOW -- random-looking, no linkage by itself |
| `fee` | 8 bytes | Yes | **MEDIUM** -- reveals willingness to pay, correlates with message size |
| `ttl` | varies | Yes | LOW -- expiry hint |
| `sender_addr` | 20 bytes | Yes | **HIGH** -- truncated SHA-256 of Ed25519 pubkey, persistent identity |
| `nonce` | 8 bytes | Yes | **MEDIUM** -- monotonic counter reveals tx count per sender |
| `msg_blocks[]` | variable | Yes (encrypted) | **MEDIUM** -- block count reveals message size |
| `dandelion_stem` | 1 bit | Yes (to relay) | LOW -- stripped before block inclusion |
| `ed25519_signature` | 64 bytes | Yes | **HIGH** -- binds tx to sender pubkey |

### 1.2 Message Block Header (inside each 1K block)

| Field | Size | Visible | Privacy impact |
|-------|------|---------|----------------|
| `msg_type` | 1 byte | Yes | **HIGH** -- distinguishes TEXT/KEY_EXCHANGE/RATCHET_REFRESH/etc. |
| `sender_id` | 20 bytes | Yes | **HIGH** -- truncated pubkey hash, same as sender_addr |
| `recipient_id` | 20 bytes | Yes | **HIGH** -- truncated pubkey hash of recipient |
| `timestamp` | 6 bytes | Yes | **MEDIUM** -- 48-bit ms precision, sub-slot timing |
| `sequence_num` | 2 bytes | Yes | **LOW** -- within-message ordering |
| `message_id` | 8 bytes | Yes | **MEDIUM** -- links multi-block messages |
| `signal_ratchet_pubkey` | 32 bytes | Yes | **MEDIUM** -- ephemeral, but links messages in same ratchet epoch |
| `prev_chain_length` | 4 bytes | Yes | **LOW** -- ratchet metadata |
| `msg_number` | 4 bytes | Yes | **MEDIUM** -- monotonic, reveals message frequency per session |
| `total_blocks` | 2 bytes | Yes | **MEDIUM** -- reveals message size |
| `block_index` | 2 bytes | Yes | **LOW** -- ordering |
| `payload_length` | 2 bytes | Yes | **MEDIUM** -- exact payload size within block |
| `payload` | 798 bytes | Encrypted | LOW -- ciphertext, indistinguishable from random |
| `HMAC` | 32 bytes | Yes | LOW -- keyed, no linkage |
| `padding` | 54 bytes | Yes | LOW -- random fill |

### 1.3 Block Header Metadata

| Field | Size | Visible | Privacy impact |
|-------|------|---------|----------------|
| `bhSlotNo` | 8 bytes | Yes | **MEDIUM** -- 11-second granularity timestamp |
| `bhBlockNo` | 8 bytes | Yes | LOW -- sequential |
| `bhPrevHash` | 32 bytes | Yes | LOW -- chain structure |
| `bhBodyHash` | 32 bytes | Yes | LOW -- Merkle root of tx hashes |
| `bhIssuerVK` | 32 bytes | Yes | **HIGH** -- block producer identity key |
| `bhVRFProof` | variable | Yes | LOW -- cryptographic proof |
| `bhVRFOutput` | variable | Yes | LOW -- random output |
| `bhSignature` | 64 bytes | Yes | LOW -- authentication |
| `bhHeartbeat` | optional | Yes | LOW -- liveness protocol |

### 1.4 Transaction Types and Type-Specific Fields

| Transaction type | Type byte | Distinguishing features |
|-----------------|-----------|------------------------|
| MSG (text/binary) | 0x00/0x01 | Single block, standard payload |
| KEY_EXCHANGE | 0x02 | 2 blocks, ML-KEM ciphertext (~1,088 bytes) |
| PREKEY_BUNDLE | 0x03 | 100 OPKs (~3,200 bytes), distinctive size |
| RATCHET_REFRESH | 0x04 | 2 blocks, same layout as KEY_EXCHANGE |
| ACK | 0x05 | Minimal payload |
| CONTROL | 0x06 | Variable |
| DUMMY | 0xFF | Filtered at mempool, never on-chain |
| KEY_ROTATE | -- | SPK rotation, distinctive payload |
| KEY_REPLENISH | -- | 50 OPKs (~1,600 bytes) |
| STAKE_WITHDRAW | -- | Consensus tx, no message payload |
| FAUCET_CLAIM | -- | PoW proof + pubkey, distinctive |

### 1.5 Consensus/Economic Metadata

| Data | Visible | Privacy impact |
|------|---------|----------------|
| Staked balances (per pubkey) | Yes | **HIGH** -- wealth exposure, persists across truncation |
| Validator set membership | Yes | **HIGH** -- public role, persists across truncation |
| Punitive factor history | Derivable | **MEDIUM** -- reward changes reveal penalty state |
| Referral attribution | Yes (3 cycles) | **MEDIUM** -- links onboarder to referred users |
| Faucet claims | Yes | **MEDIUM** -- reveals new user onboarding events |
| Heartbeat responses | Yes | **LOW** -- validator liveness, expected |

---

## 2. Sender/Recipient Unlinkability

### 2.1 Current State (v1)

In v1, `sender_addr` and `recipient_id` are deterministic truncated hashes of permanent Ed25519 identity keys. All messages from the same user share the same `sender_addr`. All messages to the same user share the same `recipient_id`. This provides **zero unlinkability** within an epoch.

An observer can trivially construct a full communication graph for any epoch: who talks to whom, how often, at what times, and in what volumes.

### 2.2 Stealth Addresses (V1 -- DKSAP)

Cross-reference: `doc/hardening/03-stealth-addresses.md`

Dual-Key Stealth Address Protocol (DKSAP) enables one-time addresses per message:

```
Recipient publishes meta-address: (scan_pubkey, spend_pubkey)
  scan_pubkey  = Ed25519 public key for scanning
  spend_pubkey = Ed25519 public key for spending

Sender generates one-time address per message:
  1. Generate ephemeral scalar r
  2. Compute shared_secret = HKDF(X25519(r, scan_pubkey), info="UmbraVox_StealthKey_v1")
  3. one_time_addr = SHA-256(spend_pubkey + shared_secret * G)[0..20]
  4. Publish ephemeral_pubkey = r * G alongside the transaction

Recipient scans:
  For each tx with ephemeral_pubkey R:
    shared_secret = HKDF(X25519(scan_privkey, R), info="UmbraVox_StealthKey_v1")
    candidate_addr = SHA-256(spend_pubkey + shared_secret * G)[0..20]
    if candidate_addr == tx.recipient_id: this message is for me
```

**Privacy gain**: Each message uses a distinct `recipient_id`. Observer cannot link messages to the same recipient without the scan private key.

**Limitation**: `sender_addr` remains the same across messages (sender signs with their identity key). Sender unlinkability requires additional mechanisms (see 2.3).

### 2.3 Ring Signatures (Feasibility Analysis)

Ring signatures would allow the sender to prove they are a member of a set of possible signers without revealing which one.

**Feasibility assessment**:

| Factor | Assessment |
|--------|-----------|
| Cryptographic complexity | HIGH -- Ed25519 ring signatures (e.g., LSAG or CLSAG) require hand implementation per project constraints |
| Verification cost | O(n) per ring member -- at ring size 11, ~11x signature verification cost per tx |
| Block size impact | ~32 bytes per ring member (pubkey) + ~64 bytes proof -- ring size 11 adds ~416 bytes |
| Interaction with account nonces | PROBLEMATIC -- nonce-based double-spend prevention requires knowing the sender; ring signatures break this |
| Interaction with fee deduction | PROBLEMATIC -- fees must be deducted from a specific account |
| Interaction with stake determination | NEUTRAL -- staking is a separate operation |

**Conclusion**: Ring signatures are **infeasible for v1 or v2** in the current account-based model. The account model fundamentally requires identifying the sender to deduct fees and increment nonces. Ring signatures are compatible with UTXO models (cf. Monero) but would require a complete redesign of the ledger model.

**Alternative for sender privacy**: Sender stealth addresses (sender generates a fresh one-time address, funds it from their main account via a mixing step, then sends the message from the one-time address). This requires a mixing/tumbling protocol and is deferred to v2+.

---

## 3. Transaction Type Hiding

### 3.1 Current State (v1)

The `msg_type` byte at offset 1 in every message block is transmitted in cleartext. An observer can trivially distinguish:

- Chat messages (0x00, 0x01) from key management (0x02, 0x03, 0x04)
- Session establishment (KEY_EXCHANGE) from ongoing conversation (TEXT)
- Ratchet refreshes (0x04), which occur every ~50 messages per direction, revealing approximate message count

Additionally, transaction sizes are highly distinctive:
- KEY_EXCHANGE and RATCHET_REFRESH: always 2 blocks
- PREKEY_BUNDLE: ~3-4 blocks (100 OPKs)
- KEY_REPLENISH: ~2 blocks (50 OPKs)
- Normal TEXT: usually 1 block
- STAKE_WITHDRAW: distinctive consensus-layer format

### 3.2 Mitigation: Uniform Transaction Format (V1)

**Requirement**: All transaction types MUST be indistinguishable in their on-chain representation.

**Design**:

1. **Encrypt the message type**: Move `msg_type` inside the encrypted payload. The on-chain transaction envelope carries no type discriminator. The recipient decrypts and discovers the type.

2. **Uniform transaction size**: Pad all transactions to a fixed size of 2 blocks (2,048 bytes on-chain). Single-block messages are padded with a second dummy block. Multi-block messages exceeding 2 blocks are split into multiple 2-block transactions linked only by encrypted internal references.

3. **Uniform block count in envelope**: The `total_blocks` field in the cleartext header is always 2. Actual multi-block reassembly information is inside the encrypted payload.

4. **Key management transactions camouflaged**: KEY_EXCHANGE, KEY_ROTATE, KEY_REPLENISH, and RATCHET_REFRESH are padded to 2 blocks and indistinguishable from TEXT messages. PREKEY_BUNDLE (which is larger) is split across multiple 2-block transactions.

**Cost**: Bandwidth overhead of ~50% for single-block messages (padded to 2 blocks). Acceptable for a privacy-focused messaging protocol.

**Residual distinguisher**: Transaction frequency patterns may still reveal type (e.g., a burst of 2-block transactions from a new account likely includes KEY_REGISTER). Mitigated by cover traffic (see Section 3.3).

### 3.3 Cover Traffic for Type Masking

Extend the existing Dandelion++ DUMMY (0xFF) mechanism:

- Nodes generate cover transactions at a configurable baseline rate (default: 1 per 60 seconds)
- Cover transactions are indistinguishable from real 2-block transactions (same size, same envelope format, encrypted payload of random bytes, valid fee payment)
- Cover transactions are included on-chain (they cost fees) but are discarded by the recipient (who cannot decrypt them, or decrypts to a DUMMY type)
- This masks the timing pattern of real transactions

**Trade-off**: Cover traffic costs real MTK in fees. The burn component creates economic drag. This is an opt-in feature; users choose their privacy/cost trade-off.

---

## 4. Fee Amount Hiding

### 4.1 Current State (v1)

The `fee` field in the transaction header is a cleartext `Word64`. Fee amounts reveal:

- Message size (fees scale linearly with `ceil(size_bytes / 1024)`)
- User's economic behavior (high fees suggest urgency or large messages)
- Congestion response (fee changes over time correlate with EMA adjustments)

### 4.2 Fixed Fees (V1)

**Design**: All transactions pay an identical fee regardless of size or type.

```
fixed_fee = base_fee * 2   -- 2-block equivalent (matches uniform tx size from Section 3)
```

Since all transactions are padded to 2 blocks (Section 3.2), all transactions pay `base_fee * 2`. The `fee` field becomes redundant (it is always the same value) but is retained for forward compatibility.

**Advantages**:
- Eliminates fee as a side channel entirely
- Simple implementation
- Compatible with EMA-adjusted base_fee (all nodes compute the same fixed_fee)

**Disadvantages**:
- Users sending short messages overpay (subsidize bandwidth)
- No fee market for priority during congestion

### 4.3 Option B: Confidential Fees (v2+)

**Design**: Use Pedersen commitments to hide fee amounts while proving they meet the minimum.

```
fee_commitment = r * H + fee * G
range_proof: fee >= base_fee * block_count
```

Where H is a nothing-up-my-sleeve generator point and r is a blinding factor.

**Requirements**:
- Hand-implemented Pedersen commitments over Curve25519
- Bulletproofs or similar range proof (compact proof that fee >= minimum without revealing exact value)
- Validator verification: check that commitment opens to a value >= required fee

**Feasibility**: HIGH complexity. Bulletproofs require ~10KB per proof and significant implementation effort. Deferred to v2+. Fixed fees (Option A) provide equivalent privacy with far less complexity.

### 4.4 Recommendation

Adopt **fixed fees (Option A)** in conjunction with uniform transaction sizing. This eliminates the fee side channel completely without cryptographic overhead.

---

## 5. Timestamp Precision

### 5.1 Current State (v1)

Two timestamp sources are visible on-chain:

1. **Block header `bhSlotNo`**: 11-second slot granularity. All transactions in a block share the same slot number. This is the coarser timestamp.

2. **Message header `timestamp`**: 48-bit millisecond-precision timestamp set by the sender. This is inside the 1K block at offset 42.

The message-level timestamp provides sub-slot precision that enables:
- Correlation of message timing with external events (user behavior patterns)
- Ordering analysis within a single block (multiple txs from same sender)
- Cross-chain timing correlation if the user interacts with other systems

### 5.2 Mitigation: Quantize Message Timestamps

**V1 implementation**: Quantize the `timestamp` field to slot boundaries.

```
quantized_timestamp = (timestamp_ms / 11000) * 11000
```

All messages in the same slot have identical timestamps. This eliminates sub-slot timing information.

**Additionally in V1:** Remove the `timestamp` field from the cleartext header entirely. Move it inside the encrypted payload (the recipient can read it; observers cannot). Replace the cleartext field with zeros or random padding.

### 5.3 Timing Correlation Residual

Even with quantized timestamps, slot-level timing (11-second granularity) permits correlation attacks:

- An adversary monitoring two endpoints can correlate "Alice sent a message in slot N" with "Bob received a message in slot N+1"
- With Dandelion++ latency of ~370-530ms, most messages arrive within the same or next slot

**Mitigation**: The primary defense is Dandelion++ stem-phase randomization, which adds 160-320ms of stem traversal plus variable fluff propagation. Combined with cover traffic (Section 3.3), this raises the noise floor for timing correlation.

**Accepted residual**: Slot-level timing correlation at 11-second granularity is an accepted limitation. The 11-second slot already provides significant timing obfuscation compared to typical 2-second blockchain slots.

---

## 6. Block Producer Metadata

### 6.1 Current State

The block producer's identity key (`bhIssuerVK`) is public in every block header, along with the VRF proof that they were elected slot leader. This is inherent to Ouroboros Praos: the VRF proof must be publicly verifiable to prevent impersonation.

### 6.2 Privacy Implications

A block producer sees all transactions in the block they produce. The producer's identity is public. This creates a metadata link:

- **Transaction ordering**: Producer chose which mempool transactions to include (though ordering is deterministic by tx hash per doc/10-security.md)
- **Inclusion timing**: Producer decided to include a transaction in this specific slot rather than letting it wait
- **Censorship signal**: Absence of a transaction from a producer's block (when the producer had it in mempool) may signal selective censorship

### 6.3 Analysis

The block producer learns no more than any other full node about transaction content (all payloads are encrypted). The producer's identity being public is a **necessary property** of the consensus mechanism -- without it, VRF proofs cannot be verified and the chain cannot be validated.

**Threat model**: A malicious producer could:
1. Correlate the IP source of Dandelion++ stem transactions they receive with the transactions they include -- mitigated by stem-phase relay (producer is unlikely to be the stem originator's direct peer)
2. Selectively exclude transactions from specific sender addresses -- mitigated by timeout-based forced inclusion (if a valid tx is not included within k slots, other producers are incentivized to include it)

### 6.4 Mitigation

No protocol change needed. Block producer identity is an accepted and necessary metadata exposure. The existing deterministic transaction ordering (by tx hash) prevents producer-chosen ordering attacks.

---

## 7. CBOR Serialization Metadata

### 7.1 Current State

Per doc/07-message-format.md, transactions are serialized as CBOR arrays with positional semantics. The schema is:

```
Transaction = CBOR [tx_header, tx_body, tx_witness]
  tx_header: [version, chain_revision, tx_hash, fee, ttl]
  tx_body:   [sender_addr, nonce, msg_blocks[], dandelion_stem]
  tx_witness: [ed25519_signature]
```

### 7.2 CBOR-Level Distinguishers

CBOR encoding can leak type information through:

1. **Array length**: Different transaction types may produce CBOR arrays of different lengths. A KEY_REGISTER transaction with 100 OPKs has a different CBOR structure than a TEXT message.

2. **Major type bytes**: CBOR encodes integers, byte strings, and arrays with different major type prefixes. The sequence of major type bytes at predictable offsets can fingerprint transaction types.

3. **Integer encoding width**: CBOR uses variable-width integer encoding (1, 2, 4, or 8 bytes depending on value). A fee of 10 MTK encodes in 1 byte; a fee of 10,000 MTK encodes in 2 bytes. This leaks fee magnitude even without reading the value.

4. **Nested structure depth**: KEY_REGISTER transactions contain nested arrays (OPK lists) that produce deeper CBOR nesting than flat TEXT messages.

### 7.3 Mitigation: Canonical Encoding Requirements

The following requirements apply to all CBOR encoding (doc/07-message-format.md already mandates canonical encoding):

1. **Deterministic encoding**: All encoders MUST produce identical byte sequences for identical logical values (RFC 8949 Section 4.2, Core Deterministic Encoding).

2. **Fixed-width integer encoding for sensitive fields**: The `fee` field MUST always be encoded as a CBOR uint64 (8 bytes, major type 0 + additional info 27), regardless of value. This prevents leaking fee magnitude through encoding width.

3. **Fixed CBOR structure**: All transaction envelopes MUST have identical CBOR structure: a 3-element array containing a 5-element header array, a 4-element body array, and a 1-element witness array. Unused fields are filled with zero-value placeholders.

4. **Uniform msg_blocks array length**: After uniform transaction sizing (Section 3.2), `msg_blocks[]` always contains exactly 2 elements. Each element is a 1,024-byte CBOR byte string.

5. **No optional fields in v1**: The `dandelion_stem` flag is stripped before block inclusion. No CBOR `null` or absent-field encoding appears in on-chain transactions.

### 7.4 Fuzz Testing Requirement

The CBOR encoder/decoder (generated from `codegen/Specs/MessageFormat.schema` per doc/07-message-format.md) must be fuzz-tested to verify:

- No structural differences between transaction types after uniform formatting
- Round-trip `decode(encode(tx)) == tx` for all valid transactions
- Malformed CBOR is rejected gracefully (never crash, never accept)
- Canonical encoding check: `encode(decode(bytes)) == bytes` for all valid encoded transactions

---

## 8. Chain Analysis Resistance

### 8.1 Transaction Graph in the Account Model

UmbraVox uses an account model (not UTXO). Each account has a persistent `sender_addr` derived from its Ed25519 identity key. This means:

- **Full communication graph is trivially constructable**: for any epoch, enumerate all transactions and build a directed graph of `sender_addr -> recipient_id` edges
- **Frequency analysis**: count edges to determine communication intensity between any pair
- **Social graph inference**: cluster analysis reveals social groups, hub nodes, isolated pairs
- **Temporal patterns**: message timing reveals activity schedules (work hours, sleep patterns, time zones)

### 8.2 Mitigation Layers

**Layer 1 -- Stealth addresses (V1)**: Break recipient linkability. Each message uses a one-time `recipient_id`. Observer cannot determine whether two transactions go to the same recipient without the scan key. See Section 2.2.

**Layer 2 -- Sender address rotation**: At each epoch boundary (and optionally within epochs), users generate a new Ed25519 identity keypair and re-register. The new identity is unlinkable to the old one on-chain. Existing Signal sessions continue unaffected (session keys are independent of blockchain identity).

```
Epoch N: user has identity IK_1, sender_addr = SHA-256(IK_1)[0..20]
Epoch N+1: user generates IK_2, registers new prekey bundle
  sender_addr = SHA-256(IK_2)[0..20]
  No on-chain link between IK_1 and IK_2
```

**Limitation**: Contacts must be notified of the new identity through a secure side channel (or via a final message from the old identity containing the new identity, which itself creates a one-time link).

**Layer 3 -- Decoy transactions (v2)**: Inject decoy transactions with random `recipient_id` values that no real user can decrypt. These are indistinguishable from stealth-addressed real transactions. Decoys dilute the transaction graph, making frequency analysis less reliable.

**Layer 4 -- Truncation (existing)**: The 11-day truncation cycle destroys the on-chain transaction history. Post-truncation, the transaction graph from the prior cycle is only available to archival adversaries (Section 10).

### 8.3 Graph Obfuscation Metrics

For v2, the following metrics should be tracked:

| Metric | Target |
|--------|--------|
| Effective anonymity set (recipients) | >= 10 per transaction (with stealth addresses + decoys) |
| Graph density (decoy ratio) | >= 2:1 decoy:real transactions |
| Cross-epoch identity linkage probability | < 5% (with address rotation + stealth addresses) |
| Communication pair distinguishability | Indistinguishable from random at p > 0.05 (statistical test) |

---

## 9. 11-Day Truncation as Metadata Defense

### 9.1 What Truncation Destroys

Per doc/05-truncation.md, at each cycle boundary:

| Data category | Destroyed? | Metadata implication |
|---------------|-----------|---------------------|
| Message transactions | Yes | Communication graph for the cycle is erased from protocol state |
| Transaction hashes | Yes | Individual message identifiers gone |
| Account nonces | Reset | Per-account message count history erased |
| Spendable balances | Reset to rewards | Spending patterns within cycle erased |
| Fee history | Yes | Economic behavior within cycle erased |
| Block headers | Yes | Timing data and producer assignments erased |
| Adaptive parameters | Recomputed | Prior cycle's congestion signal flattened |

### 9.2 What Truncation Preserves

| Data category | Persists? | Metadata implication |
|---------------|----------|---------------------|
| Staked balances | Yes | Wealth and validator commitment visible across all cycles |
| Validator set | Yes | Persistent public identity for validators |
| Key registry | Yes (in genesis) | Identity keys, SPKs, OPK counts carry forward |
| Treasury balance | Yes | Protocol economic state |
| Punitive factors | Yes (P_carryover) | Penalty history derivable across cycles |
| Referral attribution | Yes (3 cycles) | Onboarding relationships visible for 33 days |
| Accumulated hash | Yes (genesis) | Binding to prior cycle's chain (not individual txs) |

### 9.3 Truncation Effectiveness

Truncation provides a **hard temporal bound** on metadata retention at the protocol level. No honest node retains pre-truncation transaction data. This means:

- An adversary who joins the network mid-cycle cannot reconstruct prior cycles' communication graphs
- A subpoena targeting protocol-level data can only obtain the current cycle (max 11 days)
- Statistical analysis of communication patterns is limited to 11-day windows

**Limitation**: Truncation is a protocol-level defense only. It does not bind archival nodes (Section 10).

### 9.4 Cross-Cycle Linkage via Persistent Data

Even without transaction history, persistent data enables some cross-cycle analysis:

- **Validator identity**: same pubkey appears as validator across cycles, providing a fixed anchor
- **Key registry**: same identity key in the key registry across cycles links the user's blockchain identity (mitigated by address rotation in Section 8.2)
- **Stake amounts**: changes in staked balance between cycles reveal economic activity
- **Punitive factor trajectory**: a validator's reward changes reveal penalty/recovery state

**Mitigation**: Address rotation at cycle boundaries (Section 8.2) severs the key registry link. Validator identity persistence is inherent to PoS and cannot be mitigated without breaking consensus.

---

## 10. Archival Node Threat

### 10.1 Threat Description

An archival adversary (per doc/10-security.md: "runs permanent full node, never deletes data; correlates metadata across cycles") retains all blocks, transactions, and headers beyond the protocol's 11-day truncation window.

**Capabilities**:
- Reconstruct communication graphs across arbitrarily many cycles
- Perform long-term social network analysis
- Correlate address rotations by analyzing behavioral patterns (message timing, peer sets, activity schedules)
- Link pre-rotation and post-rotation identities via side channels (first message from new identity to same peer set)

### 10.2 No Protocol Defense

Per doc/10-security.md, there is **no protocol-level defense** against archival adversaries. The protocol cannot force a node to delete data -- it can only ensure that honest nodes do delete it at truncation.

This is a fundamental limitation: any data broadcast to the network is available to any node that received it. Encryption protects message content, but metadata (sender, recipient, timing, size) is necessarily cleartext for routing and validation.

### 10.3 Mitigations (Non-Protocol)

**Technical mitigations that reduce archival value**:

1. **Stealth addresses (V1)**: Archival nodes store one-time recipient addresses. Without the scan key, they cannot determine which addresses belong to the same recipient. This reduces the archival graph to `sender -> opaque_one_time_address` edges.

2. **Address rotation**: If users rotate sender identity at each cycle boundary, archival cross-cycle sender linkage requires behavioral correlation (statistical, not deterministic). With stealth addresses, both sides of the graph are anonymized.

3. **Uniform transaction format**: With all transactions being identical in size and CBOR structure, archival type classification is limited to encrypted content (inaccessible).

4. **Cover traffic**: Decoy transactions stored by archival nodes dilute the graph with noise.

**Operational mitigations**:

5. **Jurisdictional pressure**: Operators in jurisdictions with data protection laws (GDPR, etc.) may be legally required to delete data at truncation. Archival nodes in such jurisdictions face legal risk.

6. **Social norm**: The protocol specification explicitly states that retaining data beyond truncation violates the protocol's intended behavior. Node software does not provide an archival mode.

7. **Disk cost**: At ~1,198 bytes per transaction and ~1 block per 55 seconds, raw chain data accumulates at ~2 MB/day. Over years this is manageable, but the analytical value degrades as stealth addresses and cover traffic are adopted.

### 10.4 Residual Risk Assessment

| Scenario | Risk with v1 | Risk with v2 (stealth + rotation + cover) |
|----------|-------------|------------------------------------------|
| Single-cycle graph reconstruction | HIGH | MEDIUM (sender still linkable without mixing) |
| Cross-cycle identity linkage | HIGH (same keys) | LOW (rotated addresses, stealth recipients) |
| Long-term social network analysis | HIGH | MEDIUM (behavioral correlation possible) |
| Message content recovery | NONE (encrypted) | NONE (encrypted) |

---

## 11. Metadata Budget

Classification of every metadata type by disposition:

### 11.1 Legend

| Classification | Meaning |
|---------------|---------|
| **Eliminated** | No information leakage; metadata fully removed or encrypted |
| **Minimized** | Information leakage reduced to minimum required for protocol function |
| **Accepted** | Known leakage, inherent to protocol design (e.g., PoS consensus); no feasible mitigation |

### 11.2 Full Metadata Budget

| Metadata item | V1 classification | Status | Mitigation |
|---------------|-------------------|--------|------------|
| **Message content** | Eliminated | Eliminated | Signal + PQ encryption |
| **Sender identity (sender_addr)** | Minimized | Minimized | V1: address rotation per epoch |
| **Recipient identity (recipient_id)** | Eliminated | Eliminated | V1: DKSAP stealth addresses |
| **Sender-recipient linkage** | Minimized | Minimized | V1: stealth addresses + address rotation |
| **Transaction type (msg_type)** | Eliminated | Eliminated | V1: encrypted inside payload, uniform format |
| **Fee amount** | Eliminated | Eliminated | V1: fixed fees |
| **Message size (block count)** | Eliminated | Eliminated | V1: uniform 2-block transactions |
| **Message timestamp (ms)** | Eliminated | Eliminated | V1: inside encrypted payload |
| **Slot-level timing (11s)** | Minimized | Minimized | Inherent to consensus; Dandelion++ provides noise |
| **Account nonce** | Minimized | Minimized | V1: address rotation resets nonce |
| **Signal ratchet pubkey** | Eliminated | Eliminated | V1: inside encrypted payload |
| **msg_number (ratchet counter)** | Eliminated | Eliminated | V1: inside encrypted payload |
| **payload_length** | Eliminated | Eliminated | V1: fixed payload size |
| **message_id (multi-block link)** | Eliminated | Eliminated | V1: all txs are 2 blocks; no multi-block linking needed |
| **Block producer identity** | Minimized | Minimized | Necessary for consensus; no additional leakage |
| **VRF proof/output** | Minimized | Minimized | Necessary for consensus verification |
| **CBOR structure** | Eliminated | Eliminated | V1: uniform CBOR layout, fixed-width integers |
| **Staked balances** | Accepted | Accepted | Inherent to PoS; no mitigation feasible |
| **Validator set membership** | Accepted | Accepted | Inherent to PoS; no mitigation feasible |
| **Key registry (identity keys)** | Minimized | Minimized | V1: address rotation at cycle boundary |
| **Referral attribution** | Accepted | Accepted | 3-cycle expiry limits exposure window |
| **Punitive factor (P_carryover)** | Accepted | Accepted | Derivable from reward changes; inherent to penalty system |
| **Faucet claims** | Accepted | Accepted | Reveals new user events; minimal risk |
| **Transaction graph (full epoch)** | Minimized | Minimized | V1: stealth addresses + rotation |
| **Historical chain data** | Minimized | Minimized | 11-day truncation; archival nodes are out-of-scope threat |
| **IP address of originator** | Minimized | Minimized | Dandelion++ stem phase; cover traffic |
| **Cover traffic distinguishability** | Eliminated | Eliminated | DUMMY messages are same format, filtered at mempool |

### 11.3 Summary Counts

| Classification | V1 count |
|---------------|----------|
| Eliminated | 14 |
| Minimized | 11 |
| Accepted (permanent, inherent to PoS) | 5 |

### 11.4 V1 Privacy Architecture

All metadata protections listed above are included in V1. The priority order reflects implementation dependencies, not deferral:

1. **Stealth addresses (DKSAP)** — eliminates recipient linkability
2. **Uniform transaction format (2-block)** — eliminates type, size, and fee side channels
3. **Encrypted header fields** — msg_type, timestamp, ratchet pubkey, msg_number inside encrypted payload
4. **Fixed fees** — eliminates fee side channel
5. **Address rotation protocol** — reduces sender linkability across epochs
6. **Decoy transactions** — dilutes transaction graph for archival resistance

No metadata leakage is accepted at launch.

---

## 12. Cross-References

| Topic | Document |
|-------|----------|
| Stealth address specification | `doc/hardening/03-stealth-addresses.md` |
| Threat model and adversary classes | `doc/10-security.md` |
| Transaction format and CBOR schema | `doc/07-message-format.md` |
| Dandelion++ IP obfuscation | `doc/08-dandelion.md` |
| 11-day truncation lifecycle | `doc/05-truncation.md` |
| Consensus and block structure | `doc/04-consensus.md` |
| Token economics and fee model | `doc/06-economics.md` |
| Cryptographic primitives | `doc/03-cryptography.md` |

## 13. DO-178C Traceability

This hardening specification maps to the following requirements:

| Requirement ID | Description | Mitigation section |
|---------------|-------------|-------------------|
| SEC-META-001 | Sender/recipient unlinkability | Section 2 |
| SEC-META-002 | Transaction type indistinguishability | Section 3 |
| SEC-META-003 | Fee amount privacy | Section 4 |
| SEC-META-004 | Timestamp precision minimization | Section 5 |
| SEC-META-005 | CBOR canonical encoding | Section 7 |
| SEC-META-006 | Chain analysis resistance | Section 8 |
| SEC-META-007 | Truncation metadata destruction verification | Section 9 |
| SEC-META-008 | Archival threat documentation | Section 10 |

Test evidence for metadata minimization mitigations: `test/evidence/metadata-minimization/`
