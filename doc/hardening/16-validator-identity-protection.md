# Hardening Spec 16: Validator Identity Protection

## References

- doc/04-consensus.md (VRF leader election, heartbeat protocol, stake determination)
- doc/10-security.md (threat model, adversary classes)
- doc/proof-03-consensus.md (consensus safety/liveness proofs)
- doc/08-dandelion.md (Dandelion++ IP obfuscation)
- doc/09-network.md (P2P transport, peer discovery, Noise_IK)
- Tor Project, "Tor: The Second-Generation Onion Router" (Dingledine et al., 2004)
- I2P Technical Documentation (geti2p.net)
- RFC 9381 (ECVRF-ED25519-SHA512-ELL2)
- Jarecki et al., "Highly-Efficient and Composable Password-Protected Secret Sharing (Or: How to Protect Your Bitcoin Wallet Online)", IEEE S&P 2016

## Scope

Validators are high-value targets. They hold staked tokens, produce blocks, and maintain consensus. An adversary who identifies validators can target them for coercion, key theft, denial-of-service, or regulatory pressure. This specification defines protocol-level and operational measures to protect validator identities, locations, and infrastructure from discovery.

Adversary model: state-level adversary (doc/10-security.md, Class 7) with ISP-level traffic analysis, active network probing, and unlimited archival capacity.

---

## 1. IP Address Protection

### 1.1 Tor Hidden Service for Validator-to-Validator Communication

Validators SHOULD operate a Tor v3 hidden service (onion address) for all validator-to-validator traffic. This includes consensus messages (`VOTE`, `EPOCH_BOUNDARY`, `STAKE_ANNOUNCE`), heartbeat responses, and direct peer connections with other known validators.

**Protocol specification:**

```
Validator onion address derivation:
  onion_keypair = Ed25519_generate()            -- independent from staking key
  onion_address = base32(SHA3-256(onion_pubkey) || checksum || version)

Connection flow:
  1. Validator publishes onion address to DHT (encrypted under its staking pubkey)
  2. Peer validators resolve onion address via Tor
  3. Noise_IK handshake proceeds over Tor circuit
  4. All multiplexed streams (consensus, blocks, transactions) tunnel through Tor

Tor circuit parameters:
  CircuitIdleTimeout = 600 seconds
  MaxCircuitDirtiness = 1800 seconds       -- rotate circuits every 30 minutes
  NumEntryGuards = 3
  UseEntryGuards = 1
  AvoidDiskWrites = 1
```

**Latency impact:** Tor adds 200-800ms RTT. With 11-second slot duration, this is tolerable for consensus participation. Validators MUST account for Tor latency in heartbeat response timing (10-slot window = 110 seconds provides ample margin).

**Fallback:** If Tor circuit establishment fails 5 consecutive times within 10 minutes, the validator MAY fall back to clearnet with a 60-second retry timer for Tor reconnection. Clearnet fallback MUST be logged as a security event.

### 1.2 Onion Routing for Block Propagation

Block propagation uses standard gossip (doc/08-dandelion.md: "Blocks NEVER use Dandelion++ stem -- always standard gossip"). This means block producers announce blocks to all peers, which reveals the producer's IP to direct peers.

**Mitigation:** Validators SHOULD relay produced blocks through a Tor circuit to at least 2 non-adjacent peers before the block enters standard gossip. This adds one hop of indirection between the producer's IP and the first gossip announcement.

```
on_produce_block(block):
  tor_peers = select_random(outbound_tor_peers, 2)
  for peer in tor_peers:
    send_via_tor(peer, BLOCK_ANNOUNCE(block.header_hash))
  -- Do NOT announce to clearnet peers simultaneously
  -- Let tor_peers propagate via their own gossip connections
  -- Embargo: wait 3 seconds, then announce to remaining peers if block
  --   has not propagated back to self via gossip
```

### 1.3 I2P as Alternative Transport

I2P provides an alternative anonymity layer with different trust assumptions than Tor (distributed rather than directory-authority-based).

**Configuration:**

```
I2P tunnel parameters:
  TunnelLength = 3 hops (inbound and outbound)
  TunnelQuantity = 3 (redundancy)
  TunnelBackupQuantity = 1
  LeaseSetType = encrypted (type 5)

Address publication:
  Validator publishes I2P destination to DHT
  Format: base64(destination_hash)
  Dual-stack: validator MAY operate both Tor and I2P simultaneously
```

**Selection criteria:**

| Factor | Tor | I2P |
|--------|-----|-----|
| Latency | 200-800ms | 500-2000ms |
| Maturity | High | Medium |
| Exit node risk | N/A (hidden services) | N/A (garlic routing) |
| Resistance to Sybil | Directory authorities | Distributed netdb |
| Censorship resistance | Pluggable transports | SSU/NTCP2 obfuscation |
| Recommended for | Primary transport | Fallback / diversity |

Validators in jurisdictions where Tor is blocked SHOULD use I2P or Tor with pluggable transports (obfs4, Snowflake).

---

## 2. VRF Output as Identity Signal

### 2.1 The Linkability Problem

The VRF proof in the block header (`bhVRFProof`) is verifiable against the issuer's public key (`bhIssuerVK`). This is by design: any node must verify that the block producer was legitimately elected. However, this creates a permanent, cryptographically bound link between blocks and validator identity.

From doc/04-consensus.md:

```
VRF_input = epoch_nonce || slot_number
(proof, output) = VRF_prove(node_secret_key, VRF_input)
```

The proof is deterministic given `(secret_key, VRF_input)`. Any observer can verify `VRF_verify(node_public_key, VRF_input, proof)` and confirm the producer's identity.

### 2.2 Analysis of Blind VRF Schemes

**Blind VRFs** (Jarecki et al.) allow a prover to generate a VRF output without revealing which public key was used, while still allowing verification that *some* valid key from an authorized set produced the output.

**Feasibility assessment for UmbraVox:**

| Property | Standard ECVRF | Blind/Anonymous VRF |
|----------|---------------|---------------------|
| Proof verifiability | Against specific pubkey | Against set of pubkeys |
| Prover anonymity | None | Within anonymity set |
| Proof size | ~80 bytes | ~2-5 KB (ring/group signature) |
| Verification cost | 1 EC multiplication | O(n) or O(log n) with accumulators |
| Implementation complexity | RFC 9381 | Research-stage |

**Candidate constructions:**

1. **Ring VRF (Burdges & De Feo, 2020):** VRF proof that proves membership in a ring of public keys without revealing which key. Proof size grows linearly with ring size. For 1000 validators, proofs would be approximately 32 KB each -- prohibitive for block headers.

2. **Group VRF with accumulator:** Uses a cryptographic accumulator to commit to the validator set. Constant-size proofs (~256 bytes), but requires a trusted setup or transparent accumulator (e.g., RSA-UFD or class group based). Adds a trusted setup ceremony or requires class group assumptions not yet standardized.

3. **Shuffle-based approaches:** Validators collectively shuffle their keys each epoch, and VRF proofs are against shuffled keys. Requires MPC in each epoch, adding latency and complexity.

**Conclusion:** Blind VRF schemes are not feasible for v1. The verification cost and proof size overheads conflict with the 11-second slot duration and the goal of simple block validation. The identity linkage from VRF proofs is an accepted residual risk, mitigated by the network-layer protections in Sections 1, 6, 7, and 8.

**Recommendation for v2:** Monitor standardization of Ring VRFs (particularly the W3C/IETF work on anonymous credentials). If constant-size Ring VRF proofs become practical (sub-millisecond verification, sub-512-byte proofs), revisit this decision.

### 2.3 Partial Mitigation: Ephemeral Issuer Keys

Validators MAY use **epoch-scoped issuer keys** to limit cross-epoch linkability:

```
Each epoch:
  ephemeral_key = Ed25519_generate()
  registration_tx = REGISTER_EPHEMERAL(
    staking_pubkey,
    ephemeral_pubkey,
    epoch_number,
    signature_under_staking_key
  )
  -- VRF and block signing use ephemeral_key for this epoch
  -- Staking key used only for registration and stake operations
```

This limits the window of identity linkage to a single epoch (12 hours) rather than the validator's entire lifetime. Cross-epoch linkage requires correlating registration transactions, which are themselves subject to Dandelion++ anonymization.

**Cost:** One additional transaction per epoch per validator. At ~216 active validators, this adds ~216 transactions per epoch (negligible vs. epoch capacity).

---

## 3. Block Production Deanonymization

### 3.1 Timing Analysis

When a validator produces a block, the block propagates outward from the producer. An adversary with multiple observation points can measure first-arrival times and triangulate the producer's approximate geographic location.

**Threat model:**

```
Adversary controls nodes A1..An at known geographic locations.
Block B produced at time T by unknown validator V.
Observation: A_i receives B at time T + d_i, where d_i correlates with
  geographic distance from V to A_i.
Triangulation: minimize ||pos(V) - pos(A_i)|| - c * d_i over all i,
  where c is propagation speed.
```

With 10 observation points across continents, geographic resolution of approximately 500-1000 km is achievable for clearnet validators.

### 3.2 Countermeasure: Production Delay Jitter

Validators MUST inject random delay before announcing a produced block:

```
on_produce_block(block):
  jitter = uniform_random(0, PRODUCTION_JITTER_MAX_MS)
  wait(jitter)
  announce(block)

PRODUCTION_JITTER_MAX_MS = 800  -- 0 to 800ms uniform random delay
```

**Rationale for 800ms maximum:** The slot duration is 11 seconds. Block timestamp validity requires being within 11 seconds of expected slot time (doc/04-consensus.md). An 800ms jitter consumes at most ~7% of the slot window, leaving sufficient margin for propagation and validation.

**Impact on consensus:** The jitter delays block propagation by 400ms on average. With k_val=22 (value tier) finality depth and ~55-second average block interval, this has negligible effect on safety or liveness. The density-based fork choice (doc/04-consensus.md lines 134-149) is robust to sub-second delays because density is measured over multi-slot windows.

### 3.3 Countermeasure: Relay Through Tor

As specified in Section 1.2, routing produced blocks through Tor before gossip entry adds network-level indirection that defeats simple triangulation. Combined with jitter, the adversary must overcome both temporal noise and network-path indirection.

### 3.4 Residual Risk

Even with jitter and Tor relay, a long-term statistical adversary can correlate block production patterns (which slots a validator wins) with VRF public key identity. This is inherent to the VRF design (Section 2) and cannot be mitigated without blind VRFs.

---

## 4. Heartbeat Response Privacy

### 4.1 The Problem

From doc/04-consensus.md:

```
response = sign(challenge || validator_pubkey, validator_secret_key)
```

Heartbeat responses are signed with the validator's key and included in block bodies. This reveals:

1. **Which validators are online** (responded within 10 slots).
2. **Response timing** (which slot included the response), giving latency hints.
3. **Validator liveness patterns** over time (uptime profiling).

### 4.2 Privacy-Preserving Heartbeat Protocol

**Replace direct-signed responses with blinded responses:**

```
Revised heartbeat protocol:

  1. Slot leader includes challenge C in block header (unchanged).

  2. Validator computes response:
       nonce = random_32_bytes()
       commitment = SHA-256(C || validator_pubkey || nonce)
       signature = sign(commitment, validator_secret_key)
       response_msg = (commitment, signature, validator_pubkey)

  3. Validator sends response_msg via fluff broadcast
     (heartbeats MUST NOT use stem phase; they are inherently
     attributable protocol messages, so stem provides no
     additional anonymity -- see hardening/02 Section 9.3).

  4. Block producers include heartbeat responses in block body.
     Responses are ordered by commitment hash (deterministic, not
     by arrival time).

  5. Nonce is revealed in a subsequent block (within 20 slots of
     challenge) to complete the proof.
```

**Ordering by commitment hash** prevents block producers from leaking arrival-time information that could correlate with geographic location.

**Fluff-mode broadcast** for heartbeat responses is required because heartbeats are inherently attributable (they contain the validator's public key), so Dandelion++ stem phase provides no additional anonymity (see hardening/02 Section 9.3).

### 4.3 Batched Response Aggregation (v2)

For v2, consider BLS aggregate signatures for heartbeat responses. A designated aggregator collects individual BLS signatures and produces a single aggregate signature verifiable against the set of responding validators. This reduces on-chain footprint and makes individual response timing unobservable (only the aggregate appears on-chain).

**Not feasible for v1** because UmbraVox uses Ed25519 exclusively (doc/03-cryptography.md), and BLS would introduce a new curve dependency.

---

## 5. Stake Amount Privacy

### 5.1 Current Design

Stake amounts are public and required for VRF threshold computation:

```
threshold = 1 - (1 - f)^sigma_j
sigma_j = stake[validator] / total_stake
```

Every node must compute this threshold for every validator to verify block legitimacy. This means `stake[validator]` must be globally known.

### 5.2 Confidential Staking via Pedersen Commitments: Feasibility Analysis

**Pedersen commitments** can hide stake values: `C = g^v * h^r` commits to value `v` with blinding factor `r`, and range proofs ensure `v >= 0`.

**The fundamental problem:** VRF threshold verification requires computing `(1 - f)^sigma_j`, which is a function of the *plaintext* stake ratio. With Pedersen commitments, verifiers do not know `sigma_j` and cannot compute the threshold.

**Potential approach: Zero-knowledge threshold proof.**

The block producer provides a ZK proof that:

1. Their committed stake `C_j` opens to value `v_j`.
2. `sigma_j = v_j / V_total` where `V_total` is the total committed stake.
3. `VRF_output_normalized < 1 - (1 - f)^sigma_j`.

This requires proving an exponentiation relation in zero knowledge, which involves:

- Bulletproofs for range proofs: ~700 bytes, ~50ms verification.
- Exponentiation proof: requires representing `(1-f)^sigma_j` as an arithmetic circuit. The exponentiation is over a rational exponent, requiring fixed-point encoding in the circuit. Estimated circuit size: >10,000 gates.
- Total verification time estimate: 200-500ms per block.

**Feasibility verdict: NOT FEASIBLE for v1.**

With 11-second slots and a need for sub-100ms block validation, 200-500ms for stake privacy proofs consumes too much of the time budget. Additionally, the total stake `V_total` must be verifiable, requiring a running commitment accumulator updated at every stake change, adding protocol complexity.

**Partial mitigation (operational):**

- Validators MAY split their stake across multiple pseudonymous identities (at the cost of reduced per-identity election probability, which is perfectly offset by having multiple identities -- stake is additive in election probability).
- Splitting stake is permissionless: any address can stake.
- **Risk:** Splitting reduces individual stake below minimum thresholds and increases the attack surface (more keys to protect).

### 5.3 Stake Bucketing (v2 Consideration)

Instead of publishing exact stake amounts, publish only the *bucket* a validator falls into:

```
Buckets: [1000, 5000, 25000, 125000, 625000] MTK
Validator's effective stake for VRF = bucket_floor(actual_stake)

Example: validator with 17,000 MTK staked is in bucket 5000.
  VRF threshold computed with sigma_j based on 5000.
  Remaining 12,000 MTK of election probability is forfeited.
```

This reveals only order-of-magnitude stake, at the cost of reduced election fairness (validators lose election weight from the rounding). Requires careful analysis of incentive effects before adoption.

---

## 6. Network Topology Hiding

### 6.1 Threat

An adversary operating multiple nodes can map the validator connection graph by:

1. **Connection probing:** Connecting to all reachable IPs and observing which accept connections.
2. **Message timing correlation:** Observing which peers relay blocks/transactions first.
3. **PEX harvesting:** Collecting peer exchange responses to build a global topology map.

Knowing the topology reveals which validators are directly connected, enabling targeted eclipse attacks and partition attacks.

### 6.2 Connection Multiplexing

Validators SHOULD tunnel all peer connections through a common multiplexer that presents a single outbound profile:

```
Architecture:
  [Validator Node] --local--> [Multiplexer/Proxy]
                                  |-- Tor --> Peer A (validator)
                                  |-- Tor --> Peer B (validator)
                                  |-- I2P --> Peer C (validator)
                                  |-- clearnet --> Peer D (non-validator)
                                  |-- clearnet --> Peer E (non-validator)

Multiplexer behavior:
  - All outbound connections appear to originate from the same Tor circuit
    or I2P tunnel set
  - Connection timing is jittered: new connections opened at random
    intervals (Poisson process, lambda = 1 connection per 30 seconds)
  - Connection teardown is delayed: connections marked for close are kept
    alive for a random period [60, 300] seconds with keepalive traffic
```

### 6.3 Decoy Connections

Validators SHOULD maintain decoy connections to non-validator nodes:

```
Decoy parameters:
  MIN_DECOY_CONNECTIONS = 4
  MAX_DECOY_CONNECTIONS = 8
  DECOY_TRAFFIC_RATE = 1 message per 30 seconds (Poisson)

Decoy traffic:
  - Send PING/PONG and PEX_REQUEST at normal rates
  - Relay blocks and transactions normally (decoy peers are real gossip peers)
  - The adversary cannot distinguish validator-to-validator connections
    from validator-to-decoy connections without traffic volume analysis
```

### 6.4 PEX Response Sanitization

Validators MUST NOT include other known validator peers in PEX responses. PEX responses SHOULD contain only non-validator peer addresses:

```
on_pex_request(from_peer):
  candidate_peers = known_peers - validator_peers - {from_peer}
  response = random_sample(candidate_peers, min(50, len(candidate_peers)))
  send(from_peer, PEX_RESPONSE(response))
```

This prevents an adversary from harvesting the validator-to-validator topology through PEX alone.

---

## 7. Geographic Distribution Inference

### 7.1 Propagation Timing Analysis

Block propagation timing reveals geographic hints. A block produced in Asia reaches Asian nodes 50-150ms before European nodes, and 150-300ms before North American nodes. Over many blocks from the same VRF key, statistical averaging reduces noise, yielding continent-level (or better) geographic attribution.

### 7.2 Countermeasure: Random Delay Injection

This is the block-reception analog to the production jitter in Section 3.2. Validators SHOULD add random delay before relaying received blocks to their peers:

```
on_receive_block(block, from_peer):
  validate(block)
  relay_jitter = exponential_random(mean = 200ms, max = 1000ms)
  schedule_relay(block, delay = relay_jitter)

-- Exponential distribution ensures most relays are fast (preserving
-- propagation efficiency) while adding enough noise to defeat timing
-- correlation at the tail.
```

**Impact analysis:** Average additional relay delay per hop: 200ms. With typical 4-6 hop propagation diameter, total added latency: 800-1200ms. This is within the 11-second slot tolerance and does not affect the 3-second 95th-percentile propagation target (doc/09-network.md) because the target is measured for non-hardened nodes. Hardened validators accept slightly higher propagation latency as the cost of geographic privacy.

### 7.3 Countermeasure: Tor-Based Block Relay

When blocks are relayed through Tor circuits (Section 1.2), geographic timing correlations are destroyed by the multi-hop onion routing. The 3-hop Tor circuit introduces variable latency that swamps any geographic signal.

---

## 8. Validator Infrastructure Fingerprinting

### 8.1 Threat Vectors

An adversary can fingerprint validator infrastructure via:

| Vector | Observable Signal |
|--------|------------------|
| TCP behavior | Window size, MSS, TTL, timestamps, SACK patterns |
| Noise handshake timing | Cryptographic operation latency reveals CPU class |
| Block validation speed | Time from block receipt to relay reveals hardware |
| Bandwidth profile | Sustained throughput reveals network tier |
| Uptime patterns | Maintenance windows reveal operational timezone |
| Software version | Announced in HANDSHAKE (doc/09-network.md) |

### 8.2 Protocol-Level Countermeasures

**TCP normalization:**

```
Validator SHOULD configure:
  net.ipv4.tcp_timestamps = 0        -- disable TCP timestamps
  net.ipv4.tcp_window_scaling = 1    -- use standard window scaling
  net.ipv4.ip_default_ttl = 64       -- normalize TTL

If operating behind Tor: TCP fingerprinting is moot (Tor terminates TCP).
```

**Handshake timing normalization:**

```
on_noise_handshake(peer):
  start = monotonic_clock()
  perform_handshake()
  elapsed = monotonic_clock() - start
  padding_delay = max(0, HANDSHAKE_TARGET_MS - elapsed)
  wait(padding_delay)

HANDSHAKE_TARGET_MS = 50  -- all handshakes appear to take exactly 50ms
                          -- (or Tor circuit latency, whichever is larger)
```

**Block relay timing normalization:**

Block relay jitter (Section 7.2) already normalizes relay timing. No additional measures needed.

**Software version masking:**

The HANDSHAKE message includes software version (doc/09-network.md). Validators SHOULD report the latest stable version regardless of actual running version, within the 3-minor-version compatibility window. This prevents version-based fingerprinting while maintaining protocol compatibility.

**Caution:** Reporting a false version is a mild protocol dishonesty. It is acceptable for privacy but MUST NOT be used to circumvent version-enforcement disconnection rules.

### 8.3 Operational Countermeasures

- **Maintenance windows:** Schedule restarts and updates during globally distributed maintenance windows (e.g., stagger across UTC offsets), not at local business hours.
- **Bandwidth shaping:** Cap outbound bandwidth to a standardized rate (e.g., 10 Mbps) to prevent bandwidth-tier fingerprinting, regardless of actual available bandwidth.
- **Resource padding:** If running on identifiable cloud infrastructure (e.g., specific AWS instance types), use a common instance class across the validator set to prevent cloud-provider fingerprinting.

---

## 9. Physical Security Recommendations

### 9.1 Tor-Only Operation

Validators in hostile jurisdictions (where blockchain operation is illegal or closely monitored) SHOULD operate in **Tor-only mode**:

```
Configuration: tor_only_mode = true

Behavior:
  - ALL connections (peer, DHT, PEX) routed through Tor
  - No clearnet connections accepted or initiated
  - DNS resolution via Tor (SOCKS5 with remote DNS)
  - System-level firewall blocks all non-Tor traffic:
      iptables -A OUTPUT -m owner --uid-owner UmbraVox -j REJECT
      iptables -A OUTPUT -m owner --uid-owner tor -j ACCEPT
  - Tor configured with pluggable transports (obfs4/meek) if Tor itself
    is blocked

Trade-offs:
  - Higher latency (200-800ms per connection)
  - Reduced peer diversity (only Tor-reachable peers)
  - Dependency on Tor network availability
  - Acceptable for validators with modest stake; not recommended for
    top-10 validators by stake (latency affects block production competitiveness)
```

### 9.2 VPS in Neutral Jurisdictions

Validators SHOULD run infrastructure in jurisdictions with strong privacy laws and no mandatory data retention for VPS providers:

```
Recommended operational setup:
  1. VPS rented with privacy-preserving payment (cryptocurrency)
  2. VPS provider in jurisdiction with no mandatory logging
  3. Full-disk encryption (LUKS) with remote unlock via Tor SSH
  4. No personally identifiable information in VPS account
  5. VPS provider selected for resistance to arbitrary seizure
     (requires legal process, not administrative request)

Key storage:
  - Staking key NEVER stored on VPS in plaintext
  - Use remote signing: VPS holds only ephemeral session keys
  - Staking key operations performed on air-gapped device,
    signed transactions relayed to VPS via Tor
```

### 9.3 Plausible Deniability Setup

For validators under direct physical threat:

```
Deniability architecture:
  1. Validator software runs inside an encrypted container
     (hidden volume, e.g., VeraCrypt hidden OS)
  2. Outer volume contains innocuous data (standard desktop)
  3. Inner volume contains validator node, keys, chain data
  4. Boot selection: different passphrase reveals different OS
  5. Chain data encrypted at rest with separate key from OS encryption

Duress protocol:
  - Validator configures a duress passphrase
  - Entering duress passphrase boots the decoy OS and triggers
    emergency key rotation (Section 10) via a pre-configured Tor relay
  - Staked tokens begin withdrawal to a pre-designated safe address
```

### 9.4 Hardware Security Modules

Validators with significant stake SHOULD use an HSM or secure enclave for key operations:

```
HSM requirements:
  - FIPS 140-2 Level 3 or higher
  - Support for Ed25519 signing
  - Support for ECVRF proving (RFC 9381 ECVRF-ED25519-SHA512-ELL2)
  - Tamper-evident and tamper-responsive
  - Key export disabled after provisioning

Alternative: Secure enclave (e.g., ARM TrustZone, Intel SGX)
  - Lower cost than dedicated HSM
  - Reduced tamper resistance (software-based side-channel attacks possible)
  - Acceptable for validators with moderate stake
```

---

## 10. Validator Key Compromise Response

### 10.1 Emergency Key Rotation Protocol

If a validator suspects key compromise, the following protocol executes:

```
Emergency key rotation sequence:

  Step 1: Generate new key pair on secure device (air-gapped)
    new_staking_key = Ed25519_generate()
    new_vrf_key = Ed25519_generate()   -- VRF uses same curve

  Step 2: Submit KEY_ROTATE transaction from compromised key
    KEY_ROTATE {
      old_pubkey: compromised_pubkey,
      new_pubkey: new_staking_key.public,
      new_vrf_pubkey: new_vrf_key.public,
      rotation_proof: sign(
        "KEY_ROTATE" || new_staking_key.public || new_vrf_key.public || slot_number,
        compromised_secret_key
      ),
      -- Optional: pre-signed by new key to prove possession
      new_key_proof: sign(
        "KEY_ROTATE_ACK" || compromised_pubkey || slot_number,
        new_staking_key.secret
      )
    }

  Step 3: Network processes KEY_ROTATE
    - Effective immediately in next epoch (not current epoch, to prevent
      mid-epoch stake manipulation)
    - Old key is blacklisted: cannot produce blocks, sign heartbeats,
      or submit further KEY_ROTATE transactions after the new epoch begins
    - Stake transfers to new key without cooldown period

  Step 4: Validator resumes operation with new keys

Time budget: KEY_ROTATE must be included within 1 epoch (12 hours)
  of submission. Priority: KEY_ROTATE transactions are treated as
  maximum-priority (above normal fee ordering).
```

### 10.2 Stake Withdrawal Under Duress

If the validator is under physical coercion:

```
Duress withdrawal protocol:

  Pre-configured:
    duress_address: a pre-designated withdrawal address controlled by
      a trusted third party, multisig quorum, or time-locked script

  Activation:
    Validator submits STAKE_WITHDRAW to duress_address
    -- Uses STAKE_WITHDRAW_IMMEDIATE (10% penalty, doc/04-consensus.md)
    -- 10% burn is acceptable as the cost of emergency extraction
    -- Remaining 90% sent to duress_address, not the validator's
       normal withdrawal address

  Duress detection (optional, pre-configured):
    If validator uses duress passphrase (Section 9.3), the node
    automatically submits STAKE_WITHDRAW_IMMEDIATE to duress_address
    and initiates KEY_ROTATE to a pre-generated safe key
```

### 10.3 Dead Man's Switch for Key Destruction

Validators MAY configure a dead man's switch:

```
Dead man's switch protocol:

  Configuration:
    DMS_HEARTBEAT_INTERVAL = 72 hours
    DMS_ACTION = KEY_ROTATE | STAKE_WITHDRAW | KEY_DESTROY
    DMS_SAFE_ADDRESS = <pre-configured address>
    DMS_CHANNEL = Tor hidden service | I2P | pre-signed transactions

  Operation:
    1. Validator sends a signed proof-of-life to a DMS service every
       DMS_HEARTBEAT_INTERVAL hours
    2. Proof-of-life: sign("DMS_ALIVE" || unix_timestamp, staking_key)
    3. If DMS service does not receive proof-of-life within 2x interval:
       a. Broadcast pre-signed STAKE_WITHDRAW_IMMEDIATE to network
       b. Broadcast pre-signed KEY_ROTATE to DMS_SAFE_ADDRESS key
       c. Securely delete all stored key material

  DMS service:
    - Runs on separate infrastructure from validator
    - Holds only pre-signed transactions (not keys)
    - Operates via Tor hidden service
    - Multiple DMS instances for redundancy (2-of-3 quorum to trigger)
```

### 10.4 Pre-Signed Emergency Transactions

Validators SHOULD maintain a set of pre-signed emergency transactions, updated each epoch:

```
Pre-signed transaction set (refreshed per epoch):

  1. STAKE_WITHDRAW_IMMEDIATE to safe address
     - Signed with current staking key
     - Valid for current epoch + 1 (expires after 2 epochs)

  2. KEY_ROTATE to pre-generated safe key
     - Safe key pair stored offline (air-gapped, geographically separate)
     - Signed with current staking key

  3. STAKE_WITHDRAW (graceful, with cooldown) to safe address
     - For non-emergency situations

Storage:
  - Encrypted on separate device from validator
  - Accessible via Tor from DMS service
  - MUST be re-generated each epoch (old pre-signed transactions
    become invalid as nonces advance)
```

---

## 11. Regulatory Compliance Considerations

### 11.1 Jurisdictional Risk Assessment

Validators operate in a spectrum of regulatory environments. The protocol itself is jurisdiction-neutral, but operators must assess local legal requirements.

**Risk categories:**

| Category | Example Jurisdictions | Risk to Validator |
|----------|----------------------|-------------------|
| Permissive | Switzerland, Singapore | Low |
| Uncertain | US, EU, UK | Medium |
| Restrictive | China, Russia, Iran | High |
| Hostile | Jurisdictions with blockchain bans | Critical |

### 11.2 Mandatory Reporting Considerations

Some jurisdictions require financial service providers to implement KYC/AML controls. Validator operation may or may not constitute a "financial service" depending on local law.

**Protocol-level position:** UmbraVox's protocol does not implement KYC/AML at the consensus layer. Validator software does not collect or store user identity information. The protocol treats all valid transactions equally regardless of origin.

**Operational compartmentalization:**

```
Legal compartmentalization architecture:

  Layer 1: Protocol operation (validator software)
    - No user-identifying information processed or stored
    - Validator key is pseudonymous
    - No logs containing user metadata retained beyond current epoch

  Layer 2: Infrastructure operation (VPS, networking)
    - Operated by a legal entity in a permissive jurisdiction
    - Entity has no visibility into protocol-layer content
    - Standard hosting ToS compliance only

  Layer 3: Economic participation (staking)
    - Stake may be held by a separate legal entity or trust
    - Stake ownership need not be publicly linked to
      infrastructure operation
    - Multi-signature staking keys can distribute control
      across jurisdictions
```

### 11.3 Subpoena and Legal Process Response

```
Recommended response protocol:

  1. Validator receives legal process requesting data
  2. Assess scope:
     a. Historical message content: not available (encrypted, and
        truncated after 11 days)
     b. Transaction metadata: available only for current cycle
        (truncated at cycle boundary)
     c. Validator key identity: available (but pseudonymous)
     d. IP addresses of peers: not available if operating via Tor
  3. Provide only information that:
     a. Actually exists (cannot produce deleted/truncated data)
     b. Is within the scope of the legal instrument
     c. Does not compromise other validators' security
  4. If compelled to provide ongoing monitoring:
     a. Evaluate whether continued operation is compatible with
        validator security obligations to the network
     b. Consider graceful exit (STAKE_WITHDRAW with cooldown)
     c. Notify the community via canary mechanism if legally permitted

Warrant canary:
  Validators MAY publish a periodic signed statement:
    "As of [date], [validator pseudonym] has not received any
     legal process requiring data disclosure or ongoing monitoring."
  Removal of the canary signals potential compromise without
  violating gag orders.
```

### 11.4 Validator Legal Entity Structure

```
Recommended structure for validators in uncertain jurisdictions:

  Option A: Foundation/Association in permissive jurisdiction
    - Non-profit entity holds staking keys
    - Board members in multiple jurisdictions
    - No single jurisdiction can compel key surrender

  Option B: Distributed key management
    - 2-of-3 multisig across jurisdictions
    - No single party holds complete staking key
    - Operational signing uses threshold signatures
    - Key ceremony documented for audit trail

  Option C: Bare trust arrangement
    - Trustee holds infrastructure
    - Beneficiary holds economic interest
    - Separation of control from benefit
```

---

## Summary of Mitigations by Attack Vector

| Attack Vector | Mitigation | Section | Effectiveness |
|---------------|-----------|---------|---------------|
| IP discovery | Tor hidden services, I2P | 1 | High |
| VRF identity linkage | Ephemeral epoch keys (partial) | 2 | Medium |
| Block production triangulation | Jitter + Tor relay | 3 | Medium-High |
| Heartbeat liveness profiling | Dandelion++ routing, ordering by hash | 4 | Medium |
| Stake amount disclosure | Stake splitting (operational) | 5 | Low |
| Topology mapping | Multiplexing, decoys, PEX sanitization | 6 | Medium-High |
| Geographic inference | Relay jitter, Tor routing | 7 | Medium |
| Infrastructure fingerprinting | TCP normalization, timing padding | 8 | Medium |
| Physical coercion | Tor-only, VPS, deniability, HSM | 9 | Jurisdiction-dependent |
| Key compromise | Emergency rotation, DMS, pre-signed txns | 10 | High |
| Regulatory exposure | Compartmentalization, canary, legal structure | 11 | Jurisdiction-dependent |

## Residual Risks (Accepted)

1. **VRF identity linkage within an epoch** is inherent to the Ouroboros Praos design and cannot be eliminated without blind VRFs (Section 2.2).
2. **Stake amounts must be publicly verifiable** for VRF threshold computation. Confidential staking is not feasible at protocol level without zero-knowledge proofs that exceed the time budget (Section 5.2).
3. **Long-term statistical correlation** of block production patterns can deanonymize validators over many epochs despite per-epoch ephemeral keys, if the adversary can link registration transactions.
4. **Tor network dependence** introduces availability risk: if Tor is disrupted, Tor-only validators lose connectivity.
5. **Physical security** is ultimately an operational concern outside protocol scope. The protocol provides tools (key rotation, DMS, pre-signed transactions) but cannot prevent physical coercion.

## Implementation Priority

| Priority | Component | Complexity |
|----------|-----------|------------|
| P0 (launch) | Block production jitter (3.2) | Low |
| P0 (launch) | Heartbeat via Dandelion++ (4.2) | Low |
| P0 (launch) | PEX response sanitization (6.4) | Low |
| P0 (launch) | Emergency key rotation (10.1) | Medium |
| P1 (post-launch) | Tor hidden service transport (1.1) | Medium |
| P1 (post-launch) | Decoy connections (6.3) | Low |
| P1 (post-launch) | Relay jitter (7.2) | Low |
| P1 (post-launch) | Pre-signed emergency transactions (10.4) | Medium |
| P2 (hardening) | I2P alternative transport (1.3) | Medium |
| P2 (hardening) | Ephemeral epoch keys (2.3) | Medium |
| P2 (hardening) | Infrastructure fingerprint countermeasures (8) | Low-Medium |
| P2 (hardening) | Dead man's switch (10.3) | Medium |
| P3 (research) | Blind/Ring VRF evaluation (2.2) | High |
| P3 (research) | Confidential staking (5.2, 5.3) | High |
