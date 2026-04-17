# Requirements Traceability Matrix

## Overview

This document provides bidirectional traceability between system requirements, source modules, test cases, and verification evidence as required by DO-178C DAL A (Section 6.3.4). Every high-level requirement traces forward to implementation modules and test cases, and every module traces backward to the requirement(s) it satisfies.

## Traceability Structure

- **Format**: REQ-\<area\>-\<number\> → Module → Test → Evidence
- **Areas**: CRYPTO, CONS, ECON, TRUNC, STORE, NET, DANDELION, VER, API
- **Bidirectional**: Each requirement links to its implementing module(s); each module links back to the requirement(s) it fulfills.
- **Coverage metric**: MC/DC (Modified Condition/Decision Coverage) per DO-178C DAL A structural coverage requirements.

## Requirements Index

### Cryptographic Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-CRYPTO-001 | AES-256-GCM encryption per NIST SP 800-38D | doc/03 | UmbraVox.Crypto.AES | test/crypto/aes_kat | Pending |
| REQ-CRYPTO-002 | SHA-256 per FIPS 180-4 | doc/03 | UmbraVox.Crypto.SHA256 | test/crypto/sha256_kat | Pending |
| REQ-CRYPTO-003 | X25519 key agreement per RFC 7748 | doc/03 | UmbraVox.Crypto.X25519 | test/crypto/x25519_kat | Pending |
| REQ-CRYPTO-004 | Ed25519 signatures per RFC 8032 (PureEd25519) | doc/03 | UmbraVox.Crypto.Ed25519 | test/crypto/ed25519_kat | Pending |
| REQ-CRYPTO-005 | ML-KEM-768 per FIPS 203 | doc/03 | UmbraVox.Crypto.MLKEM | test/crypto/mlkem_kat | Pending |
| REQ-CRYPTO-006 | HKDF per RFC 5869 | doc/03 | UmbraVox.Crypto.HKDF | test/crypto/hkdf_kat | Pending |
| REQ-CRYPTO-007 | Signal Double Ratchet (symmetric + DH ratchet) | doc/03 | UmbraVox.Protocol.Signal | test/protocol/signal_ratchet | Pending |
| REQ-CRYPTO-008 | PQXDH key agreement (X25519 + ML-KEM hybrid) | doc/03 | UmbraVox.Protocol.PQXDH | test/protocol/pqxdh | Pending |
| REQ-CRYPTO-009 | Signal+PQ composition security (IND-CCA2) | doc/03 | UmbraVox.Protocol.* | test/evidence/crypto-composition-proof | Pending |
| REQ-CRYPTO-010 | Constant-time crypto operations (no secret-dependent branching) | doc/03 | UmbraVox.Crypto.FFI.* | test/crypto/timing_verification | Pending |

### Consensus Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-CONS-001 | VRF-based slot leader election per Ouroboros Praos | doc/04 | UmbraVox.Consensus.VRF | test/consensus/vrf_leader_election | Pending |
| REQ-CONS-002 | Longest-chain fork choice with VRF tiebreaking | doc/04 | UmbraVox.Consensus.ForkChoice | test/consensus/fork_choice | Pending |
| REQ-CONS-003 | Slot assignment: floor(unix_timestamp_ms / 11000) | doc/04 | UmbraVox.Consensus.Slot | test/consensus/slot_assignment | Pending |
| REQ-CONS-004 | Composite stake calculation (balance-weighted with uptime multiplier) | doc/04 | UmbraVox.Consensus.Stake | test/consensus/stake_composite | Pending |
| REQ-CONS-005 | Heartbeat challenge-response for uptime verification | doc/04 | UmbraVox.Consensus.Heartbeat | test/consensus/heartbeat | Pending |
| REQ-CONS-006 | Two-tier finality: k=11 (messages, ~10 min) / k=22 (value, ~20 min) | doc/04 | UmbraVox.Consensus.Finality | test/consensus/finality_depth | Pending |
| REQ-CONS-007 | Epoch nonce derivation: SHA-256(prev_nonce \|\| last_VRF_output) | doc/04 | UmbraVox.Consensus.Nonce | test/consensus/nonce_derivation | Pending |
| REQ-CONS-008 | Network partition recovery via longest-chain reorg | doc/04 | UmbraVox.Consensus.Recovery | test/consensus/partition_recovery | Pending |
| REQ-CONS-009 | Mempool management: 50K TX cap, lowest-fee-first eviction | doc/04 | UmbraVox.Consensus.Mempool | test/consensus/mempool_eviction | Pending |
| REQ-CONS-010 | Truncation trigger at cycle boundary (22 epochs, 11 days) | doc/04, doc/05 | UmbraVox.Consensus.Truncation | test/consensus/truncation_trigger | Pending |

### Economic Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-ECON-001 | Conservation invariant: sum(all_tokens) == 11,000,000,000 MTK | doc/06 | UmbraVox.Econ.Invariant | test/econ/conservation_invariant | Pending |
| REQ-ECON-002 | Dynamic fee calculation: EMA-adjusted, clamped to [10, 10000] MTK | doc/06 | UmbraVox.Econ.Fee | test/econ/fee_calculation | Pending |
| REQ-ECON-003 | Reward distribution: uptime * punitive, proportional to pool | doc/06 | UmbraVox.Econ.Reward | test/econ/reward_distribution | Pending |
| REQ-ECON-004 | Penalty system: tiered (minor/moderate/severe) with carry-over decay | doc/06 | UmbraVox.Econ.Penalty | test/econ/penalty_tiers | Pending |
| REQ-ECON-005 | Onboarding faucet: min(10K, reserve/capacity) with PoW rate-limit | doc/06 | UmbraVox.Econ.Onboarding | test/econ/faucet_distribution | Pending |
| REQ-ECON-006 | User rebate: 5% of fees for bidirectionally active users (>=10 sent, >=10 received) | doc/06 | UmbraVox.Econ.Rebate | test/econ/rebate_eligibility | Pending |
| REQ-ECON-007 | Sybil bonding: 50,000 * n^2 MTK for nth validator per /16 subnet | doc/06 | UmbraVox.Econ.Sybil | test/econ/quadratic_bonding | Pending |
| REQ-ECON-008 | Validator onboarding bonus (10% of referred user fees, 3-cycle expiry) | doc/06 | UmbraVox.Economics.Onboarding | test/economics/onboarding_bonus | Pending |
| REQ-ECON-009 | Cycle-scoped burn: burned_total resets to 0 at cycle boundary | doc/06 | UmbraVox.Econ.CycleBurn | test/econ/cycle_burn_reset | Pending |
| REQ-ECON-010 | Supply restoration: pool = INITIAL_SUPPLY - staked - reserve - treasury at boundary | doc/06 | UmbraVox.Econ.SupplyRestore | test/econ/supply_restoration | Pending |
| REQ-ECON-011 | Adaptive burn rate: proportional controller, range [0.20, 0.80] | doc/06 | UmbraVox.Econ.AdaptiveController | test/econ/adaptive_burn_rate | Pending |
| REQ-ECON-012 | Early truncation trigger: supply < threshold at epoch boundary | doc/06 | UmbraVox.Econ.EarlyTruncation | test/econ/early_truncation_trigger | Pending |
| REQ-ECON-013 | Adaptive parameter clamping: all params within defined bounds | doc/06 | UmbraVox.Econ.AdaptiveController | test/econ/param_clamping | Pending |
| REQ-ECON-014 | Minimum cycle duration: >= 1 epoch (3,927 slots) | doc/06 | UmbraVox.Econ.CycleDuration | test/econ/min_cycle_duration | Pending |
| REQ-ECON-015 | Treasury cap: <= 10% of INITIAL_SUPPLY, excess to pool | doc/06 | UmbraVox.Econ.TreasuryCap | test/econ/treasury_cap | Pending |

### Truncation Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-TRUNC-001 | Snapshot: compute Merkle root of all account balances, stakes, and metadata at cycle boundary | doc/05 | UmbraVox.Truncation.Snapshot | test/truncation/snapshot_merkle | Pending |
| REQ-TRUNC-002 | Attestation: require 2/3+ validator signatures on snapshot hash | doc/05 | UmbraVox.Truncation.Attestation | test/truncation/attestation_quorum | Pending |
| REQ-TRUNC-003 | Genesis creation: produce new genesis block from attested snapshot | doc/05 | UmbraVox.Truncation.Genesis | test/truncation/genesis_creation | Pending |
| REQ-TRUNC-004 | WAL recovery: detect incomplete truncation via WAL marker, resume from last committed entry | doc/04, doc/05 | UmbraVox.Truncation.WAL | test/truncation/wal_recovery | Pending |
| REQ-TRUNC-005 | Cross-epoch replay prevention: reject transactions referencing pre-truncation block hashes | doc/05 | UmbraVox.Truncation.Replay | test/truncation/replay_prevention | Pending |
| REQ-TRUNC-006 | Offline handling: nodes rejoining after truncation receive new genesis + proof | doc/05 | UmbraVox.Truncation.Rejoin | test/truncation/offline_rejoin | Pending |
| REQ-TRUNC-007 | Early truncation: supply-based trigger integrates with snapshot phase | doc/05, doc/06 | UmbraVox.Truncation.EarlyTrigger | test/truncation/early_trigger | Pending |
| REQ-TRUNC-008 | Supply restoration: pool restored and burned_total reset during truncation execution | doc/05, doc/06 | UmbraVox.Truncation.SupplyRestore | test/truncation/supply_restore | Pending |

### Storage Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-STORE-001 | State DB: persistent storage of account balances, stakes, and metadata | doc/07 | UmbraVox.Store.StateDB | test/store/state_db_crud | Pending |
| REQ-STORE-002 | Key store: encrypted storage of node private keys (Ed25519, X25519, ML-KEM) | doc/07 | UmbraVox.Store.KeyStore | test/store/key_store_encrypt | Pending |
| REQ-STORE-003 | Block store: append-only storage of blocks within current cycle | doc/07 | UmbraVox.Store.BlockStore | test/store/block_store_append | Pending |
| REQ-STORE-004 | WAL (Write-Ahead Log): crash-recovery log for truncation and state transitions | doc/07 | UmbraVox.Store.WAL | test/store/wal_crash_recovery | Pending |

### Network Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-NET-001 | Noise_IK handshake for authenticated encrypted peer connections | doc/09 | UmbraVox.Net.Noise | test/net/noise_ik_handshake | Pending |
| REQ-NET-002 | Kademlia DHT for peer discovery and routing | doc/09 | UmbraVox.Net.Kademlia | test/net/kademlia_routing | Pending |
| REQ-NET-003 | Peer scoring: reputation-based connection management | doc/09 | UmbraVox.Net.PeerScore | test/net/peer_scoring | Pending |
| REQ-NET-004 | Bootstrap: initial peer discovery from hardcoded seed nodes | doc/09 | UmbraVox.Net.Bootstrap | test/net/bootstrap_connect | Pending |
| REQ-NET-005 | Chain sync: request and validate missing blocks from peers | doc/09 | UmbraVox.Net.ChainSync | test/net/chain_sync | Pending |

### Dandelion++ Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-DANDELION-001 | Stem phase routing: forward transaction to single selected peer | doc/08 | UmbraVox.Dandelion.Stem | test/dandelion/stem_routing | Pending |
| REQ-DANDELION-002 | Relay selection: choose stem relay via deterministic pseudorandom function per epoch | doc/08 | UmbraVox.Dandelion.Relay | test/dandelion/relay_selection | Pending |
| REQ-DANDELION-003 | Embargo timer: transition stem→fluff after timeout (prevents stuck transactions) | doc/08 | UmbraVox.Dandelion.Embargo | test/dandelion/embargo_timeout | Pending |
| REQ-DANDELION-004 | Cover traffic: generate dummy stem transactions at random intervals | doc/08 | UmbraVox.Dandelion.Cover | test/dandelion/cover_traffic | Pending |
| REQ-DANDELION-005 | Anonymity bounds: provable unlinkability under honest-majority assumption | doc/08 | UmbraVox.Dandelion.Analysis | test/evidence/dandelion-anonymity-proof | Pending |

### Versioning Requirements

| ID | Requirement | Source Doc | Module | Test | Coverage |
|----|------------|-----------|--------|------|----------|
| REQ-VER-001 | Chain revision: monotonically increasing revision counter embedded in genesis block, incremented at each truncation | doc/05, doc/11 | UmbraVox.Versioning.ChainRevision | test/versioning/chain_revision | Pending |
| REQ-VER-002 | Version negotiation: peers exchange protocol version during handshake, reject incompatible versions, negotiate common feature set | doc/09, doc/11 | UmbraVox.Versioning.Negotiate | test/versioning/version_negotiate | Pending |
| REQ-VER-003 | Software backward compatibility: new nodes can sync and validate chains produced by older protocol versions | doc/11 | UmbraVox.Versioning.Compat | test/versioning/backward_compat | Pending |

## Status Summary

| Area | Total Requirements | Implemented | Tested | MC/DC Coverage | Evidence Complete |
|------|-------------------|-------------|--------|----------------|-------------------|
| CRYPTO | 10 | Pending | Pending | Pending | Pending |
| CONS | 10 | Pending | Pending | Pending | Pending |
| ECON | 15 | Pending | Pending | Pending | Pending |
| TRUNC | 8 | Pending | Pending | Pending | Pending |
| STORE | 4 | Pending | Pending | Pending | Pending |
| NET | 5 | Pending | Pending | Pending | Pending |
| DANDELION | 5 | Pending | Pending | Pending | Pending |
| VER | 3 | Pending | Pending | Pending | Pending |
| **Total** | **60** | **Pending** | **Pending** | **Pending** | **Pending** |

## Maintenance

This matrix is updated at each phase gate per doc/12-development-phases.md. Automated extraction from code annotations will supplement manual entries once implementation begins. The traceability chain must be complete (no orphan requirements, no untraceable modules) before each phase gate review.

### Annotation Convention (for future implementation)

Source code modules will use structured annotations to enable automated traceability extraction:

```
-- @req REQ-CRYPTO-001
-- @verify test/crypto/aes_kat
-- @evidence doc/evidence/aes-gcm-compliance.pdf
```

These annotations will be parsed by the CI pipeline to generate an up-to-date traceability report at each build.
