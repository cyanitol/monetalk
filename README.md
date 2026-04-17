# UmbraVox

A decentralized communications research project and technical manuscript.

UmbraVox is a protocol design, writing project, and reference implementation effort focused on censorship resistance, privacy-preserving communication, and durable freedom of thought and expression in the digital age.

This repository is published as both a technical artifact and an expressive work.

## Overview

UmbraVox proposes a decentralized communications system in which participants operate peer nodes rather than relying on centralized service providers. The design combines end-to-end encryption, post-quantum protective layers, network-level origin obfuscation, and short-lived ledger retention to study how lawful private communication systems may be described, analyzed, and implemented in modern computing environments.

This repository is part technical specification and part expressive work. It is intended to function simultaneously as:

- a written argument
- a systems design
- a reference architecture
- a proof-oriented software artifact
- the foundation for a longer book-length treatment of the subject

## Preface

Hello everyone,

I would like to announce the beginning of a new project.

For too long, coercion against freedom of conscience, freedom of inquiry, and freedom of expression has been tolerated in one form or another throughout human history. What is at stake is not merely secrecy for its own sake, but the preservation of one of mankind’s most important endowments: the freedom of self-direction in thought, belief, communication, and association.

Across time, religious, philosophical, and intellectual traditions have developed methods of guarded transmission to preserve meaning under conditions of hostility, censorship, persecution, or institutional corruption. These methods have taken many forms, including symbolic language, restricted commentary, encoded notation, disciplined oral transmission, and other practices intended to preserve truth, protect communities, and maintain continuity across generations.

UmbraVox is an attempt to describe a modern technical analogue to that broader human tradition. Just as texts were once preserved in caves, monasteries, remote communities, and hidden archives, this work explores whether cryptography, distributed systems, and formally reasoned software can help preserve lawful private discourse against censorship, mass surveillance, and unjust suppression.

This project is intended to be the first in a series. Its purpose is not only to describe a system in theory, but also to present a reference implementation strategy and a body of reasoning expressed through computer science, mathematics, and software construction. In that sense, UmbraVox is meant to be both descriptive and demonstrative: a technical manuscript, a design proposal, and an implementation-oriented proof artifact.

It is offered in the spirit of intellectual liberty, freedom of conscience, scientific inquiry, and the enduring right of human beings to preserve and share ideas without unjust interference.

## Expression and Legal Notice

This repository, and any related UmbraVox manuscripts, drafts, specifications, commentary, examples, proofs, or source text, are intended as expressive works. They may include political, philosophical, scientific, mathematical, literary, and technical speech.

Source code, algorithms, formal descriptions, pseudocode, protocol specifications, and implementation notes may also constitute protected expression in some jurisdictions. However, laws regulating cryptographic software, privacy technologies, export controls, publication, compilation, possession, distribution, importation, and operational deployment differ across countries and legal regimes.

Accordingly:

- this repository is provided for informational, research, educational, and expressive purposes
- nothing in this repository constitutes legal advice
- any person who compiles, ports, modifies, distributes, exports, deploys, or operates software derived from this work is solely responsible for compliance with applicable law
- the authors, contributors, and publishers make no representation that any implementation or use of this work is lawful in every jurisdiction

If you reduce any portion of this work to practice in executable form, distribute binaries, provide hosted services, or operate derived systems in the real world, you are responsible for determining and satisfying all legal, regulatory, licensing, and compliance obligations that apply where you live or operate.

## What UmbraVox Is

UmbraVox is a proposed decentralized chat and communications protocol in which each participant runs a full node. The system is designed around the following research goals:

- end-to-end confidentiality
- forward secrecy and post-compromise resilience
- post-quantum protective wrapping
- resistance to centralized censorship
- resistance to long-term mass retention
- network-level sender obfuscation
- formal reasoning about system behavior
- minimal dependency assumptions in the reference implementation

## Key Properties

- **End-to-end encrypted**: Signal Double Ratchet with an ML-KEM-768 post-quantum outer layer
- **Decentralized**: No central servers; consensus is maintained among participating nodes
- **Ephemeral by design**: 11-day chain truncation minimizes long-term message retention at the protocol level
- **Deniable**: Message content is designed without asymmetric signatures on payload content, preserving deniability properties
- **Spam-resistant**: Token-based participation costs and rewards help regulate abuse
- **Self-renewing**: Each 11-day cycle restores full token supply under the current economic model
- **IP-obfuscating**: Dandelion++ style propagation for on-chain messages and Noise_IK encrypted direct P2P sessions reduce origin-linkability
- **Self-contained reference approach**: Pure Haskell verification-oriented implementations with FFI into constant-time C for production targets, avoiding third-party library dependency assumptions in core design goals

## Dual-Mode Architecture

UmbraVox supports two transport modes:

- **On-chain (primary)**: Messages are broadcast via Dandelion++ and included in blocks. Provides strong censorship resistance with full metadata protection (stealth addresses, encrypted headers, fixed fees, uniform blocks). Latency: ~55 seconds average for block inclusion.
- **Direct P2P (preserved)**: Established Signal sessions can exchange messages directly over TCP + Noise_IK. Provides low latency (~50-150ms) but weaker censorship resistance. IP visible to peer unless using Tor.

## Documentation

All major design documentation lives in [`doc/`](doc/):

| Document | Description |
|----------|-------------|
| [01 - Overview](doc/01-overview.md) | System overview, architecture, encryption pipeline |
| [02 - Language & Structure](doc/02-language-and-structure.md) | Haskell, project layout, no-external-libraries constraint |
| [03 - Cryptography](doc/03-cryptography.md) | Primitives, Signal protocol, post-quantum wrapper, key registry |
| [04 - Consensus](doc/04-consensus.md) | Ouroboros Praos adaptation, VRF, block structure, stake |
| [05 - Truncation](doc/05-truncation.md) | 11-day cycle, snapshots, epoch genesis, state transitions |
| [06 - Economics](doc/06-economics.md) | Token supply, message costs, rewards, penalties, adaptive controller, Universe Cycle model |
| [07 - Message Format](doc/07-message-format.md) | Message block layout, block capacity (4,444 msgs), CBOR serialization, transaction envelope |
| [08 - Dandelion++](doc/08-dandelion.md) | IP obfuscation parameters, algorithm, failsafes |
| [09 - Network](doc/09-network.md) | P2P topology, transport security, discovery, peer scoring |
| [10 - Security](doc/10-security.md) | Threat model, adversary classes, deniability architecture |
| [11 - Node Architecture](doc/11-node-architecture.md) | Concurrency, storage layout, resource estimates, API |
| [12 - Development Phases](doc/12-development-phases.md) | Development roadmap and verification strategy |
| [20 - Economic Analysis](doc/20-economic-analysis.md) | Universe Cycle economic model analysis |

## Quick Numbers

| Parameter | Value |
|-----------|-------|
| Slot duration | 11 seconds |
| Cycle length | 11 days (22 epochs × 12 hours) |
| Message block size | ~4.44 MB (4,444 × 1,024 = 4,550,656 bytes per block) |
| Messages per block | 4,444 |
| Global throughput | ~80.8 msg/sec (~6.98M/day) |
| Message cost | Dynamic (10 to 10,000 MTK, EMA-adjusted) |
| Total supply | 11,000,000,000 MTK (restored each cycle) |
| Economic model | Universe Cycle |
| Send-to-display latency | ~370 to 530 ms |
| Settlement depth | k = 11/22 (message tier ~10 min, value tier ~20 min) |
| Compact block relay | Enabled (mandatory) |
| Minimum bandwidth | ~400 KB/s |

## Known Limitations (v1)

- **Steady-state storage**: ~80 GB steady-state storage requirement (commodity SSD territory)
- **Archival node risk**: Protocol-level truncation does not automatically prevent malicious archival retention
- **Offline message loss**: Users offline for a full cycle may lose messages permanently
- **Compression deferred**: Wire-level payload compression is not part of v1

## Status

Design and specification phase. No production release yet.

## License

See [LICENSE](LICENSE).

## Legal and Publishing Notes

For the legal framing of this repository and its status as an expressive
and research work, see [LEGAL-NOTICE.md](LEGAL-NOTICE.md) and
[PUBLISHING-NOTE.md](PUBLISHING-NOTE.md).