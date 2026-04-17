# Language Decision and Project Structure

## Language: Haskell

**Recommendation: Haskell** (GHC, using only `base` and GHC-bundled libraries)

Rationale:
- **Correctness first**: The type system encodes invariants at compile time -- critical for crypto and consensus code
- **Purity**: Referential transparency makes reasoning about cryptographic state machines tractable
- **Concurrency**: STM (Software Transactional Memory) and `async` are in `base`/GHC-bundled for concurrent peer management
- **Performance**: Compiled native code; GHC's runtime handles thousands of lightweight threads
- **Standard library coverage**: `base` provides ByteString, networking (`Network.Socket`), concurrency (`Control.Concurrent`), STM, binary encoding, and IO

## No External Libraries Constraint

We use only packages that ship with GHC (`base`, `bytestring`, `containers`, `array`, `stm`, `network`, `binary`, `directory`, `filepath`, `time`, `process`, `unix`). All cryptographic algorithms, serialization formats, consensus logic, and P2P protocols are hand-implemented.

## Build Configuration

**Supported GHC versions**: GHC 9.6 and above. The codebase uses no language extensions beyond those available in GHC 9.6, ensuring forward compatibility with newer compiler releases without feature gating.

**Cabal build flags**:

- `-fpure-haskell` -- selects the pure Haskell reference implementations for all crypto primitives. When this flag is disabled (the default for production builds), the build links FFI stubs wrapping constant-time C implementations instead.
- `-fprofiling` -- enables GHC's cost-centre profiling annotations for performance analysis. Not used in production binaries.
- `-fcoverage` -- compiles with HPC (Haskell Program Coverage) instrumentation enabled. This flag is always active in CI test builds to produce the coverage artifacts required for DO-178C evidence.

**HPC configuration**: When `-fcoverage` is active, HPC instruments every top-level and local binding in all modules under `src/UmbraVox/` and `codegen/`. Coverage ticks are written to `.tix` files at test-suite exit. The CI pipeline merges per-test-suite `.tix` files via `hpc combine`, then generates HTML and machine-readable reports via `hpc markup` and `hpc report`, depositing results into `test/coverage/`.

## Code Generation Toolchain

Rather than writing every primitive by hand, we use a code generation toolchain (Template Haskell or a standalone codegen binary) to mechanically derive implementations from formal specifications. The generators produce:

- **Crypto primitives from FIPS/RFC algorithmic specs**: Structured spec files (e.g., `SHA256.spec` encoding FIPS 180-4) are parsed and transformed into both pure Haskell reference implementations and FFI stubs for constant-time production execution.
- **CBOR serialization from schema definitions**: A `.schema` file describing the wire format is compiled into encode/decode functions, eliminating hand-written serialization bugs.
- **Protocol state machines from typed FSM specs**: `.fsm` files define states, transitions, and guards for protocols (Signal handshake, consensus rounds). The generator emits a typed state machine with exhaustiveness checking at compile time.
- **Test harnesses with embedded test vectors**: For every generated module, the toolchain also emits a test harness pre-loaded with official test vectors (NIST CAVP, RFC appendices), ensuring the generated code is verified against known-good outputs from day one.

### Input Format Specifications

The code generators consume three structured input formats. Each format is designed to be auditable, diffable, and expressive enough to capture the semantics of its target domain without ambiguity.

**`.spec` files -- Crypto primitive specifications**: Structured extraction from FIPS/RFC prose. Each `.spec` file contains the following fields:

- **Algorithm name**: canonical identifier (e.g., `SHA-256`, `AES-256`, `ML-KEM-768`)
- **Block size**: input block size in bytes
- **Round count**: number of transformation rounds
- **Constants table**: named constant arrays (e.g., SHA-256 K values, AES S-box) expressed as literal hex sequences
- **Step-by-step operations**: the algorithm body expressed in a restricted DSL limited to: variable assignments, bitwise operations (AND, OR, XOR, NOT, rotate, shift), modular arithmetic (add, subtract, multiply mod 2^n), and conditionals (if/then/else on boolean predicates). No loops -- iteration is expressed as unrolled round sequences with explicit round indices.

**`.fsm` files -- Protocol state machine specifications**: Each `.fsm` file defines:

- **States**: an enum of all protocol states (e.g., `Idle | AwaitingPreKey | HandshakeComplete | Ratcheting | Error`)
- **Events**: an enum of all input events (e.g., `RecvPreKeyBundle | RecvMessage | Timeout | UserSend`)
- **Transitions**: a total mapping of (state x event) pairs to (next-state x [action]) pairs, where actions are side-effect descriptors (e.g., `SendMessage`, `DeriveKey`, `ResetTimer`)
- **Guards**: boolean predicates on the current state (e.g., `hasValidSession`, `prekeyAvailable`) that gate transitions
- **Exhaustive pattern matching enforced**: the generator rejects any `.fsm` file where the (state x event) matrix is not fully covered, ensuring no unhandled protocol condition at compile time

**`.schema` files -- CBOR serialization schemas**: A CDDL-like notation (following RFC 8610 conventions) defining CBOR wire structure. Each `.schema` file specifies:

- **Field names**: human-readable identifiers for each field in the structure
- **Types**: constrained to CBOR primitives -- `uint`, `bstr` (byte string), `tstr` (text string), `array`, `map`
- **Fixed sizes**: byte-length constraints where applicable (e.g., `bstr .size 32` for a 256-bit key)
- **Optional fields**: fields marked with `?` that may be absent in the encoded form, generating `Maybe`-typed accessors in the Haskell output

### Generator Invocation

Generators run as a pre-build step: `cabal configure && cabal run codegen`. The codegen binary reads all `.spec`, `.fsm`, and `.schema` files from `codegen/Specs/` and writes the generated Haskell modules into the appropriate locations under `src/UmbraVox/` and `test/Test/`. Generated outputs are checked into version control rather than produced ephemerally at build time -- this ensures reproducibility (any commit is fully buildable without running the generator) and provides a clear audit trail for certification reviewers who need to inspect exactly what code was compiled.

### TQL-1 Qualification

The code generator is itself a DAL A artifact. It carries its own MC/DC coverage suite and is qualified to Tool Qualification Level 1 (TQL-1) under DO-330. This means errors in the generator are treated with the same rigor as errors in the generated code -- the tool cannot silently introduce defects that escape verification.

### Dual Output Strategy

Each generator produces two artifacts from a single spec:

1. **Pure Haskell** -- used for correctness verification, property testing, and formal reasoning. These modules live under `src/UmbraVox/` alongside the rest of the codebase and are the canonical reference.
2. **FFI stubs** -- thin Haskell wrappers around constant-time C implementations generated from the same spec. These are used in production builds where timing-side-channel resistance is required (AES, X25519, ML-KEM).

The build system selects pure or FFI variants via a Cabal flag, allowing the test suite to run against the pure implementation while production binaries link the constant-time variant.

### Equivalence CI Check

A nightly CI pipeline runs both the pure Haskell and FFI code paths on identical inputs -- 10,000+ random test vectors per cryptographic primitive -- and asserts bitwise-identical outputs. This guarantees that the FFI constant-time implementations are semantically equivalent to the pure reference implementations, catching any divergence introduced by C compiler optimizations, endianness assumptions, or translation errors in the FFI layer.

## Project Structure

```
UmbraVox/
|-- UmbraVox.cabal
|-- app/
|   |-- Main.hs                      -- Entry point
|-- codegen/
|   |-- CryptoGen.hs                 -- Generates crypto primitives from specs
|   |-- CBORGen.hs                   -- Generates serialization from schema
|   |-- FSMGen.hs                    -- Generates state machines
|   |-- TestGen.hs                   -- Generates test harnesses + vectors
|   |-- Specs/
|   |   |-- SHA256.spec              -- FIPS 180-4 structured spec
|   |   |-- AES256.spec              -- FIPS 197 structured spec
|   |   |-- MLKEM768.spec           -- FIPS 203 structured spec
|   |   |-- Signal.fsm              -- Signal protocol state machine
|   |   |-- Consensus.fsm           -- Consensus state machine
|   |   |-- MessageFormat.schema    -- CBOR schema definition
|-- src/
|   |-- UmbraVox/
|   |   |-- Crypto/                   -- All cryptography (hand-implemented)
|   |   |   |-- AES.hs               -- AES-256 block cipher
|   |   |   |-- GCM.hs               -- Galois/Counter Mode (AEAD)
|   |   |   |-- SHA256.hs            -- SHA-256 hash
|   |   |   |-- SHA512.hs            -- SHA-512 hash
|   |   |   |-- HMAC.hs              -- HMAC construction
|   |   |   |-- HKDF.hs              -- HKDF key derivation (RFC 5869)
|   |   |   |-- Curve25519.hs        -- X25519 ECDH (RFC 7748)
|   |   |   |-- Ed25519.hs           -- Ed25519 signatures (RFC 8032)
|   |   |   |-- MLKEM.hs             -- ML-KEM-768 (CRYSTALS-Kyber, FIPS 203)
|   |   |   |-- VRF.hs               -- ECVRF-ED25519-SHA512 (RFC 9381)
|   |   |   |-- Random.hs            -- CSPRNG (system entropy + ChaCha20)
|   |   |   |-- Signal/
|   |   |   |   |-- X3DH.hs          -- Extended Triple Diffie-Hellman
|   |   |   |   |-- PQXDH.hs         -- Post-Quantum X3DH (hybrid X25519 + ML-KEM)
|   |   |   |   |-- DoubleRatchet.hs -- Double Ratchet Algorithm
|   |   |   |   |-- SenderKeys.hs    -- Group messaging sender keys
|   |   |   |   |-- Session.hs       -- Signal session state management
|   |   |   |-- PQWrapper.hs         -- Post-quantum outer encryption layer
|   |   |   |-- KeyStore.hs          -- Encrypted-at-rest key management
|   |   |-- Consensus/
|   |   |   |-- Types.hs             -- SlotNo, EpochNo, CycleNo, BlockNo
|   |   |   |-- Block.hs             -- Block and BlockHeader types
|   |   |   |-- Ledger.hs            -- Ledger state: balances, nonces, stakes
|   |   |   |-- Protocol.hs          -- Ouroboros Praos adaptation
|   |   |   |-- LeaderElection.hs    -- VRF-based slot leader selection
|   |   |   |-- Validation.hs        -- Block and transaction validation
|   |   |   |-- ForkChoice.hs        -- Longest chain + density rule
|   |   |   |-- Nonce.hs             -- Epoch nonce evolution
|   |   |   |-- Truncation.hs        -- 11-day chain truncation + epoch genesis
|   |   |   |-- Mempool.hs           -- Transaction pool with fee validation
|   |   |-- Economics/
|   |   |   |-- Token.hs             -- Token supply, distribution
|   |   |   |-- Fees.hs              -- Message cost: C_base * ceil(size/1024)
|   |   |   |-- Rewards.hs           -- Uptime-weighted stake multiplier rewards
|   |   |   |-- Penalty.hs           -- Abuse detection, punitive multipliers
|   |   |   |-- Cycle.hs             -- 11-day cycle reset logic
|   |   |   |-- Onboarding.hs        -- New user token bootstrap
|   |   |-- Network/
|   |   |   |-- Transport.hs         -- TCP connection management
|   |   |   |-- Noise.hs             -- Noise_IK handshake (hand-implemented)
|   |   |   |-- PeerManager.hs       -- Peer discovery, scoring, banning
|   |   |   |-- Gossip.hs            -- Block + transaction gossip protocol
|   |   |   |-- Dandelion.hs         -- Dandelion++ stem/fluff routing
|   |   |   |-- Protocol.hs          -- Wire protocol encoding/decoding
|   |   |   |-- Sync.hs              -- Chain synchronization protocol
|   |   |-- Chat/
|   |   |   |-- Session.hs           -- Chat conversation state
|   |   |   |-- Message.hs           -- Message types, 1K block chunking
|   |   |   |-- Transaction.hs       -- Chat message -> blockchain transaction
|   |   |   |-- Contacts.hs          -- Contact/identity management
|   |   |   |-- API.hs               -- JSON-RPC API for UI clients
|   |   |-- Storage/
|   |   |   |-- ChainDB.hs           -- Append-only block file storage
|   |   |   |-- StateDB.hs           -- Account state (flat file + index)
|   |   |   |-- Index.hs             -- Block/tx indexes
|   |   |   |-- Checkpoint.hs        -- Truncation checkpoints
|   |   |-- Protocol/
|   |   |   |-- CBOR.hs              -- CBOR serialization (hand-implemented)
|   |   |   |-- MessageFormat.hs     -- 1024-byte block layout
|   |   |   |-- WireFormat.hs        -- Network message envelope
|-- test/
|   |-- Test/
|   |   |-- Crypto/                   -- Crypto test vectors (NIST, RFC)
|   |   |-- Consensus/               -- Property tests for consensus
|   |   |-- Economics/               -- Economic model simulations
|   |   |-- Network/                 -- P2P protocol tests
|   |   |-- Integration/             -- Multi-node scenarios
|   |-- coverage/
|   |   |-- mcdc/                    -- MC/DC coverage reports (DO-178C)
|   |   |-- structural/             -- Statement + branch coverage
|   |   |-- codegen/                -- Coverage of the code generators themselves
|   |-- evidence/
|   |   |-- traceability/           -- Req -> code -> test mapping matrices
|   |   |-- reviews/                -- Code review and inspection records
|   |   |-- analysis/               -- Dead code, data/control coupling analysis
```

## DO-178C Compliance Notes

The project structure supports **bidirectional traceability** as required by DO-178C objectives for DAL A software:

1. **Spec files to generated code**: Each `.spec` and `.fsm` file in `codegen/Specs/` maps deterministically to one or more generated Haskell modules under `src/UmbraVox/`. The generator embeds traceability annotations (comments referencing the source spec, section, and line) in every generated function, so a reviewer can trace any line of generated code back to the requirement it satisfies.

2. **Generated code to generated tests**: `TestGen.hs` reads the same spec files and emits test harnesses that exercise every branch and decision in the generated code. Test case identifiers embed the spec reference, creating an unbroken link from requirement through implementation to verification.

3. **Generated tests to coverage reports**: Running the test suite under HPC (Haskell Program Coverage) produces statement, branch, and MC/DC coverage data deposited in `test/coverage/`. These reports are the primary evidence artifacts for certification, demonstrating that every requirement has been both implemented and verified.

4. **Evidence packaging**: The `test/evidence/` directory collects the derived artifacts needed for a DO-178C certification package -- traceability matrices mapping requirements to code to tests, code review records, and structural analyses (dead code detection, data coupling, control coupling). These are generated or updated as part of the CI pipeline and are always consistent with the current codebase.

This closed loop -- spec to code to test to coverage to evidence -- ensures that no requirement exists without a corresponding implementation and test, and no code exists without a requirement justifying its presence.

### MC/DC Measurement Strategy

GHC's HPC tool natively provides line and branch coverage but does not directly measure Modified Condition/Decision Coverage (MC/DC) as required by DO-178C DAL A. The project bridges this gap through three complementary techniques:

1. **Strict evaluation annotations on all decision points**: Every boolean expression in DAL A modules that participates in a branching decision (if/then/else, guards, case scrutinees) is annotated with strict evaluation (`BangPatterns` or `seq`). This prevents lazy evaluation from obscuring which conditions were actually evaluated during a test run, ensuring that HPC ticks faithfully reflect execution rather than thunk creation.

2. **Custom coverage instrumentation via Template Haskell**: A dedicated Template Haskell pass instruments compound boolean conditions (expressions involving `&&`, `||`, `not`, and comparison operators) by decomposing them into individual sub-expression evaluations. Each sub-expression is wrapped in a recording combinator that logs its truth value to a per-module coverage accumulator. Post-test-run analysis of these logs verifies that every boolean sub-expression in every decision has independently affected the decision outcome -- the formal MC/DC criterion.

3. **Property-based testing with condition isolation**: For each compound decision, the test suite includes property tests that systematically toggle each boolean sub-expression independently while holding all others fixed. This is achieved via targeted input generation that isolates the influence of each condition, ensuring that the MC/DC independence requirement is satisfied by construction rather than by accident.

The combined output of HPC branch data and the Template Haskell condition logs is merged into a unified MC/DC report deposited in `test/coverage/mcdc/`.
