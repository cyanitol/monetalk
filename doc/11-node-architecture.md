# Node Architecture

## Concurrency Model

- One Haskell thread per peer connection (lightweight green threads via `forkIO`)
- STM for shared state (mempool, chain tip, peer table)
- `TVar` for mutable consensus state
- `TBQueue` for inter-component message passing

## Storage

- **Blocks**: Flat files, one per block, organized by epoch directory. Epoch numbering is sequential from genesis (epoch_000, epoch_001, ...). Block files named by slot number within epoch: `slot_000001.bin`. At truncation, all epoch directories except current are deleted.
- **State DB**: Append-only flat file with fixed-size records (64 bytes each). Record format: `[pubkey_hash: 20 bytes, balance: 8 bytes, nonce: 8 bytes, stake_weight: 8 bytes, punitive_factor: 4 bytes (fixed-point 16.16), padding: 16 bytes]`. In-memory index: `Map PubKeyHash FileOffset`, rebuilt from file scan on startup. CRC-32 per record for corruption detection.
- **Adaptive parameters**: Stored as part of the epoch genesis block and loaded into consensus state on startup. No change to per-account record format.
- **Chain revision**: Monotonically increasing integer stored in `chain_revision.db` and embedded in each genesis block. Incremented at every truncation. Nodes use this to detect chain identity across truncation boundaries and reject blocks from incompatible chain revisions. The revision history (revision number -> genesis hash) is maintained for bootstrap verification.
- **Key store**: Encrypted flat files. Key derivation: Argon2id(passphrase, salt=random_16_bytes, t=3, m=256MB, p=1) → 32-byte key. Salt stored in plaintext alongside encrypted key file. AES-256-GCM encryption with random 12-byte nonce per file. Nonce stored as file prefix.
- **Signal sessions**: One encrypted file per peer conversation.
- **Chat history**: Optional local plaintext storage (user preference, not protocol-level).

## Write-Ahead Log (Crash Recovery)

All state-modifying operations use WAL:

```
1. Write intent to $UmbraVox_DATA/wal/current.wal (fsync)
2. Apply change to target (state DB, block file, etc.)
3. Mark WAL entry as committed (fsync)
```

On startup recovery:

```
1. Read WAL entries sequentially
2. For each entry, check status field:
   - "pending"     → replay operation against state DB
   - "committed"   → verify state matches expected result
   - "rolled_back" → skip (no action needed)
3. Incomplete entries at EOF (no terminator 0xFF) are discarded
4. Verify state DB consistency (CRC-32 per record)
5. Resume normal operation
```

WAL compaction: after successful checkpoint, WAL is truncated to zero.

WAL entry format: `[timestamp, operation_type, target_file, data_hash, status]`

## Storage Layout

```
$UmbraVox_DATA/
|-- chain/
|   |-- blocks/
|   |   |-- epoch_003/
|   |   |   |-- slot_000001.bin
|   |   |   |-- slot_000002.bin
|   |-- checkpoints/
|   |   |-- checkpoint_epoch_002.bin
|   |   |-- checkpoint_epoch_003.bin
|-- state/
|   |-- accounts.db          -- pubkey -> {balance, nonce, stake_weight}
|   |-- indexes.db           -- tx_id -> block_ref, height -> block_ref
|   |-- chain_revision.db    -- current chain revision number + genesis hash history
|-- keys/
|   |-- identity.enc         -- Ed25519 keypair (AES-256-GCM encrypted)
|   |-- signal_identity.enc
|   |-- signal_prekeys.enc
|   |-- kyber_keypair.enc
|-- sessions/
|   |-- signal/              -- Per-peer Signal ratchet state
|   |-- pq/                  -- Per-peer PQ shared state
|-- config/
|   |-- node.toml
```

## Resource Estimates

| Resource | Estimate |
|----------|----------|
| CPU | 4 cores minimum, 8 recommended |
| RAM | 2 GB min, 4 GB recommended |
| Disk | ~80 GB steady-state (derivation: 3,927 slots × 20% occupancy = 785 blocks/epoch × 4,550,656 bytes (~4.44 MB) = ~3.57 GB chain data/epoch × 22 epochs = ~78.5 GB/cycle + state DB + indexes + WAL headroom) |
| Bandwidth | ~400 KB/s sustained (minimum); peaks to ~5 MB/s during sync |

## Memory Limits and Backpressure

Bounded TBQueue capacities:

```
Peer inbound:   1,000 messages
Peer outbound:  1,000 messages
Consensus:        500 blocks
Dandelion stem: 2,000 transactions
Mempool:       50,000 transactions (~50 MB; sufficient for ~4,444 per 55s block interval)
```

Backpressure strategy:

- Dandelion stem full -> REJECT with STEM_FULL status (sender retries via alternate relay peer; preserves privacy by avoiding silent drops)
- Peer queues full -> drop oldest entry
- Mempool full -> reject new entry (sender gets MEMPOOL_FULL error)
- Log all drops/rejections for monitoring

Memory budget (target):

```
Peer connections:   ~5 MB (50 peers x 100 KB buffer each)
Mempool:          ~50 MB (50K transactions × 1 KB average; sufficient for ~4,444 per block)
Chain state:     ~500 MB (ledger + indexes + compact block reconstruction cache)
Signal sessions: ~150 MB (50 peers x ~3 MB state each)
GHC runtime:      ~50 MB (heap, stack, closures)
Total target:    ~755 MB (fits within 2 GB minimum)
```

## Clock Synchronization

```
Slot clock = floor(unix_timestamp_ms / 11000)
```

Sources (priority order):

```
1. System NTP (+-50ms if available)
2. Peer median (median of last 10 block timestamps)
```

Tolerance: +-1 second

Reject blocks: timestamp > +-11s from expected slot time

## Chat API (JSON-RPC over WebSocket)

```
chat.send         -- Send encrypted message
chat.subscribe    -- Subscribe to incoming messages
chat.initSession  -- Establish Signal session with peer
chat.contacts     -- List contacts
chat.history      -- Local message history
wallet.balance    -- Check token balance
node.status       -- Node sync status, peer count, etc.
faucet.request    -- New user requests onboarding grant (requires PoW proof)
faucet.status     -- Check faucet availability and current grant amount
faucet.configure  -- Operator sets grant amount, rate limits, terms (admin only)
```

Validators can optionally operate as onboarding faucets, distributing tokens
from their own wallet to new users. The referral is recorded on-chain via the
`referrer_validator` field in the onboarding transaction. See doc/06 for the
economic incentive model.

## API Authentication

```
API key derived from user passphrase:
  Argon2id(passphrase, salt=node_id, t=3, m=256MB, p=1) → api_key
Stored as Argon2id hash only (never plaintext).

Request authentication:
  HMAC-SHA256(api_key, request_body || timestamp)
  Replay prevention: reject requests with timestamp >30s old.

All JSON-RPC requests require: Authorization: Bearer <hmac_token>
WebSocket upgrade requires same header.
Alternative: Unix socket with filesystem permissions (mode 0600)
```

## Logging and Monitoring

Log levels: ERROR, WARN, INFO, DEBUG, TRACE

Default: INFO

Structured JSON logging to `$UmbraVox_DATA/logs/node.log`

Log rotation: 100 MB max, 10 files retained

Metrics (available via `node.metrics` RPC):

```
peer_count          -- current connected peers
mempool_size        -- pending transactions
chain_height        -- current block number
blocks_produced     -- this cycle
messages_sent       -- this cycle
messages_received   -- this cycle
gc_pause_ms         -- last GC pause duration
disk_usage_bytes    -- chain + state
circulating_supply  -- sum of all spendable balances (for early truncation monitoring)
cycle_burned_total  -- tokens burned this cycle (resets at boundary)
adaptive_burn_rate  -- current cycle's burn rate parameter
cycle_progress_pct  -- percentage of target cycle duration elapsed
early_trunc_risk    -- circulating_supply / (threshold * INITIAL_SUPPLY)
```

## GHC RTS Configuration

Recommended flags:

```
+RTS -N4 -H256m -A32m -qg -RTS
```

```
-N4:    Use 4 OS threads (match recommended 4 cores)
-H256m: Initial heap size 256 MB
-A32m:  Allocation area 32 MB (reduces minor GC frequency)
-qg:    Parallel GC (reduces pause times)
```

## Boot Sequence

```
1.  Load config (node.toml)
2.  Decrypt key material (prompt for passphrase)
3.  Check WAL for incomplete operations -> replay/rollback
4.  Load state DB + indexes into memory
5.  Load chain tip from block storage
6.  Load peer table (anchor connections from prior session)
7.  Start TCP listener
8.  Connect to bootstrap/anchor peers
9.  Sync chain (download headers first, validate VRF proofs, then download blocks in parallel)
10. Start slot clock (begins once headers synced to within 1 epoch of tip; block download continues in background)
11. Start consensus engine (begin evaluating VRF for each slot)
12. Start WebSocket API listener
13. Ready for operation
```

## Upgrade Strategy

Soft upgrades (backwards compatible):

- New message types, new RPC endpoints
- Nodes ignore unknown message types
- No consensus impact

Hard upgrades (consensus-breaking):

- Announced 5 cycles (55 days) in advance via CONTROL message
- Activation at specific epoch boundary
- Old nodes that don't upgrade are forked off
- Binary compatibility: new node can sync old chain
