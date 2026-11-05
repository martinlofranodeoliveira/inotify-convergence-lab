# Development 0.1.0 contract

## Ownership and execution model

This contract describes a Linux-only C17 laboratory, not an arbitrary directory indexer. `icl_create` takes no path. It allocates a private mode-0700 parent with `mkdtemp` under `/tmp`, creates `root` and `quarantine` beneath it, and holds no-follow directory descriptors. Only these generated objects may be mutated or cleaned up. There is no host discovery, process spawning, network access, telemetry or persistent database.

All API calls for an instance must be serialized on one thread. Only the fixed companion writer functions may mutate its namespace. An oracle descriptor is for trusted, read-only testing; it is not a sandbox capability against malicious same-UID code. External writers, path replacement by external code, hostile `/tmp` infrastructure, filesystem crashes and network filesystems are outside the stable-snapshot contract.

Except for create/destroy and null arguments, errors belong to the instance. `icl_last_error` returns an owned borrowed record: result, optional native errno (zero for contract/EVP failures), and a fixed operation label, never arbitrary filenames or file contents. Later failures or successful reconciliation may replace it. Do not interpret an old error record as the result of a later call. Check each returned result.

`icl_create` sets `*out = NULL` on failure and optionally copies an error. `icl_destroy` invalidates the instance and all borrowed pointers even on cleanup failure; it reports the first cleanup errno through its optional copied record. Cleanup is descriptor-relative, bounded and no-follow. A failed cleanup can leave owned fixture objects; it does not scan elsewhere or follow a symlink. Callers must close all oracle duplicates before destroy. No fork/concurrent lifetime sharing is supported.

## Namespace and resource limits

The following limits apply jointly to the index root and sibling quarantine, excluding the two base directories:

| Resource | Limit |
| --- | ---: |
| Entries, including directories and deliberate invalid probes | 256 |
| Non-base directories | 64 |
| Path components, including a file name | 3 |
| Component length | 32 ASCII bytes |
| Regular file length | 4096 bytes |
| Sum of regular file contents | 1048576 bytes |
| Root watches, including the root itself | 65 |
| Cookies considered in one drain | 256 |
| Kernel read buffer | 8192 bytes |
| File hash read buffer | 1024 bytes |

Components start with `[A-Za-z0-9]` and continue with `[A-Za-z0-9._-]`. Empty components, absolute paths, leading dots, `.`/`..`, backslashes, non-ASCII, trailing slash and depth four are rejected. `ICL_PATH_CAP` is 99 including NUL. The final map sorts paths by unsigned ASCII bytes; this subset permits `strcmp` to implement that order.

Regular files require no-follow open, `fstat`, `st_nlink == 1`, bounded size/read, stable object identity and stable size/mtime/ctime across the read. Symlinks are rejected at metadata inspection, without opening their targets. Directories are opened with `O_DIRECTORY | O_NOFOLLOW`. Special files are rejected without reading them. Data file opens also use nonblocking mode defensively. The root is excluded from snapshot directory counts. Quarantine contents are validated and charged to the joint limits but are neither watched nor included in the snapshot.

Writer operations inventory both owned namespaces before mutations where additional capacity is needed. No write request exceeds 4096 bytes. Removal remains available to repair deliberately invalid fixtures. No recursive remove operation is exposed. Quarantine accepts one regular file at its fixed `exile` name; an occupied slot is not overwritten. Rename validates all affected descendant paths before its real `renameat` call.

`icl_set_limits` is allowed only when the writer is inactive. Event limit is 1–4096, work limit 1–8192, deadline 1–5000 ms. Defaults are 4096 events, 4096 work units and 2000 ms. A work unit is a scanner directory/entry visit, a file read attempt, a writer write attempt, or an inotify read attempt. Each inventory and each drain starts a new budget; this is not an aggregate CPU quota. Event limits count records inspected in a drain, not syscalls. A buffer read can discard unprocessed records when its budget is exceeded: that invalidates watch evidence and requires rebuilding.

Checked counters never wrap. Generation/epoch exhaustion fails closed. Logical limits are not hard disk, RSS, CPU-time, durability or syscall-latency guarantees. Monotonic deadlines are checked between operations; they bound loop waiting, not a blocked filesystem syscall. No kernel queue limits are changed.

## Serial writer protocol

1. `icl_writer_begin(lab, &token)` rejects nested writers, checks epoch overflow, increments the epoch, and changes status to **dirty before any filesystem side effect**. Even a no-op writer invalidates status.
2. Writer functions require the exact active token. Tokens strictly increase within one instance. Never transfer tokens between instances.
3. `icl_writer_end(lab, token)` rejects stale/inactive tokens and leaves dirty status. It closes the serial mutation interval; it is not a filesystem transaction, durability barrier or snapshot publication.
4. `icl_reconcile` is permitted only with the writer inactive. The coordinator must not begin another writer until it returns.

A stale end does not close the active writer. A failed operation need not roll back earlier or partial changes. End using the valid token and recover by reconciliation or bounded removal. Destroy may be used after any failure, including while a writer is active.

`writer_mkdir`, `writer_put`, `writer_rename`, `writer_remove` use validated root-relative paths. `put` replaces contents when append is zero and appends when it is one. It is not atomic replacement; use a separate owned temporary file plus `writer_rename` to exercise replacement. `writer_remove` uses no-follow metadata and unlinks a file-like entry or removes an empty directory. It can remove the deliberately invalid link/FIFO probes.

## Status, results and snapshot lifetime

Results:

- `ICL_OK`: the requested operation completed. Only successful **reconcile** publishes current data; writer success alone never does.
- `ICL_INVALID`: bad protocol/path/type/argument or an unexpected probe outcome.
- `ICL_DIRTY`: an event drain completed without proving current status, or evidence was deliberately discarded.
- `ICL_INCOMPLETE`: a work/event/watch/counter/deadline bound or incomplete evidence prevented completion.
- `ICL_NATIVE`: a native syscall, allocation or EVP operation failed; inspect the owned error record. EVP failures use native errno zero.

Snapshot status is separate: **invalid** before the first publication, **dirty** after writer begin/invalidation, **incomplete** after failed reconciliation or a bounded operation, and **current** only after successful reconciliation. Other invalid/native API failures conservatively mark dirty and questionable evidence for reset. Rejected null-instance calls return invalid without an instance record.

`icl_snapshot_get` returns a borrowed const pointer to the last verified data and copies the live status if requested. Before first success the data is zero with generation zero. It does not consume events. An unsuccessful reconcile never replaces any bytes of the verified snapshot. A later writer changes live status, not the verified data's epoch/generation. The pointer is valid until destroy; its contents are immutable until the next successful reconciliation. Copy the struct to retain an older publication beyond that point. Consumers must require live status current, not merely nonzero generation.

`icl_get_evidence` returns borrowed live counters, not snapshot data. They record completed cookie-pair evidence, instance generations, native watch failures, explicitly simulated overflows, observed `IN_Q_OVERFLOW` records and deliberate discarded drains separately. No successful receipt is produced by the CLI if a required assertion/reconcile fails.

## Inotify and reconciliation

Inotify only invalidates and supplies diagnostic evidence. It never directly updates the verified file map. Watches include create/delete/modify/attribute/close-write/move/self-removal evidence, not access events caused by hashing.

Cookies are associated only inside a single complete drain of one retained inotify-instance generation. Each cookie must have exactly one FROM and one TO on known watches. Duplicate sides, zero cookies, unmatched sides, self-moves/removals, `IN_IGNORED`, unknown descriptors and queue overflow invalidate the evidence. Matching counters are committed only if the entire drain's cookie/watch evidence remains unambiguous. Pairs never survive drain boundaries, which is deliberately more conservative than retaining unmatched cookies. A match is not a promise that every intermediate filesystem state was observed.

The implementation never removes individual watches and then trusts their numeric descriptors again. `IN_IGNORED` is treated as invalidation, including when queued after automatic watch removal. A questionable instance is closed and replaced on reconciliation. Every reconcile also proactively rebuilds a fresh instance, so no old cookie or descriptor can enter a new generation.

Publication requires all of:

1. Companion writer inactive throughout the call.
2. Old evidence drained when trustworthy; a new inotify instance established.
3. Complete descriptor-relative root enumeration, regular-file size/hash checks and watch installation for every discovered directory, including root.
4. Complete bounded quarantine validation.
5. Fresh-instance event drain through `EAGAIN`, with no relevant events or questionable watch evidence during the scan.
6. Checked snapshot generation increment and one final data assignment.

Any failure preserves the old data and marks the live status incomplete. Recovery begins with a fresh instance and full inventory. Events during the final scan cause incomplete rather than an automatic unbounded retry. The path-only Linux `inotify_add_watch` interface receives only generated private absolute paths, with `IN_ONLYDIR | IN_DONT_FOLLOW`; enumeration and mutations are descriptor-relative. No `/proc` path tricks are used. The closed-writer contract prevents ancestor replacement during watch installation.

`icl_consume_events` never publishes. `icl_discard_events` genuinely reads and drops queued evidence, invalidates status before reading and requires rebuilding even if no event was queued. `icl_simulate_overflow` increments only the simulated counter and requires rebuilding; it does not claim the kernel produced a marker. Actual `IN_Q_OVERFLOW` records increment only the observed counter.

## Closed diagnostics and CLI output

`icl_writer_probe` deliberately creates fixed synthetic `bad-link` (target `../quarantine`), `bad-hard` (hardlink to `a.txt`) or `bad-fifo` entries. These are negative-test fixtures, never valid indexed objects. Other probes call native `read` on the owned directory, or create/remove `watch-gone` and make a real `inotify_add_watch` call against that removed owned path. On Linux the expected native errors are `EISDIR` and `ENOENT`. No injected errno substitutes for these calls.

`icl_oracle_root_fd` returns an owned duplicate for independent, trusted read-only verification. Directory enumeration must open `.` again to get an independent directory offset rather than relying on `dup` offsets. Caller closes it and must not mutate through it.

CLI syntax: `icl-demo [--json]`. Exit 0 means all nine causal stages, negative checks, independent oracle checks and cleanup succeeded and output was flushed; exit 1 means runtime/assertion/output failure; exit 2 means usage error. JSON is one UTF-8 object followed by LF. Paths in it are restricted ASCII, so no arbitrary string escaping surface is exposed. Human output and JSON contain only fixed labels and verified generated metadata. No timing or universal exact event-count assertions are included.
