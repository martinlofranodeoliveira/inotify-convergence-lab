# Design: evidence, barriers, verified maps

## Three different objects

The fixture namespace, the retained inotify instance, and the last verified snapshot are deliberately distinct. A writer epoch invalidates current status immediately. The event queue may subsequently explain some changes, but cannot decide when those changes form a completed transaction. The snapshot becomes current only at a coordinator-controlled quiescent barrier after full verification.

The snapshot is a fixed-capacity value. Reconciliation builds a separate local inventory and commits once, after scan/watch/drain success. Errors cannot partially replace the last publication. Status is stored outside that value, preventing a retained old generation from accidentally advertising itself as current after writer begin.

## Conservative watch lifecycle

Maintaining a fully incremental rename index would require difficult assumptions about coalescing, overwritten targets, subtree moves, cookie lifetimes and watch-ID reuse. This version does not attempt that algorithm. Cookie matching is bounded diagnostic evidence, limited to a drain within one instance generation. It does not establish path identity in the verified map.

Every reconciliation closes the old instance and constructs a new one. Unknown descriptors and automatically removed watches, including queued `IN_IGNORED`, invalidate evidence rather than being assigned a guessed path. A removed-directory probe exercises the native watch error, not a mocked watch function. Its failure cannot publish a generation.

Fresh watches are installed before enumerating each directory, while the writer is inactive. Access events are not requested. Any relevant fresh-instance event during enumeration prevents publication. The root and all discovered directories must be watched. Quarantine is intentionally unwatched: moving a file there leaves an unmatched FROM in the retained instance, demonstrating why reconciliation is required.

## Filesystem confinement

The public creation API accepts no tree argument. Generated parent/root/quarantine directories are private to one instance. Normal operations walk validated components through descriptors using no-follow opens. Metadata is inspected without following symlinks, regular files require one link, and opened objects are checked against the inspected metadata. Actual file reads are bounded even if metadata lies or a file grows.

Linux provides no descriptor-relative `inotify_add_watchat`. The only generated-path operation inside the watch layer is `inotify_add_watch` against the private root and validated descendants. `IN_DONT_FOLLOW` protects the final component; private ownership plus the closed writer protects ancestors. This is not a claim of safety against an uncoordinated malicious same-UID writer. No `/proc` discovery, subprocesses or arbitrary host paths are needed.

Cleanup only visits these owned descriptors, never follows symlinks, stops at the same namespace/depth bound, checks errors and reports failures. It does not attempt broad recovery by scanning `/tmp`. Partial cleanup is safer than broadening authority.

## Bounded implementation

The opaque heap instance contains the last map and small watch/evidence tables. Inventories, hashing buffers and event buffers have fixed capacities. OpenSSL allocates its digest context; its allocation and digest operations are checked. Resource exhaustion fails closed. Repeated EINTR consumes work budget rather than looping forever. Close is attempted once, not retried after Linux may already have released the descriptor.

The namespace quota covers quarantined bytes too. Writer preflight scans make budget enforcement straightforward without maintaining a second mutable accounting ledger. This trades small bounded repeated work for simpler correctness. No performance benchmark is asserted.

## Verification strategy

The CLI is itself an asserting, deterministic offline demonstration. Tests share its scenario but add protocol and adversarial cases. The independent oracle has a separate traversal and uses OpenSSL 3's one-shot `EVP_Q_digest`, while the library uses incremental EVP context operations. Tests also verify literal contents and the known SHA-256 of `ab`, so agreement between two traversals is not the only check.

Causal assertions use completed writer epochs and final path/content maps, not exact event counts. The event-limit test creates distinct names so coalescing cannot eliminate all independent create evidence. Native open/rename failures use missing paths inside the owned root; the read failure uses an actual directory read. Hardlink, symlink and FIFO fixtures are rejected before indexing. Work-limit failures verify byte-for-byte retention of the old map with incomplete status.

The sanitizer target enables ASan, leak detection and UBSan with fail-on-finding settings. CI runs tests non-root, without network or capabilities, under 1 GiB and two CPUs. The Dockerfile installs build dependencies but is not an immutable dependency lock. Project execution results must be established by running the technical gates, not inferred from this design document.

## Official API references

- inotify semantics, coalescing, overflow, cookies and watch lifecycle: https://man7.org/linux/man-pages/man7/inotify.7.html
- Native rename behavior: https://man7.org/linux/man-pages/man2/rename.2.html
- Descriptor-relative and no-follow opening: https://man7.org/linux/man-pages/man2/openat.2.html
- OpenSSL incremental digest API: https://docs.openssl.org/master/man3/EVP_DigestInit/
- OpenSSL 3 one-shot API used by the oracle: https://docs.openssl.org/3.0/man3/EVP_DigestInit/

The implementation is original; these references document APIs rather than supplying copied application code. Scope is the precise documented subset, not broad POSIX or monitoring-standard compliance.
