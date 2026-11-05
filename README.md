# Inotify Convergence Lab

Development version **0.1.0** — original software by [Lofrano Tecnologia](https://lofranotecnologia.com.br).

A Linux C17 library and closed, asserting fixture application exploring directory-index convergence. It uses real inotify, real renames, rename cookies, descriptor-relative enumeration and OpenSSL EVP SHA-256. It is **not a host scanner**. Every instance creates a new private tree and a sibling, unwatched quarantine under a private `/tmp/icl-XXXXXX` directory. No input selects an existing tree.

Repository: https://github.com/martinlofranodeoliveira/inotify-convergence-lab

[Português](README.pt-BR.md) · [Precise contract](docs/contract.md) · [Design](docs/design.md)

## Build, test, demonstrate

Requirements: Linux, GCC 14, Make, OpenSSL 3 development headers and libcrypto. Run tests as a non-root account. No network is used by the library, tests or demo. On an already provisioned development machine:

```sh
make
make test
make sanitize
make demo-assert
build/icl-demo --json
make package
make install PREFIX="$HOME/.local"
```

The source archive is `build/inotify-convergence-lab-0.1.0.tar.gz`. Installation writes the demo, static library and header to the chosen prefix; it does not register a service. A caller links `libicl.a` with `-lcrypto`.

For an isolated build using the supplied Dockerfile:

```sh
docker build --tag icl-dev .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --memory 1g --cpus 2 --user 1000:1000 icl-dev make test sanitize demo-assert package
```

Image construction requires package access. Test execution does not. The Dockerfile is a convenience build recipe, not a pinned offline image or distribution lockfile. Prepare and retain an independently verified offline image when exact package reproducibility is required. It mounts no host trees.

The selected environment reported for qualification was GCC 14.3.0 and OpenSSL 3.0.16 (`libssl-dev` package `3.0.16-1~deb12u1`) in a local `gcc:14-bookworm` image. The supplied qualification report covered EVP SHA-256 of `ab`, descriptor-relative create/rename/remove and real inotify create/read under UID 1000, no network and dropped capabilities. These are environment observations supplied with the project brief, not results of this project's test suite. No complete artifact digest is reproduced because none was supplied here. The build recipe may resolve different packages. No cross-kernel, latest-version, performance or production-readiness claim is made.

## Expected demo output

The demo exits nonzero on any failed assertion or cleanup/output error. On success its human-readable output is:

```text
Inotify Convergence Lab 0.1.0 (development)
initial: current files=2 directories=1 bytes=3
rename-append: current files=2 directories=1 bytes=5
replacement: current files=2 directories=1 bytes=4
directory-rename: current files=2 directories=1 bytes=4
quarantine: current files=1 directories=1 bytes=1
simulated-overflow-recovery: current files=2 directories=1 bytes=5 overflow=simulated
native-watch-recovery: current files=2 directories=1 bytes=5
symlink-recovery: current files=2 directories=1 bytes=5
event-budget-recovery: current files=2 directories=1 bytes=5
Native watch failure, symlink rejection and event-budget exhaustion: checked
Independent oracle and content assertions: passed
```

This is an expected example, not an execution claim. `--json` emits one JSON object containing `development_version`, `assertions`, nine `stages`, three `negative_checks`, and the two sorted `final_files` with size and SHA-256. Its final map is `d.txt` containing `z` and `renamed/c.txt` containing `1234`. It deliberately omits timing, random fixture names and coalescing-dependent event counts. The overflow stage always says **simulated**; it does not assert a kernel overflow occurred.

## Small library example

```c
#include "icl.h"

int example(void)
{
    icl *lab = NULL;
    icl_error error;
    uint64_t token;
    int result = 1;
    if (icl_create(&lab, &error) != ICL_OK) return 1;
    if (icl_writer_begin(lab, &token) == ICL_OK &&
        icl_writer_put(lab, token, "a.txt", "ab", 2, 0) == ICL_OK &&
        icl_writer_end(lab, token) == ICL_OK &&
        icl_reconcile(lab) == ICL_OK) {
        icl_state state;
        const icl_snapshot *s = icl_snapshot_get(lab, &state);
        result = !(state == ICL_STATE_CURRENT && s->files == 1 && s->bytes == 2);
    }
    if (icl_destroy(lab, &error) != ICL_OK) result = 1;
    return result;
}
```

`writer_begin` invalidates current status immediately, even if no mutation follows. A failed operation can have partial effects; end the valid writer epoch, then reconcile or remove the owned invalid fixture and reconcile. Snapshot data remains unchanged until a successful publication, but **its separate status can be dirty or incomplete**. Inspect both.

## Why reconcile?

Inotify is evidence of change, not a transaction journal. Events can coalesce; directory moves alter descendant paths; cookies can be unmatched; watch IDs can become questionable. This small implementation intentionally rebuilds the watch instance on every reconcile. A closed companion-writer epoch, complete enumeration/hash, complete watch coverage and event drain are all necessary to publish current data. Cookie matches are diagnostic evidence only, never instructions to rewrite the verified map.

Tests include independent descriptor-relative enumeration and one-shot hashing, fixed content expectations, real native open/read/rename/watch failures, discarded events, simulated overflow, stale epochs, invalid object types, work/event exhaustion, boundary namespaces, and retained old data with non-current status. ASan/UBSan findings fail the sanitizer target. Project test execution is not asserted by this documentation.

## Limits and exclusions

- Single-threaded serial coordinator only. Outside writers are excluded, including writes through an oracle descriptor. No stable-snapshot promise covers them.
- Across root and quarantine: at most 256 entries, 64 non-base directories, three path components, 4096 bytes/file, 1 MiB contents. Root itself is not a counted directory.
- Each component is 1–32 ASCII characters, begins with an ASCII letter/digit, and continues with letters, digits, `.`, `_`, `-`. Paths are relative. No symlinks, hardlinks or special files are indexed.
- No guaranteed intermediate-state detection, real kernel overflow generation, network-filesystem support, crash recovery, persistence, durability, filesystem transactions or broad standards compliance.
- Logical budgets are not disk/RSS guarantees. Deadlines are checked between bounded operations; they cannot interrupt a blocked kernel call. Failed bounded cleanup can leave the owned private fixture for manual inspection; it never broadens its search.

MIT, copyright 2026 Lofrano Tecnologia. For general contact use the [official homepage](https://lofranotecnologia.com.br). Security reports belong in [GitHub private vulnerability reporting](https://github.com/martinlofranodeoliveira/inotify-convergence-lab/security/advisories/new).
