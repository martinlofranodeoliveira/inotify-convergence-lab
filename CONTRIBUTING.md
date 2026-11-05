# Contributing

Author and maintainer organization: Lofrano Tecnologia.

Use synthetic fixtures only. Keep every filesystem mutation inside an instance's newly created root or sibling quarantine. Do not add host scanning, secrets, telemetry, arbitrary subprocesses or runtime model/API dependencies. Preserve the distinction between diagnostic inotify evidence, writer barriers and verified snapshots.

Before proposing a change, use Linux with GCC 14 and OpenSSL 3 development files, then run as a non-root account:

```sh
make test
make sanitize
make demo-assert
make package
```

The Dockerfile and CI demonstrate the isolated execution envelope. Dependency installation is a separate online preparation step; tests must run offline. If reporting environment evidence, include actual compiler/OpenSSL/package versions and complete artifact digests only when measured. Never substitute abbreviated or invented hashes. Do not infer cross-kernel behavior from one run.

Add regression tests for changed contracts and failure paths. Assert final content/path maps at fixed writer barriers, not universal event counts. Keep the independent oracle independent. Sanitizer findings, cleanup failures and incomplete evidence must fail checks rather than be suppressed. Update both READMEs and docs/contract.md when changing the public API or its bounds.

Use four spaces in C and tabs in Make recipes. Check all native and EVP results, bounded loops and integer arithmetic. Contributions must be original and MIT-compatible; no private client source or personal data.

General contact: https://lofranotecnologia.com.br

For vulnerabilities use the private reporting link in SECURITY.md rather than public issues. This repository provides no automated publishing or deployment workflow.
