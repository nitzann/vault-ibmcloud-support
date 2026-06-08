# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Build & Test Commands

**Single test execution:**
```bash
make test TEST=./vault TESTARGS="-run TestSpecificTest"
```

**Test with specific build tags:**
```bash
CGO_ENABLED=0 BUILD_TAGS='testonly' make test TEST=./vault
```

**Docker-based tests require VAULT_BINARY env var:**
```bash
GOOS=linux make dev
VAULT_BINARY=$(pwd)/bin/vault go test -run TestName ./path
```

**UI tests from root (not ui/ directory):**
```bash
cd ui && pnpm run test:oss
```

## Critical Non-Obvious Patterns

**Test helpers location:** Core test utilities in [`vault/testing.go`](vault/testing.go), NOT in a separate test package

**Build tags required:** Tests need `BUILD_TAGS='testonly'` - production builds exclude test-only code

**Docker test setup:** Use [`sdk/helper/testcluster/docker`](sdk/helper/testcluster/docker) with `VAULT_BINARY` env var for local binary testing

**Generated code:** Run `make prep` before building - generates required code from `go generate` directives (skip with `SKIP_GEN=1`)

**Protobuf changes:** After modifying `.proto` files, run `make proto` then commit generated `.pb.go` files

**CGO disabled by default:** `CGO_ENABLED=0` unless using FoundationDB (`FDB_ENABLED=1` sets `CGO_ENABLED=1`)

**Module structure:** Vault uses local `replace` directives in [`go.mod`](go.mod:15-23) for `./api`, `./sdk` submodules - changes require coordinated updates

**Test timeouts:** Default 45m (`TEST_TIMEOUT`), extended tests 60m, integration 120m

**Makefile sed handling:** Uses `gsed` on macOS, `sed` elsewhere - see [`Makefile`](Makefile:15-22) for platform detection

**License headers:** All files require `// Copyright IBM Corp. 2016, 2025` and `// SPDX-License-Identifier:` headers (BUSL-1.1 for main code, MPL-2.0 for SDK)