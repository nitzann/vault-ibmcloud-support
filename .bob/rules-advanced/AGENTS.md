# Project Advanced Coding Rules (Non-Obvious Only)

**Test helpers in vault/testing.go:** Core test utilities are in [`vault/testing.go`](../../vault/testing.go), not a separate test package - import from `github.com/hashicorp/vault/vault` for test helpers

**Build tags mandatory for tests:** All test code MUST use `BUILD_TAGS='testonly'` - production builds exclude this code via build tags

**Docker tests require binary path:** When using [`sdk/helper/testcluster/docker`](../../sdk/helper/testcluster/docker), set `VAULT_BINARY` env var to local binary path before running tests

**Generated code workflow:** Run `make prep` before building to execute `go generate` - generated files ARE committed to git (skip with `SKIP_GEN=1` if you know you don't need it)

**Protobuf workflow:** After editing `.proto` files, run `make proto` to regenerate `.pb.go` files, then commit both - sed post-processing is applied automatically

**Module replace directives:** Local submodules (`./api`, `./sdk`) use `replace` in [`go.mod`](../../go.mod:15-23) - changes to these require coordinated updates across modules

**CGO disabled by default:** `CGO_ENABLED=0` unless FoundationDB is enabled (`FDB_ENABLED=1` automatically sets `CGO_ENABLED=1`)

**Platform-specific sed:** Makefile uses `gsed` on macOS, `sed` elsewhere - see [`Makefile`](../../Makefile:15-22) for detection logic

**License headers required:** Every file needs `// Copyright IBM Corp. 2016, 2025` and `// SPDX-License-Identifier:` (BUSL-1.1 for main, MPL-2.0 for SDK)

**Access to MCP and Browser tools available**