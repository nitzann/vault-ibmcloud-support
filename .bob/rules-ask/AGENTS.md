# Project Documentation Rules (Non-Obvious Only)

**Test helpers location:** Core test utilities in [`vault/testing.go`](../../vault/testing.go), NOT in a separate test package - this is counterintuitive for Go projects

**Build tags for test code:** Test-only code uses `BUILD_TAGS='testonly'` build tag - production builds exclude this via conditional compilation

**Docker testing pattern:** Tests using [`sdk/helper/testcluster/docker`](../../sdk/helper/testcluster/docker) require `VAULT_BINARY` env var pointing to local binary - not documented in test files themselves

**Generated code is committed:** Unlike many Go projects, generated files from `go generate` ARE committed to git - run `make prep` to regenerate

**Protobuf sed post-processing:** After `make proto`, sed scripts automatically modify generated `.pb.go` files - see [`Makefile`](../../Makefile:245-246) for transformations

**Local module replacements:** [`go.mod`](../../go.mod:15-23) uses `replace` directives for `./api` and `./sdk` submodules - changes require coordinated updates across all three modules

**Platform-specific tooling:** Makefile detects macOS and uses `gsed` instead of `sed` - see [`Makefile`](../../Makefile:15-22) for platform detection logic

**Test timeout defaults:** Tests default to 45m timeout, extended tests 60m, integration 120m - configured via `TEST_TIMEOUT` variable

**UI tests run from root:** UI tests must be run from project root with `cd ui && pnpm run test:oss`, not from within ui/ directory