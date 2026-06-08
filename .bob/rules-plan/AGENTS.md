# Project Architecture Rules (Non-Obvious Only)

**Monorepo with local replacements:** Vault is structured as a monorepo with main module, `./api`, and `./sdk` submodules - [`go.mod`](../../go.mod:15-23) uses `replace` directives requiring coordinated updates

**Test code isolation via build tags:** Production builds exclude test utilities using `BUILD_TAGS='testonly'` - test helpers in [`vault/testing.go`](../../vault/testing.go) are only available in test builds

**Generated code is source of truth:** Generated files from `go generate` and protobuf compilation ARE committed to git - `make prep` regenerates, but files are versioned

**Docker test architecture:** Tests using [`sdk/helper/testcluster/docker`](../../sdk/helper/testcluster/docker) require `VAULT_BINARY` env var - allows testing local binary changes in containerized environment

**Protobuf post-processing pipeline:** After protobuf generation, sed scripts transform generated code - see [`Makefile`](../../Makefile:245-246) for ID/URL/API capitalization fixes

**CGO conditional compilation:** CGO disabled by default (`CGO_ENABLED=0`) unless FoundationDB support enabled (`FDB_ENABLED=1`) - affects build tags and dependencies

**Platform-specific build tooling:** Makefile detects macOS vs Linux for `gsed`/`sed` usage - see [`Makefile`](../../Makefile:15-22) for platform detection

**Multi-tier timeout strategy:** Tests use tiered timeouts: 45m default, 60m extended, 120m integration - prevents hanging tests while allowing long-running scenarios

**UI build integration:** UI built with Ember/pnpm but tests run from project root - `cd ui && pnpm run test:oss` pattern required

**License header enforcement:** All files require IBM copyright and SPDX license identifier - BUSL-1.1 for main code, MPL-2.0 for SDK submodule