# IBM Cloud Auth Method — Architecture & Capability Reference

> **Branch context:** This document describes the `plan1` branch of `vault-ibmcloud-support`, which reflects the completed sub-tasks 1–4 of the AWS-alignment plan. Sub-tasks 5 (tests) and 6 (documentation cleanup) remain pending.

---

## Table of Contents

1. [What the IBM Cloud Auth Method Does](#1-what-the-ibmcloud-auth-method-does)
2. [How It Fits into the Vault Architecture](#2-how-it-fits-into-the-vault-architecture)
3. [Architecture Layers Diagram](#3-architecture-layers-diagram)
4. [Code Components and Their Responsibilities](#4-code-components-and-their-responsibilities)
5. [Authentication Flow (Code Flow Diagram)](#5-authentication-flow-code-flow-diagram)
6. [Root Credential Rotation Flow](#6-root-credential-rotation-flow)
7. [Comparison with the AWS Auth Method](#7-comparison-with-the-aws-auth-method)
8. [Key Design Decisions and Trade-offs](#8-key-design-decisions-and-trade-offs)

---

## 1. What the IBM Cloud Auth Method Does

The IBM Cloud auth method (`builtin/credential/ibmcloud`) allows workloads running on IBM Cloud — or users and services that possess IBM Cloud IAM credentials — to authenticate to HashiCorp Vault without embedding a static Vault token.

**Authentication contract (post-plan1):**
1. The caller exchanges their long-lived IBM Cloud credential (API key, trusted profile CR token, etc.) with **IBM IAM locally** on the client side.
2. The caller sends the resulting short-lived **IAM JWT** (≤ 60 min validity) plus a `role` name to the Vault login endpoint.
3. Vault verifies the JWT **offline** (RS256 signature via JWKS) and **online** (IBM IAM introspect), then checks the caller's identity against the role's binding constraints.
4. On success, Vault issues a Vault token scoped to the role's policies and TTLs.

The method supports two identity types, each mapped to a role type:

| Role type | Identity kind | Typical caller |
|---|---|---|
| `apikey` | IAM User or Service ID | Developers, CI/CD pipelines, service-to-service |
| `trusted_profile` | Compute resource identity | VPC VSIs, IKS pods, Code Engine jobs |

---

## 2. How It Fits into the Vault Architecture

HashiCorp Vault models all authentication backends as **credential plugins** that implement the `logical.Backend` interface. The IBM Cloud method is a built-in credential plugin — compiled into the Vault binary and available as `auth/ibmcloud`.

```
┌─────────────────────────────────────────────────────────────────┐
│                         Vault Binary                            │
│                                                                 │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │  Vault Core  │   │ Secret Engines│   │  Auth Methods    │   │
│  │  (router,    │   │  (kv, pki,   │   │  (token, aws,    │   │
│  │   policies,  │   │   database…) │   │   ibmcloud, …)   │   │
│  │   storage)   │   └──────────────┘   └──────────────────┘   │
│  └──────┬───────┘                               │               │
│         │  logical.Backend interface            │               │
│         └───────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

**Registration chain:**

| Location | Role |
|---|---|
| [`helper/builtinplugins/registry_full.go`](helper/builtinplugins/registry_full.go) | Maps `"ibmcloud"` → `Factory` function |
| [`command/server/commands_full.go`](command/server/commands_full.go) | Wires the factory into the server startup |
| [`command/client/agent/config/config.go`](command/client/agent/config/config.go) | Registers `"ibmcloud"` in `autoAuthMethodKeys` so Agent configs parse |
| [`command/client/proxy/config/config.go`](command/client/proxy/config/config.go) | Same for Vault Proxy |
| [`agentproxyshared/helpers.go`](agentproxyshared/helpers.go) | CLI-handler registration for `vault login -method=ibmcloud` |

The `Factory` function in [`builtin/credential/ibmcloud/backend.go`](builtin/credential/ibmcloud/backend.go) creates the backend and returns a `logical.Backend`. From that point, Vault Core routes all HTTP requests under `auth/ibmcloud/...` to this backend.

---

## 3. Architecture Layers Diagram

```
╔══════════════════════════════════════════════════════════════════╗
║  Caller (human / machine)                                        ║
║                                                                  ║
║  ┌──────────────────┐     ┌──────────────────────────────────┐  ║
║  │  vault login CLI │     │  Vault Agent / Proxy auto-auth   │  ║
║  │  (-method=       │     │  (method "ibmcloud")              │  ║
║  │   ibmcloud)      │     │                                  │  ║
║  │  cli.go          │     │  command/client/auth/ibmcloud/   │  ║
║  └────────┬─────────┘     └──────────────┬───────────────────┘  ║
║           │ 1. Exchange credential        │ 1. Exchange credential║
║           │    with IBM IAM locally       │    with IBM IAM       ║
╠═══════════╪══════════════╗               │                       ║
║  IBM IAM  │              ║               │                       ║
║           ▼              ║               ▼                       ║
║   /identity/token        ║        /identity/token               ║
║    → IAM JWT             ║         → IAM JWT                    ║
╚═══════════╪══════════════╝               │                       ║
            │ 2. POST /auth/ibmcloud/login  │                       ║
            │    {role, token=<JWT>}        │                       ║
            └─────────────────────────────►│                       ║
╔════════════════════════════════════════╗ │                       ║
║  Vault Server                          ║ │                       ║
║                                        ║ │                       ║
║  ┌─────────────────────────────────┐   ║ │                       ║
║  │  path_login.go                  │◄──╝ │                       ║
║  │  pathLoginUpdate()              │     │                       ║
║  │                                 │     │                       ║
║  │  3a. Offline verify (jwks.go)   │     │                       ║
║  │    - fetch JWKS (on unknown kid)│     │                       ║
║  │    - check RS256 sig            │     │                       ║
║  │    - check exp/nbf/issuer       │     │                       ║
║  │                                 │     │                       ║
║  │  3b. Online introspect          │     │                       ║
║  │    - confirm active=true        │     │                       ║
║  │    - extract identity claims    │     │                       ║
║  │                                 │     │                       ║
║  │  3c. Role binding checks        │     │                       ║
║  │    - account membership         │     │                       ║
║  │    - access group membership    │     │                       ║
║  │    - bound_* constraints        │     │                       ║
║  │    - CIDR check                 │     │                       ║
║  │                                 │     │                       ║
║  │  4. Issue Vault token           │     │                       ║
║  └─────────────────────────────────┘     │                       ║
║          │            ▲                  │                       ║
║          │ storage    │ IAM API calls    │                       ║
║          ▼            │                  │                       ║
║  ┌──────────────┐  ┌──────────────────┐ │                       ║
║  │  path_role.go│  │  client.go       │ │                       ║
║  │  path_config │  │  jwks.go         │ │                       ║
║  │  .go         │  │  (IAM HTTP calls)│ │                       ║
║  └──────────────┘  └──────────────────┘ │                       ║
╚════════════════════════════════════════╝ │                       ║
                                           │                       ║
╔══════════════════════════════════╗       │                       ║
║  IBM Cloud IAM (external)        ║       │                       ║
║                                  ║       │                       ║
║  /identity/keys  (JWKS)          ║       │                       ║
║  /identity/introspect            ║       │                       ║
║  /identity/v1/apikeys            ║       │                       ║
║  /identity/v1/serviceids         ║       │                       ║
║  /identity/.well-known/openid-   ║       │                       ║
║    configuration                 ║       │                       ║
╚══════════════════════════════════╝       │                       ║
```

**Vault storage layer:**

```
Vault Storage (encrypted)
├── auth/ibmcloud/
│   ├── config          ← SealWrapped: IAM endpoint, API key, service ID, account ID, rotation schedule
│   └── role/<name>     ← Role definitions: type, bound_* fields, token policies/TTL
```

---

## 4. Code Components and Their Responsibilities

### 4.1 [`backend.go`](builtin/credential/ibmcloud/backend.go) — Backend wiring

| Symbol | Responsibility |
|---|---|
| `Factory()` | Entry point. Creates the backend, calls `Setup`, returns `logical.Backend`. |
| `backend` struct | Embeds `*framework.Backend`. Owns the IAM client cache, admin token cache, and mutexes. |
| `getIAMClient()` | Double-check-locked cache for the IBM IAM HTTP client. Recreated when config changes or rotation clears it. |
| `getAdminToken()` | Cached IAM bearer token for Vault's own admin API calls. Refreshed 5 minutes before expiry. |
| `invalidate()` | Called by Vault Core when a storage key changes (replication). Clears the IAM client and admin token caches. |
| `cleanup()` | Called on shutdown. Clears caches. |
| `RotateCredential` callback | Registered on `framework.Backend`. Called by Vault Core on the automated rotation schedule. Delegates to `rotateRoot()`. |
| `pathLoginRenew()` | Handles token renewal: re-checks CIDR and role TTL, does not re-verify JWT. |

**Paths registered:**

| Path | Auth required | Handler file |
|---|---|---|
| `login` | No (unauthenticated) | `path_login.go` |
| `role/:name` | Yes | `path_role.go` |
| `role/` (list) | Yes | `path_role.go` |
| `roles/` (list) | Yes | `path_role.go` |
| `config` | Yes | `path_config.go` |
| `config/rotate-root` | Yes | `path_config_rotate_root.go` |

---

### 4.2 [`path_config.go`](builtin/credential/ibmcloud/path_config.go) — Configuration

Manages the single `config` storage key under `SealWrapStorage` (API key encrypted at rest).

**Config fields:**

| Field | Type | Notes |
|---|---|---|
| `iam_endpoint` | string | Default: `https://iam.cloud.ibm.com` |
| `iam_client_timeout` | int (seconds) | Default: 30 |
| `api_key` | string (sensitive) | Admin API key. Requires `service_id` + `account_id`. |
| `service_id` | string | Service ID that owns the admin API key. |
| `account_id` | string | IBM Cloud account. If set, callers' account membership is verified. |
| `rotation_schedule` | string | CRON expression for automated rotation (new on plan1). |
| `rotation_period` | duration | Interval-based alternative to a CRON schedule. |
| `rotation_window` | duration | Acceptable skew window for a scheduled rotation. |
| `disable_automated_rotation` | bool | Disables scheduled rotation without clearing other params. |

**Validation rules:**
- `api_key` requires `service_id` and `account_id` to also be set.
- `account_id` requires `api_key` to be set.
- Automated rotation fields are processed by `automatedrotationutil.ParseAutomatedRotationFields()`.

**On write:** If rotation params changed, `automatedrotationutil.HandleRotationJob()` registers or deregisters the scheduled job with Vault Core's rotation scheduler.

---

### 4.3 [`path_config_rotate_root.go`](builtin/credential/ibmcloud/path_config_rotate_root.go) — Root credential rotation

Provides both the manual `POST config/rotate-root` endpoint and the `rotateRoot()` helper shared with the automated callback.

**`rotateRoot()` steps:**

1. Load config; validate `api_key` and `service_id` are present.
2. Authenticate with the current API key → get an IAM bearer token.
3. Create a new API key via `CreateAPIKey()`.
4. Retrieve the old API key's ID via `GetAPIKeyDetails()` (needed for cleanup).
5. **Persist the new API key first** (fail-safe: if storage write fails, delete the new key immediately).
6. Authenticate with the new API key to get a fresh token.
7. Delete the old API key.
8. Clear the cached IAM client (`b.iamClient = nil`).
9. Return a response with `service_id`, `rotated_at`, `new_key_id`.

If step 6 or 7 fails, the new key is already saved so Vault remains operational; warnings are returned rather than an error.

---

### 4.4 [`path_login.go`](builtin/credential/ibmcloud/path_login.go) — Authentication endpoint

Accepts `{ role, token }` (unauthenticated path).

**Handler (`pathLoginUpdate`) sequence:**

1. Resolve the role from storage.
2. Obtain the cached IAM client.
3. Verify the token offline and online (`client.VerifyToken()`).
4. Derive the identity type from the introspect `sub_type` claim:
   - `User` or `ServiceId` → maps to role type `apikey`
   - `Profile` → maps to role type `trusted_profile`
5. Confirm the derived type matches the role's configured type.
6. Run account/access-group verification (uses admin token for user/service ID lookup).
7. Validate the identity against the role's `bound_*` fields.
8. Optionally check CIDR bounds.
9. Return `auth.Auth` with alias `iam_id`, metadata, and role token params.

**Token renewal** (`pathLoginRenew`): re-applies token bounds and CIDR check; does not re-verify the IBM JWT (it would have long expired).

---

### 4.5 [`path_role.go`](builtin/credential/ibmcloud/path_role.go) — Role management

Roles are the primary policy binding unit.

**Role struct fields:**

| Field | Applies to | Description |
|---|---|---|
| `type` | both | `"apikey"` or `"trusted_profile"` |
| `bound_account_id` | `apikey` | Required: only tokens from this account |
| `bound_service_ids` | `apikey` | Optional: allowlist of Service ID IAM IDs |
| `bound_user_ids` | `apikey` | Optional: allowlist of user IAM IDs |
| `bound_access_group_ids` | `apikey` | Optional: caller must be member of all listed groups |
| `bound_trusted_profile_id` | `trusted_profile` | Required: specific profile ID |
| `bound_compute_resource_crn` | `trusted_profile` | Optional: CRN patterns (glob wildcards supported) |
| `bound_compute_resource_type` | `trusted_profile` | Optional: `vsi`, `iks`, `ce`, etc. |
| `token_*` (TTL, policies, CIDR) | both | Standard Vault `tokenutil.TokenParams` |

---

### 4.6 [`client.go`](builtin/credential/ibmcloud/client.go) — IBM IAM HTTP client

Wraps all calls to IBM Cloud IAM REST APIs.

| Method | Endpoint | Purpose |
|---|---|---|
| `AuthenticateWithAPIKey()` | `POST /identity/token` | Exchange API key for bearer token |
| `VerifyToken()` | JWKS + introspect | Offline + online JWT verification |
| `ValidateToken()` | `POST /identity/introspect` | Online-only token check |
| `CreateAPIKey()` | `POST /identity/v1/apikeys` | Create a new API key (rotation) |
| `DeleteAPIKey()` | `DELETE /identity/v1/apikeys/{id}` | Delete an API key (rotation cleanup) |
| `GetAPIKeyDetails()` | `GET /identity/v1/apikeys` | Look up API key ID by value |
| `GetServiceID()` | `GET /identity/v1/serviceids/{id}` | Verify service ID account membership |
| `CheckUserAccount()` | IAM user management API | Verify user account membership |
| `CheckAccessGroupMembership()` | Access Groups API | Verify group memberships |

---

### 4.7 [`jwks.go`](builtin/credential/ibmcloud/jwks.go) — Offline JWT verification

Implements a lazy-refresh JWKS verifier.

**Key behavior:**
- Keys fetched from `<iam_endpoint>/identity/keys` on first use.
- Issuer discovered from `<iam_endpoint>/identity/.well-known/openid-configuration`.
- Keys re-fetched **only when** a JWT presents an unknown `kid` (with a 30-second guard against refetch storms).
- No periodic background refresh.
- Verifies: RS256 algorithm, signature, `exp`, `nbf` (with 10-second clock skew), and issuer.

---

### 4.8 [`cli.go`](builtin/credential/ibmcloud/cli.go) and [`command/client/auth/ibmcloud/`](command/client/auth/ibmcloud/) — Client-side credential exchange

**Design principle (post-plan1):** Vault only ever receives a JWT. The client-side code is responsible for exchanging API keys or CR tokens with IBM IAM before calling Vault.

| Component | Purpose |
|---|---|
| `cli.go CLIHandler` | `vault login -method=ibmcloud`. Accepts `token`, `apikey` (or `IBMCLOUD_API_KEY`), or a trusted-profile CR-token flow. Calls IBM IAM to produce a JWT, then writes `{role, token}` to Vault. |
| `command/client/auth/ibmcloud/ibmcloud.go` | Vault Agent auto-auth method. Same exchange logic, same output contract. |

---

## 5. Authentication Flow (Code Flow Diagram)

### 5.1 API Key / User authentication (role type `apikey`)

```
Caller                     Vault Server              IBM Cloud IAM
──────                     ────────────              ─────────────
  │                             │                         │
  │  POST /identity/token       │                         │
  │  {grant_type=urn:apikey,    │                         │
  │   apikey=<key>}             │                         │
  │────────────────────────────────────────────────────►  │
  │◄────────────────────────────────────────────────────  │
  │  {access_token: <JWT>}      │                         │
  │                             │                         │
  │  POST /auth/ibmcloud/login  │                         │
  │  {role:"my-role",           │                         │
  │   token:<JWT>}              │                         │
  │──────────────────►          │                         │
  │                   │         │                         │
  │           path_login.go     │                         │
  │           pathLoginUpdate() │                         │
  │                   │         │                         │
  │                   │  Load role from storage           │
  │                   │─────────────────►                 │
  │                   │◄─────────────────                 │
  │                   │  ibmCloudRole{type:"apikey", ...} │
  │                   │                         │         │
  │                   │  jwks.go: verify RS256 sig        │
  │                   │  check exp/nbf/issuer             │
  │                   │  (refetch JWKS if unknown kid)    │
  │                   │─────────────────────────────────► │
  │                   │◄───────────────────────────────── │
  │                   │  /identity/keys (JWKS)            │
  │                   │                         │         │
  │                   │  client.go: POST /identity/introspect
  │                   │─────────────────────────────────► │
  │                   │◄───────────────────────────────── │
  │                   │  {active:true, sub_type:"User",   │
  │                   │   account_id:..., iam_id:...}     │
  │                   │                         │         │
  │                   │  sub_type "User" → apikey role    │
  │                   │  Matches role.Type? ✓             │
  │                   │                         │         │
  │                   │  account_id check (if config.AccountID set):
  │                   │  getAdminToken() → call IAM       │
  │                   │─────────────────────────────────► │
  │                   │◄───────────────────────────────── │
  │                   │  CheckUserAccount() ✓             │
  │                   │                         │         │
  │                   │  bound_access_group_ids check     │
  │                   │─────────────────────────────────► │
  │                   │◄───────────────────────────────── │
  │                   │  CheckAccessGroupMembership() ✓   │
  │                   │                         │         │
  │                   │  matchesAPIKeyIdentity() ✓        │
  │                   │  CIDR check ✓                     │
  │                   │                         │         │
  │◄──────────────────│                         │         │
  │  {client_token: <Vault token>,              │         │
  │   policies: [...], ttl: ...}                │         │
```

### 5.2 Trusted Profile (compute) authentication (role type `trusted_profile`)

```
VPC VSI / IKS pod          Vault Server              IBM Cloud IAM
─────────────────          ────────────              ─────────────
  │                             │                         │
  │  PUT /identity/v1/token     │                         │
  │  (VPC metadata service)     │                         │
  │──────────────────────────────────────────────────►    │
  │◄──────────────────────────────────────────────────    │
  │  compute resource identity token                      │
  │                             │                         │
  │  POST /identity/v1/iam_tokens                         │
  │  Authorization: Bearer <cr-token>                     │
  │  {trusted_profile: {id: <profile-id>}}  (optional)    │
  │──────────────────────────────────────────────────►    │
  │◄──────────────────────────────────────────────────    │
  │  {iam_token: <JWT with sub_type="Profile">}           │
  │                             │                         │
  │  POST /auth/ibmcloud/login  │                         │
  │  {role:"compute-role",      │                         │
  │   token:<JWT>}              │                         │
  │──────────────────►          │                         │
  │                   │         │                         │
  │           path_login.go     │                         │
  │           pathLoginUpdate() │                         │
  │                   │  ... (same offline + introspect) ...
  │                   │                         │         │
  │                   │  sub_type "Profile" → trusted_profile role
  │                   │  Matches role.Type? ✓             │
  │                   │                         │         │
  │                   │  account_id check:                │
  │                   │  introspect account_id == config.AccountID ✓
  │                   │  (no admin API call needed for trusted profiles)
  │                   │                         │         │
  │                   │  matchesTrustedProfileIdentity()  │
  │                   │  - bound_trusted_profile_id ✓     │
  │                   │  - CRN pattern match ✓            │
  │                   │  - resource type ✓                │
  │                   │                         │         │
  │◄──────────────────│                         │         │
  │  {client_token: <Vault token>, ...}         │         │
```

---

## 6. Root Credential Rotation Flow

Both the manual (`POST config/rotate-root`) and automated (scheduled via `rotation_schedule`) paths use the same `rotateRoot()` function.

```
Trigger: manual POST or Vault Core scheduler
           │
           ▼
    b.configMutex.Lock()
    rotateRoot(ctx, req)
           │
           ▼
    1. Load config (must have api_key + service_id)
           │
           ▼
    2. AuthenticateWithAPIKey(current api_key) → old token
           │
           ▼
    3. CreateAPIKey(old token, service_id) → {new_key_id, new_api_key}
           │
           ▼
    4. GetAPIKeyDetails(old token, current api_key) → old_key_id
           │
           ▼
    5. Storage.Put(new api_key)   ← persisted BEFORE old key is deleted
       If Put fails: DeleteAPIKey(new_key_id) and return error
           │
           ▼
    6. AuthenticateWithAPIKey(new api_key) → new token
       If fails: return response with warning
           │                (new key is saved; Vault still works)
           ▼
    7. DeleteAPIKey(new token, old_key_id)
       If fails: return response with warning
           │
           ▼
    8. b.iamClient = nil   ← forces recreation with new key
           │
           ▼
    9. Return {service_id, rotated_at, new_key_id}
```

**Automated rotation wiring (plan1):**

```
framework.Backend.RotateCredential = func(ctx, req) error {
    b.configMutex.Lock()
    defer b.configMutex.Unlock()
    _, err := b.rotateRoot(ctx, req)
    return err
}
```

`automatedrotationutil.HandleRotationJob()` is called in `pathConfigWrite()` whenever rotation params change, registering or deregistering the scheduled job with Vault Core's rotation scheduler.

---

## 7. Comparison with the AWS Auth Method

### 7.1 Feature matrix

| Capability | IBM Cloud (`ibmcloud`) | AWS (`aws`) |
|---|---|---|
| **Auth types** | `apikey` (user/service ID), `trusted_profile` (compute) | `ec2` (PKCS7 instance doc), `iam` (SigV4 GetCallerIdentity) |
| **Token/credential format received by Vault** | RS256 JWT (bearer, ≤ 60 min) | EC2: PKCS7-signed XML; IAM: pre-signed STS request |
| **Replay protection** | Relies on JWT expiry + account/role binding | EC2: nonce + identity access list; IAM: SigV4 non-replayable by design |
| **Offline credential check** | JWKS signature verification | EC2: PKCS7 cert; IAM: SigV4 signature |
| **Online credential check** | IAM introspect (every login) | EC2: none after PKCS7; IAM: STS GetCallerIdentity |
| **Root credential type** | IBM IAM API key | AWS access key + secret key |
| **Root credential rotation** | `config/rotate-root` (manual + automated) | `config/rotate-root` (manual + automated) |
| **Automated rotation** | `rotation_schedule / period / window` via `automatedrotationutil` | Same |
| **Config paths** | `config`, `config/rotate-root` | `config/client`, `config/certificate`, `config/identity`, `config/sts`, `config/rotate-root`, `config/tidy/*` |
| **Role binding: identity** | `bound_account_id`, `bound_service_ids`, `bound_user_ids` | `bound_iam_principal_arn`, `bound_iam_role_arn` |
| **Role binding: compute** | `bound_trusted_profile_id`, `bound_compute_resource_crn`, `bound_compute_resource_type` | `bound_ami_id`, `bound_ec2_instance_id`, `bound_region`, `bound_subnet_id`, `bound_vpc_id` |
| **Access control groups** | `bound_access_group_ids` (IBM Access Groups) | No direct equivalent |
| **Workload identity federation** | Not supported | `role_arn` + `identity_token_*` |
| **Tidy / maintenance** | None (stateless; no identity access list) | Periodic tidy of deny list + identity access list |
| **Caching** | IAM HTTP client, admin token, JWKS keys | EC2/IAM AWS SDK clients, ARN→ID map (TTL cache), role cache |
| **Audience claim validation** | No dedicated audience claim; account ID + role binding is the guard | IAM: validates `sts:GetCallerIdentity`; EC2: PKCS7 cert ties identity to AWS |
| **Client-side exchange** | Client exchanges credential with IBM IAM; sends JWT to Vault | Client pre-signs STS request; sends signed headers to Vault |
| **CLI helper** | `cli.go` + `command/client/auth/ibmcloud` | `cli.go` + `command/client/auth/aws` + `internal/awsutil/v2` |

### 7.2 Structural differences

**AWS has two orthogonal auth methods in one plugin:**
```
aws plugin
├── ec2 method  ← hardware-anchored identity (PKCS7 + instance doc)
└── iam method  ← cryptographically non-replayable (SigV4)
```

**IBM Cloud has two orthogonal identity types, both using JWT:**
```
ibmcloud plugin
├── apikey type    ← user or service ID (long-lived key exchanged for JWT)
└── trusted_profile type  ← compute resource identity (metadata service → IAM → JWT)
```

**AWS IAM is cryptographically non-replayable** — the SigV4 signature is a unique single-use proof tied to the Vault server's IAM server ID header. IBM Cloud JWT is a short-lived bearer token: it can be replayed within its validity window. The IBM Cloud plugin mitigates this with account ID + role binding checks, but the window is a known trade-off documented in the alignment plan.

**AWS has richer config surface** because EC2 requires certificate management, STS regional endpoints, and cross-account role assumption. IBM Cloud IAM is a single global endpoint with no regional STS equivalent.

### 7.3 Code pattern alignment (what plan1 aligned)

| Pattern | AWS | IBM Cloud (plan1) |
|---|---|---|
| `ForwardPerformanceSecondary` on config write | ✓ | ✓ (added) |
| `ForwardPerformanceStandby` on config write | ✓ | ✓ (added) |
| `Summary` + `Responses` on config operations | ✓ | ✓ (added) |
| Agent/Proxy `autoAuthMethodKeys` registration | ✓ | ✓ (added) |
| Client-side credential exchange | ✓ | ✓ (added) |
| Automated rotation via `automatedrotationutil` | ✓ | ✓ (added) |
| Shared `rotateRoot()` helper for manual + automated | ✓ | ✓ (added) |
| `RotateCredential` callback on `framework.Backend` | ✓ | ✓ (added) |

---

## 8. Key Design Decisions and Trade-offs

### 8.1 Token-only login contract
Vault never sees a raw API key or CR token. Clients exchange credentials locally and send only the resulting JWT. This isolates Vault from credential exposure and matches the AWS pattern (clients pre-sign STS requests locally).

### 8.2 JWT is a bearer token, not a proof-of-possession
IBM IAM tokens are RS256-signed JWTs valid for approximately 60 minutes. Unlike AWS SigV4, they are replayable within their validity window. Mitigations: short TTL, account ID binding, role binding. This trade-off is acknowledged and documented; a Vault-specific audience mechanism does not exist in IBM IAM.

### 8.3 Minimal JWKS refresh strategy
Keys are only re-fetched when a JWT presents an unknown `kid`. There is no periodic background refresh. This is intentional: IBM Cloud IAM key rotation is slow, and on-demand refresh with a storm guard is sufficient. The guard prevents thundering herd on a new key rollout.

### 8.4 Role type derived from token, not from login request
The role type (`apikey` vs `trusted_profile`) is derived from the `sub_type` claim in the introspect response, not from a field the caller supplies. This prevents a caller with a `User` token from claiming they are a compute workload.

### 8.5 Admin credentials required for user/service ID account verification
For `apikey`-type roles, Vault needs admin IAM credentials to verify that a user or service ID belongs to the configured account. The admin token is cached and refreshed 5 minutes before expiry to avoid IAM rate limits. Trusted profile verification uses only the introspect response's `account_id` claim (no admin call needed).

### 8.6 No workload identity federation
AWS supports `role_arn` + `identity_token_*` for cross-cloud workload federation. No IBM Cloud equivalent was identified during research. This is explicitly listed as a non-goal.

### 8.7 No periodic tidy
AWS maintains identity access lists and deny lists that require periodic cleanup. IBM Cloud's stateless JWT verification has no server-side session state to tidy. This is a simplification, not a gap.
