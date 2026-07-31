# wb-247 bake-off — Route B: in-provider RDS IAM token minting

**Repo:** `Gusto/provider-sql` (fork) · **branch:** `wb-247-route-b-iam-connector` · **base:** `origin/gusto-main`

Route B teaches provider-sql to mint the RDS IAM auth token **itself**, at connect
time, from its own IRSA / Pod Identity ServiceAccount identity — instead of an
external controller writing a token into a Secret that provider-sql reads
(that's Route A, tracked as wb-254 in `crossplane-provider-platform-core`).

This document records what was built and scores Route B on the shared bake-off
axes so it compares 1:1 with Route A.

## What was built (this prototype)

| File | Purpose | LOC |
|---|---|---|
| `pkg/clients/mysql/mysql.go` | `TokenMinter` interface; `iamConnector` (a `driver.Connector` that mints per physical connection); `NewWithMinter`; `getOrOpenPoolConnector` + `applyPoolConfig` refactor | +128 / −18 |
| `pkg/clients/mysql/rdsauth/minter.go` | Concrete `Minter`: `feature/rds/auth.BuildAuthToken` + default cred chain + optional assume-role chain | +55 |
| `pkg/clients/mysql/iam_connector_test.go` | Deterministic tests via a driver-boundary seam + fake minter, plus a real-path connect test | +172 |
| `pkg/clients/mysql/rdsauth/minter_test.go` | Compile-time proof `*rdsauth.Minter` satisfies `mysql.TokenMinter` | +10 |
| `apis/cluster/mysql/v1alpha1/provider_types.go` | `RDSIAMAuth` source + enum + `RDSAuthConfig` block | +27 / −2 |
| `apis/cluster/mysql/v1alpha1/zz_generated.deepcopy.go` | Regenerated deepcopy (controller-gen) | +25 |
| `pkg/controller/cluster/mysql/user/reconciler.go` | `Connect()` branch on source; injected `newMinter` / `newDBWithMinter` seams | +61 / −12 |
| `pkg/controller/cluster/mysql/user/reconciler_test.go` | `TestConnectRDSIAMAuth` (wiring + both error paths) | +98 |
| `go.mod` / `go.sum` | aws-sdk-go-v2 dependency add | +45 |

`go build ./...`, `go vet`, and `go test ./pkg/clients/mysql/... ./pkg/controller/cluster/mysql/...` all pass.

### The load-bearing idea

The token (a ~15-minute credential) is supplied per **physical** connection by a
`driver.Connector`, and is **never** part of the DSN, the pool key, or any
Secret:

- Pool is opened with `sql.OpenDB(&iamConnector{...})` and keyed by a
  **password-less DSN** (`iam:` + user/host/tls/params). Token rotation reuses
  the same pool. Proven by `TestNewWithMinter_PoolKeyExcludesToken`.
- `iamConnector.Connect` calls `minter.Mint(ctx)` on every new physical
  connection, re-parses the base DSN, sets `cfg.Passwd = token`, and delegates
  to the go-sql-driver connector. Proven by
  `TestIAMConnector_MintsFreshTokenPerConnection` (one mint per connect; the
  minted token reaches the driver as `cfg.Passwd` with
  `AllowCleartextPasswords=true`).
- Mint failures surface as connect errors and never reach the driver
  (`TestIAMConnector_MintErrorPropagates`).
- End-to-end wiring is covered too: `TestNewWithMinter_InvokesMinterOnConnect`
  drives the real `NewWithMinter → getOrOpenPoolConnector → Connect → Mint` path
  (a query against an unreachable addr; the minter is consulted before the dial
  fails).

**Known limitation (benign):** `getOrOpenPoolConnector` caches the *first*
`iamConnector` for a given pool key and ignores the minter from later
`NewWithMinter` calls with the same key — mirroring the existing DSN pool cache,
which also never evicts. This is harmless because the cached minter's
`aws.CredentialsProvider` auto-refreshes and keeps minting valid tokens; but a
change to region / assume-role config would not take effect until the provider
process restarts. Acceptable for the pilot; worth an eviction/versioned-key note
if the config becomes dynamic.

> **Comparison altitude — now leveled.** This prototype is a full vertical
> slice on the **cluster** ProviderConfig path (the one the shared-DB admin
> connection uses): connector core + concrete minter + the ProviderConfig
> `RDSIAMAuth` source + `RDSAuth` config + deepcopy regen + the reconciler
> `Connect()` branch, all unit-tested. This matches the altitude of the Route A
> brief (wb-254 = one CRD + controller). The **namespaced** ProviderConfig
> variant is a second deployment mode not used by the wb-247 target; it mirrors
> the cluster diff 1:1 and is intentionally left un-applied so Route B is one
> slice, not two (wiring it would make Route B *larger* than Route A, not
> equal).

### Opt-in wiring (built, cluster path)

- `apis/cluster/mysql/v1alpha1/provider_types.go`: `CredentialsSourceRDSIAMAuth`
  const, the enum marker value (`MySQLConnectionSecret;RDSIAMAuth`), and an
  optional `RDSAuth { Region string; AssumeRoleARNs []string }` block (region is
  the one input not derivable from the connection secret). Deepcopy regenerated
  via `controller-gen object` (pinned v0.20.0).
- `pkg/controller/cluster/mysql/user/reconciler.go` `Connect()`: when
  `source == RDSIAMAuth`, joins endpoint/port + reads the username from the
  connection secret, builds the minter via an injected `newMinter` factory
  (defaulting to `rdsauth.New`, so reconciler tests stay hermetic), and calls
  `mysql.NewWithMinter`. Errors on a missing `rdsAuth` block or a mint-build
  failure. Covered by `TestConnectRDSIAMAuth` (mint args captured; both error
  paths).

## Scoring on the shared bake-off axes

| Axis | Route B result |
|---|---|
| **New-code footprint** | Full cluster slice built: ~280 LOC production + regen, ~280 test, across the mysql client, a new `rdsauth` package, the ProviderConfig API, and the user reconciler. No new CRD, no new controller. |
| **New API surface** | One new `ProviderConfig` credential source + an optional `RDSAuth` block. No new top-level resource kind. |
| **Operational surface** | **Zero new deployables.** Rides provider-sql's existing pod. Needs the pod's ServiceAccount annotated with an IRSA role (the mechanism the unified clusters already use) — a config change, not a new workload. |
| **Security posture** | **Strongest: the token never lands in a Kubernetes Secret.** It exists only in memory for the duration of a connect. This is the "stop storing credentials" goal met literally. |
| **`ConnMaxIdleTime` coupling** | **Moot.** The pool key is stable across rotation, so a rotating token does not churn the pool or leak connections. Route A depends on `ConnMaxIdleTime` to reclaim the fresh-pool-per-rotation churn; Route B removes the churn entirely. |
| **DSN-corruption bug (wb-250/246)** | **Moot for this path.** The token is set via `cfg.Passwd`, never interpolated into a DSN string, so the presigned-URL-shaped token can't corrupt the DSN. (`allowCleartextPasswords` is still required and already present.) |
| **New dependency cost** | Adds aws-sdk-go-v2 to provider-sql, which had **none**: `config`, `credentials`, `feature/rds/auth`, `service/sts`, `service/sso`, `service/ssooidc`, `smithy-go`, plus internal modules (~15 modules). This is Route B's main cost and the primary count against it. |
| **Upstreamability** | Directly addresses `crossplane-contrib/provider-sql#106` (open request for RDS IAM auth). The core `TokenMinter`/connector is generic; a Gusto-specific `rdsauth` minter could stay in the fork while the interface is offered upstream. |
| **Verifiability** | Same ceiling as Route A: unit-tested here; the real token handshake needs real Aurora (LocalStack can't emulate it). Staging step deferred. wb-251 confirmed the shared ProviderConfig is `tls: skip-verify` (cleartext guard passes); wb-252 confirmed Aurora MySQL 8.0. |

## Route B vs Route A — the tradeoff in one line

Route B is smaller in moving parts (no CRD, no controller, no new deployable),
strictly better on security (no token in a Secret) and on the pooling/DSN
concerns (both moot), at the cost of pulling aws-sdk-go-v2 into provider-sql and
concentrating the change inside the fork. Route A keeps provider-sql nearer
upstream but adds a controller + CRD to build and operate and still parks a live
token in a Secret.

## Sibling tickets this route collapses or de-scopes

- **wb-247** (the refresher controller): not built — replaced by in-provider minting.
- **wb-250 / wb-246** (DSN-corruption / cleartext): the DSN-corruption fix becomes moot for the IAM path (token bypasses the DSN string).
- **wb-248** (`rds-db:connect` grant): still required, now scoped to provider-sql's own IRSA role.
- **wb-249** (admin-user bootstrap) and **wb-252** (engine version): unchanged; independent of route choice.
