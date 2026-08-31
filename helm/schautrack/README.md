# Schautrack

A simple, self-hosted nutrition tracking application.

## Introduction

This chart deploys [Schautrack](https://github.com/schaurian/schautrack) on a Kubernetes cluster using Helm.

## Prerequisites

- Kubernetes 1.22+
- Helm 3.x
- The CloudNativePG operator (>= 1.24), if using the in-chart database

## Installing

### From Helm repository

```bash
helm repo add schautrack https://helm.schautrack.com
helm repo update

helm install schautrack schautrack/schautrack \
  --set postgresql.storage.size=10Gi
```

### From source

```bash
git clone https://github.com/schaurian/schautrack.git
cd schautrack

helm install schautrack ./helm/schautrack \
  --set postgresql.storage.size=10Gi
```

### Using a values file (recommended for GitOps)

Create a `values.yaml` file:

```yaml
config:
  adminEmail: "admin@example.com"

postgresql:
  instances: 3        # HA; CloudNativePG owns the credential
  storage:
    size: 10Gi

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: calories.example.com
      paths:
        - path: /
          pathType: Prefix
```

Then install:

```bash
helm install schautrack schautrack/schautrack -f values.yaml
```

> **Tip:** For production, use [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) or [external-secrets](https://external-secrets.io/) to manage sensitive values. See [Using an existing secret](#using-an-existing-secret) below.

## Uninstalling

```bash
helm uninstall schautrack
```

> **Note:** This does not delete the PersistentVolumeClaim. To delete all data:
> ```bash
> kubectl delete pvc -l app.kubernetes.io/instance=schautrack
> ```

## Configuration

See [values.yaml](values.yaml) for the full list of configurable parameters.

### Using an existing secret

For production environments with external secret management (e.g., External Secrets Operator, Sealed Secrets), you can reference a pre-existing Kubernetes Secret instead of having the chart create one:

```yaml
existingSecret: "my-schautrack-secrets"

# These values are ignored when existingSecret is set:
# smtp.user, smtp.pass, ai.key, ai.keyEncryptionSecret,
# oidc.clientSecret, externalDatabase.url
```

The referenced Secret must contain these keys:

| Key | Required | Description |
|-----|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `POSTGRES_PASSWORD` | No longer used | CloudNativePG owns the credential; see the PostgreSQL section |
| `SMTP_USER` | No | SMTP username |
| `SMTP_PASS` | No | SMTP password |
| `AI_KEY` | No | API key for AI provider |
| `AI_KEY_ENCRYPTION_SECRET` | No | Secret for encrypting user API keys |
| `OIDC_CLIENT_SECRET` | No | OAuth2 client secret (required when `oidc.issuer` is set) |

Example External Secrets Operator configuration:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: schautrack-secrets
spec:
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: my-schautrack-secrets
  data:
    - secretKey: DATABASE_URL
      remoteRef:
        key: schautrack/database
        property: url
    # ... additional keys as needed
```

### Using an external database

Disable the in-chart CloudNativePG cluster and provide a connection string:

```yaml
postgresql:
  enabled: false

externalDatabase:
  url: "postgres://user:password@host:5432/schautrack"
```

### Enabling ingress with TLS

```yaml
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: calories.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: schautrack-tls
      hosts:
        - calories.example.com
```

### Enabling AI features

Schautrack supports AI-powered nutrition estimation from food photos:

```yaml
ai:
  provider: openai  # or: claude, gemini, ollama
  key: "sk-..."
  model: "gpt-4o"
  keyEncryptionSecret: ""  # Generate with: openssl rand -hex 32
  dailyLimit: 10  # Per-user limit when using global key
```

> **Note:** Ollama models must be downloaded before use. Models specified in API requests will fail if not pre-downloaded on your Ollama server.

### Enabling SMTP (transactional email)

Configuring SMTP enables all transactional email flows: password reset, registration email verification, email-change verification, and 2FA reset. Without SMTP configured, none of these flows can deliver their codes.

```yaml
smtp:
  host: smtp.example.com
  port: 587
  user: noreply@example.com
  pass: "your-password"
  from: "Schautrack <noreply@example.com>"
  secure: false
```

### Tuning rate limits

Every limit the application enforces is exposed under `config.rateLimit`. Each
one is **optional**: leave it empty and the chart omits the environment
variable entirely, so the application's own default applies.

```yaml
config:
  # Trust X-Forwarded-For — decides whether buckets key on the real client IP
  # or on your ingress controller's. Leave at the default (true) behind an
  # ingress; set "false" for direct-access deployments.
  trustProxy: ""
  rateLimit:
    strict: 15   # let API clients run 15 AI estimates per 5 min instead of 5
    apiToken: 120
```

> **Do not paste the defaults in.** Setting `auth: 10` looks harmless but pins
> your deployment to the value the chart author last copied; if the application
> changes its default, your release will not follow. Set only what you actually
> want to differ. A value of `0` is treated as unset by the application, so it
> means "use the default" rather than "block everything".

Behind an ingress, `config.trustProxy` must stay at its default (`true`) or
every request will share one bucket keyed by the ingress controller's IP, and
the per-IP limits below become effectively global.

### Opting out of the update check

By default the application asks GitHub (`api.github.com`) once an hour for the
newest published release, so the footer can tell you your instance is out of
date. That is the only unsolicited outbound request the application makes. If
you would rather it made none — a privacy-sensitive deployment, or an
air-gapped cluster where the call can only ever fail — turn it off:

```yaml
config:
  updateCheck:
    enabled: false
```

`enabled: false` is the *only* value that changes anything: the application
reads `UPDATE_CHECK_ENABLED != "false"`, so anything else (including leaving it
empty) means "on". `--set config.updateCheck.enabled=false` works too — the
chart renders the boolean as the string `"false"` the application expects.

Turning the check off does **not** remove the "Report an Issue" links; those
are built from static configuration and keep working. Only the version lookup
is skipped, and the footer stops claiming an update is available.

The alternative to disabling it is to point it somewhere you control — a
self-hosted GitHub Enterprise or GitLab mirror of the repository:

```yaml
config:
  updateCheck:
    provider: gitlab
    repo: infra/mirrors/schautrack
    baseUrl: https://gitlab.example.com
```

For GitHub Enterprise the API is assumed at `<baseUrl>/api/v3`, for GitLab at
`<baseUrl>/api/v4`. Set all three together: `provider` alone would query
GitLab for `schaurian/schautrack`, which does not exist there.

## Parameters

### Global

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/schaurian/schautrack` |
| `image.tag` | Image tag (defaults to chart appVersion) | `""` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets | `[]` |
| `nameOverride` | Override chart name | `""` |
| `fullnameOverride` | Override full name | `""` |
| `existingSecret` | Use existing Secret (skips Secret creation) | `""` |

### Application

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.port` | Port the application listens on | `3000` |
| `config.adminEmail` | Email with admin access | `""` |
| `config.supportEmail` | Support contact email | `""` |
| `config.enableLegal` | Enable /imprint, /privacy, /terms | `false` |
| `config.imprintUrl` | Imprint page URL | `/imprint` |
| `config.imprintAddress` | Imprint address (use `\n` for line breaks) | `""` |
| `config.imprintEmail` | Imprint email | `""` |
| `config.enableBarcode` | Enable barcode scanning via OpenFoodFacts | `""` (true) |
| `config.enableRegistration` | `open` or `false`/`invite` (requires invite code) | `""` (open) |
| `config.trustProxy` | Trust X-Forwarded-For headers for rate limiting | `""` (true) |
| `config.robotsIndex` | Allow search engine indexing | `false` |
| `config.baseUrl` | Base URL for SEO meta tags and the OpenAPI `servers` entry (auto-detects if empty) | `""` |
| `config.stepUpTTL` | Step-up auth grace window after login before sensitive auth-method changes require re-prompting. Any Go duration (e.g. `5s`, `10m`, `1h`); empty = server default of 30m | `""` |
| `config.androidPackageName` | Package name for Android App Links (`/.well-known/assetlinks.json`) | `to.schauer.schautrack` |
| `config.androidCertFingerprints` | Comma-separated SHA-256 signing-cert fingerprint(s) for App Links (**deployment-specific**; empty disables the endpoint) | `""` |

### Rate limiting

All optional. An empty value omits the environment variable, leaving the
application's own default in force — the "Default" column below is that
application default, not a value this chart writes into the ConfigMap. See
[Tuning rate limits](#tuning-rate-limits).

| Parameter | Env var | Description | Default |
|-----------|---------|-------------|---------|
| `config.rateLimit.auth` | `RATE_LIMIT_AUTH` | Authentication attempts per IP per **15 minutes** on login, register, and step-up re-auth | `""` (`10`) |
| `config.rateLimit.strict` | `RATE_LIMIT_STRICT` | Requests per IP per **5 minutes** on sensitive endpoints: password-reset request/confirm, 2FA reset, email-change request, and **AI estimate**. Raise this to give users more AI throughput. | `""` (`5`) |
| `config.rateLimit.api` | `RATE_LIMIT_API` | Requests per IP per **minute** on the public API (`/api/v1`). The outer guard and the only limit that throttles unauthenticated traffic; keep it well above the auth limiters. | `""` (`120`) |
| `config.rateLimit.apiToken` | `RATE_LIMIT_API_TOKEN` | Requests per personal access token per **minute** on `/api/v1`. The limit a legitimate API client hits; per-IP alone means everyone behind one NAT shares a bucket. | `""` (`60`) |
| `config.rateLimit.barcode` | `RATE_LIMIT_BARCODE` | Barcode lookups per **minute**, per IP on the app's own route and per **account** on `GET /api/v1/barcode/{code}`. One value covers both so the API cannot become the cheaper path to the same third-party database. | `""` (`30`) |
| `config.trustProxy` | `TRUST_PROXY` | Whether the limiters above key on `X-Forwarded-For` / `X-Real-Ip` instead of the socket peer. Leave default behind an ingress. | `""` (`true`) |

Both API limits reject with `429` and a `Retry-After` header.

The barcode-lookup limiter (30 per minute) is not configurable in this release;
see [issue #366](https://github.com/schaurian/schautrack/issues/366).

### CAPTCHA

| Parameter | Env var | Description | Default |
|-----------|---------|-------------|---------|
| `config.captcha.globalThreshold` | `LOGIN_CAPTCHA_GLOBAL_THRESHOLD` | Failed logins per account email or per client IP (cross-session, 15-minute window) before login demands a CAPTCHA. The per-session threshold is fixed at 3 and unaffected. Raise only where clients legitimately share one source IP (a test harness, or an egress NAT in front of many users) — otherwise the shared-IP counter CAPTCHA-gates unrelated sessions. `0` or less is ignored by the application, so it means "default". | `""` (`3`) |

`CAPTCHA_BYPASS` is intentionally **not** exposed by this chart and should stay
that way. It is a test-only escape hatch that makes CAPTCHA verification accept
any non-empty answer, removing all brute-force protection from login and
registration; it is set only by the end-to-end test harness
(`compose.test.yml`).

### Update check

All optional; an empty value omits the environment variable and leaves the
application's default in force. See
[Opting out of the update check](#opting-out-of-the-update-check).

| Parameter | Env var | Description | Default |
|-----------|---------|-------------|---------|
| `config.updateCheck.enabled` | `UPDATE_CHECK_ENABLED` | Set `false` to skip the hourly outbound release lookup — recommended for privacy-sensitive or air-gapped installs. Disable-only: the application reads `!= "false"`, so no other value has any effect. "Report an Issue" links keep working. | `""` (`true`) |
| `config.updateCheck.provider` | `UPDATE_PROVIDER` | Release host to query: `github` or `gitlab`. An unknown value is logged and falls back. | `""` (`github`) |
| `config.updateCheck.repo` | `UPDATE_REPO` | `owner/repo` (GitLab also accepts nested `group/subgroup/project`) | `""` (`schaurian/schautrack`) |
| `config.updateCheck.baseUrl` | `UPDATE_BASE_URL` | Host override for self-hosted GitHub Enterprise (API at `<baseUrl>/api/v3`) or GitLab (`<baseUrl>/api/v4`) | `""` (provider's public host) |

### AI

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ai.provider` | AI provider: `openai`, `claude`, `gemini`, or `ollama` | `""` |
| `ai.key` | API key for AI provider | `""` |
| `ai.keyEncryptionSecret` | Secret for encrypting user API keys | `""` |
| `ai.endpoint` | Custom API endpoint | `""` |
| `ai.model` | Model override (e.g., `gpt-4o`, `claude-sonnet-4-5-20250929`, `gemini-3.6-flash`, `gemma3:12b`) | `""` |
| `ai.dailyLimit` | Daily requests per user (0 = unlimited). The app defaults to unlimited; this chart sets `10`. | `10` |

### SMTP

| Parameter | Description | Default |
|-----------|-------------|---------|
| `smtp.host` | SMTP server hostname | `""` |
| `smtp.port` | SMTP server port | `587` |
| `smtp.user` | SMTP username | `""` |
| `smtp.pass` | SMTP password | `""` |
| `smtp.from` | From address | `""` |
| `smtp.secure` | Use TLS | `false` |

### OIDC / Single Sign-On

| Parameter | Description | Default |
|-----------|-------------|---------|
| `oidc.issuer` | OIDC issuer URL (enables OIDC when set) | `""` |
| `oidc.clientId` | OAuth2 Client ID from your provider | `""` |
| `oidc.clientSecret` | OAuth2 Client Secret (stored in the chart Secret as `OIDC_CLIENT_SECRET`) | `""` |
| `oidc.label` | Sign-in button label (defaults to issuer host, e.g. `Google`) | `""` |
| `oidc.requireInvite` | Require an invite code for OIDC sign-up | `false` |
| `oidc.redirectUrl` | Callback URL override (auto-built from `config.baseUrl` if empty) | `""` |

> The redirect URI registered with your OIDC provider must be `<config.baseUrl>/auth/oidc/callback`.

### Passkeys / WebAuthn

| Parameter | Description | Default |
|-----------|-------------|---------|
| `passkeys.rpId` | Relying Party ID, e.g. `schautrack.com` (enables passkeys when set; baked into every registered passkey, so changing it invalidates existing ones) | `""` |
| `passkeys.rpName` | Display name shown in browser/OS passkey prompts | `""` (`Schautrack`) |
| `passkeys.rpOrigins` | Allowed origins, comma-separated full URLs with scheme | `""` (`https://<rpId>`) |

### PostgreSQL (CloudNativePG)

Requires the [CloudNativePG operator](https://cloudnative-pg.io/) (>= 1.24)
already installed in the cluster. The chart does not install it: the operator is
cluster-scoped and shared, so owning it from an application chart would mean two
releases fighting over one set of CRDs.

**Upgrading from a chart older than 3.0.0 is a breaking change.** The bundled
single-Pod PostgreSQL `Deployment` is gone and your data is in a PVC this chart
no longer manages. Read [docs/cloudnativepg.md](../../docs/cloudnativepg.md)
before upgrading — it migrates the data and verifies it before cutover. The
render fails with a pointer to that page if you still set a removed key.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.enabled` | Provision a CloudNativePG `Cluster` | `true` |
| `postgresql.instances` | Instances. 1 = no standby; use 3 for real HA | `1` |
| `postgresql.imageName` | Override the operator's default PostgreSQL image | `""` |
| `postgresql.auth.database` | Database name | `schautrack` |
| `postgresql.auth.username` | Database user (owner) | `schautrack` |
| `postgresql.auth.existingSecret` | `kubernetes.io/basic-auth` Secret to use instead of the operator-generated one. Must also carry a `uri` key | `""` |
| `postgresql.storage.size` | Data volume size | `10Gi` |
| `postgresql.storage.storageClass` | Storage class (empty = cluster default) | `""` |
| `postgresql.walStorage.enabled` | Put the WAL on its own volume | `false` |
| `postgresql.walStorage.size` | WAL volume size | `2Gi` |
| `postgresql.maxConnections` | `max_connections`. See note below | `100` |
| `postgresql.parameters` | Extra `postgresql.conf` parameters | `{}` |
| `postgresql.resources` | Resource requests/limits | `{}` |
| `postgresql.affinity` | Pod affinity rules | `{}` |
| `postgresql.backup.enabled` | Continuous backup + PITR to S3 | `false` |
| `postgresql.backup.destinationPath` | e.g. `s3://bucket/schautrack` | `""` |
| `postgresql.backup.endpointURL` | Set for non-AWS S3 (MinIO, R2) | `""` |
| `postgresql.backup.s3Credentials.secretName` | Secret with the S3 keys | `""` |
| `postgresql.backup.retentionPolicy` | Retention window | `30d` |
| `postgresql.backup.schedule` | **Six**-field cron, seconds first. Empty disables it | `0 0 3 * * *` |
| `postgresql.bootstrap.importFrom.enabled` | One-shot `pg_dump`/`pg_restore` import at bootstrap from a PostgreSQL you keep running. Not the path off the old bundled DB | `false` |

There is no `postgresql.auth.password`: CloudNativePG generates and owns the
credential, and the app reads `DATABASE_URL` straight from the Secret the
operator manages. That is also why a password rotation no longer needs a chart
upgrade to take effect.

> **Note on `maxConnections`:** the default is derived, not chosen. The app pins
> its pgxpool to `MaxConns = 20` per replica and holds one *more* connection
> outside the pool for the SSE `LISTEN`, which occupies its connection for the
> lifetime of the process. The floor is therefore `replicas × 21` plus
> CloudNativePG's own superuser and replication slots.

> **Note on Services:** CloudNativePG publishes `-rw`, `-ro` and `-r`. Everything
> here uses `-rw`. `NOTIFY` does not replicate, so a DSN on a read Service leaves
> the SSE broker listening to a channel that never fires — reads work, health
> checks pass, and cross-instance updates die silently.

### External Database

| Parameter | Description | Default |
|-----------|-------------|---------|
| `externalDatabase.url` | PostgreSQL connection string | `""` |

### Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `3000` |

### Ingress

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class | `""` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts | `[]` |
| `ingress.tls` | TLS configuration | `[]` |

### Probes

Both blocks are rendered into the container's `livenessProbe`/
`readinessProbe`, so any valid Pod probe shape works — `httpGet` (the
default), `tcpSocket`, `exec`, or `grpc` — plus the usual timing fields
(`timeoutSeconds`, `failureThreshold`, `successThreshold`).

| Parameter | Description | Default |
|-----------|-------------|---------|
| `livenessProbe` | Liveness probe for the app container | `httpGet /api/health` on port `http`, `initialDelaySeconds: 10`, `periodSeconds: 30` |
| `readinessProbe` | Readiness probe for the app container | `httpGet /api/health` on port `http`, `initialDelaySeconds: 5`, `periodSeconds: 10` |

**Setting a value merges with the default, it does not replace it.** Helm
deep-merges a values file on top of the chart's defaults key by key, so
adding `tcpSocket:` to `livenessProbe` does **not** clear the default
`httpGet:` — you end up with both set, which is an invalid probe (Kubernetes
allows exactly one handler) that fails at apply time. Null out the handler
you're replacing explicitly:

```yaml
# Switch to a TCP check (e.g. behind a proxy that doesn't speak the app's
# health-check semantics, or during debugging when /api/health is suspect).
livenessProbe:
  httpGet: null   # required — see note above
  tcpSocket:
    port: http
  initialDelaySeconds: 10
  periodSeconds: 30
```

The chart validates this at render time: `helm template`/`helm install`
fails immediately, naming the probe and the conflicting keys, if a probe
ends up with zero handlers or more than one — instead of producing a
manifest that only fails later, at `kubectl apply` or an ArgoCD sync,
possibly mid-rollout.

### Resources and Scheduling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources` | Resource requests/limits | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |
| `podAnnotations` | Pod annotations | `{}` |
| `podSecurityContext` | Pod security context | `{}` |
| `securityContext` | Container security context | `{}` |

### Service Account

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create service account | `false` |
| `serviceAccount.annotations` | Service account annotations | `{}` |
| `serviceAccount.name` | Service account name | `""` |

## Upgrading

The chart follows semantic versioning; no breaking changes have been released
through the current `0.5.x` series. `helm upgrade` in place is safe.

### 0.5.0

- Exposed `livenessProbe` and `readinessProbe` (app container) and
  `postgresql.livenessProbe` / `postgresql.readinessProbe` (postgres
  container). Previously these were hardcoded in the templates and
  unreachable from values. Since `0.4.0` added `values.schema.json` with
  `additionalProperties: false` at the root, passing them from a values file
  or an ArgoCD `Application` CR was worse than a no-op: it failed schema
  validation with a fatal install/upgrade error instead of being silently
  ignored.
- All four default to exactly what the chart hardcoded before — upgrading
  from `0.4.x` changes no running probe. See [Probes](#probes) for the
  override shape and a note on the postgres probe's default command not
  tracking `postgresql.auth.*`.
- `helm template`/`helm install` now fails fast, naming the probe and the
  conflicting keys, if a probe override ends up with zero or more than one
  handler (`httpGet`/`tcpSocket`/`exec`/`grpc`) set — most commonly from
  forgetting to null out the default handler when switching probe kind (see
  [Probes](#probes)). Kubernetes would otherwise reject the object at apply
  time instead of at render time, possibly mid-rollout.

### 0.4.0

- Exposed the update check (`config.updateCheck.enabled`, `.provider`, `.repo`,
  `.baseUrl`), so the privacy opt-out the application documents is finally
  reachable from the chart. Setting `config.updateCheck.enabled: false` stops
  the hourly request to `api.github.com`.
- Exposed `config.captcha.globalThreshold`
  (`LOGIN_CAPTCHA_GLOBAL_THRESHOLD`).
- With this release every environment variable the application reads is
  settable from the chart, except `BUILD_VERSION` (baked into the image at
  build time) and `CAPTCHA_BYPASS` (test-only, deliberately unreachable).
- All new values default to empty, which omits the environment variable and
  leaves the application's own default in force — upgrading from `0.3.x`
  changes no behaviour.

### 0.3.0

- Exposed the rate limits (`config.rateLimit.auth`, `.strict`, `.api`,
  `.apiToken`). All default to empty, which omits the environment variable and
  leaves the application's own default in force — so upgrading from `0.2.x`
  changes no running limit.

### 0.2.x

- Added optional OIDC / Single Sign-On support (`oidc.*`, `OIDC_CLIENT_SECRET`).
- Added optional Passkeys / WebAuthn support (`passkeys.*`).
- Exposed the step-up auth grace window (`config.stepUpTTL`).

All of the above are opt-in and disabled by default, so existing releases are
unaffected until the corresponding values are set.

## License

[AGPL-3.0](https://github.com/schaurian/schautrack/blob/main/LICENSE)
