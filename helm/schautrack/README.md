# Schautrack

A simple, self-hosted calorie tracking application.

## Introduction

This chart deploys [Schautrack](https://github.com/schaurian/schautrack) on a Kubernetes cluster using Helm.

## Prerequisites

- Kubernetes 1.22+
- Helm 3.x
- PV provisioner support (if using bundled PostgreSQL)

## Installing

### From Helm repository

```bash
helm repo add schautrack https://helm.schautrack.com
helm repo update

helm install schautrack schautrack/schautrack \
  --set config.sessionSecret="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 16)"
```

### From source

```bash
git clone https://github.com/schaurian/schautrack.git
cd schautrack

helm install schautrack ./helm/schautrack \
  --set config.sessionSecret="$(openssl rand -base64 32)" \
  --set postgresql.auth.password="$(openssl rand -base64 16)"
```

### Using a values file (recommended for GitOps)

Create a `values.yaml` file:

```yaml
config:
  sessionSecret: ""  # Use sealed-secrets or external-secrets
  adminEmail: "admin@example.com"

postgresql:
  auth:
    password: ""  # Use sealed-secrets or external-secrets

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

> **Tip:** For production, use [sealed-secrets](https://github.com/bitnami-labs/sealed-secrets) or [external-secrets](https://external-secrets.io/) to manage sensitive values.

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

### Using an external database

Disable the bundled PostgreSQL and provide a connection string:

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

Schautrack supports AI-powered calorie estimation from food photos:

```yaml
ai:
  provider: openai  # or: claude, ollama
  key: "sk-..."
  model: "gpt-4o-mini"
  keyEncryptionSecret: ""  # Generate with: openssl rand -hex 32
  dailyLimit: 50  # Per-user limit when using global key
```

### Enabling SMTP (password reset)

```yaml
smtp:
  host: smtp.example.com
  port: 587
  user: noreply@example.com
  pass: "your-password"
  from: "Schautrack <noreply@example.com>"
  secure: false
```

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

### Application

| Parameter | Description | Default |
|-----------|-------------|---------|
| `config.sessionSecret` | Session encryption key (**required**) | `""` |
| `config.adminEmail` | Email with admin access | `""` |
| `config.supportEmail` | Support contact email | `""` |
| `config.enableLegal` | Enable /imprint, /privacy, /terms | `false` |
| `config.imprintUrl` | Imprint page URL | `/imprint` |
| `config.imprintAddress` | Imprint address (use `\n` for line breaks) | `""` |
| `config.imprintEmail` | Imprint email | `""` |
| `config.robotsIndex` | Allow search engine indexing | `false` |
| `config.baseUrl` | Base URL for SEO meta tags (auto-detects if empty) | `""` |

### AI

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ai.provider` | AI provider: `openai`, `claude`, or `ollama` | `""` |
| `ai.key` | API key for AI provider | `""` |
| `ai.keyEncryptionSecret` | Secret for encrypting user API keys | `""` |
| `ai.endpoint` | Custom API endpoint | `""` |
| `ai.model` | Model override (e.g., `gpt-4o-mini`) | `""` |
| `ai.dailyLimit` | Daily requests per user (0 = unlimited) | `0` |

### SMTP

| Parameter | Description | Default |
|-----------|-------------|---------|
| `smtp.host` | SMTP server hostname | `""` |
| `smtp.port` | SMTP server port | `587` |
| `smtp.user` | SMTP username | `""` |
| `smtp.pass` | SMTP password | `""` |
| `smtp.from` | From address | `""` |
| `smtp.secure` | Use TLS | `false` |

### PostgreSQL (bundled)

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.enabled` | Deploy bundled PostgreSQL | `true` |
| `postgresql.image.repository` | PostgreSQL image | `postgres` |
| `postgresql.image.tag` | PostgreSQL version | `18-alpine` |
| `postgresql.auth.database` | Database name | `schautrack` |
| `postgresql.auth.username` | Database user | `schautrack` |
| `postgresql.auth.password` | Database password (**required**) | `""` |
| `postgresql.persistence.enabled` | Enable persistence | `true` |
| `postgresql.persistence.size` | PVC size | `5Gi` |
| `postgresql.persistence.storageClass` | Storage class | `""` |
| `postgresql.persistence.accessMode` | PVC access mode | `ReadWriteOnce` |
| `postgresql.resources` | Resource requests/limits | `{}` |

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

### To 1.0.0

No breaking changes.

## License

[AGPL-3.0](https://github.com/schaurian/schautrack/blob/main/LICENSE)
