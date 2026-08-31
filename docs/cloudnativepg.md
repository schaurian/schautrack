# PostgreSQL on CloudNativePG

Chart 3.0.0 replaced the bundled single-Pod PostgreSQL `Deployment` with a
[CloudNativePG](https://cloudnative-pg.io/) `Cluster`. This is a breaking
change: your data lives in a PVC the chart no longer manages, and upgrading in
place without reading this page destroys it.

## Why

The old bundled database was a `Deployment` with `replicas: 1`, `strategy:
Recreate`, and a PVC. It had no backups, no point-in-time recovery, no failover,
and no managed minor-version upgrades — a `kubectl delete pvc` away from
permanent data loss. CNPG provides all four and is the operator this project
now assumes for self-hosted deployments.

## Prerequisites

The CNPG operator (>= 1.24) must already be installed. The chart deliberately
does not install it: the operator is cluster-scoped and shared between every
application that uses it, so owning it from an application chart would mean two
releases fighting over one set of CRDs.

```bash
kubectl apply --server-side -f \
  https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.28/releases/cnpg-1.28.0.yaml
kubectl -n cnpg-system wait --for=condition=Available deploy/cnpg-controller-manager --timeout=180s
```

## The one invariant you must not break

**Everything that talks to the database uses the `-rw` Service.**

CNPG publishes three Services: `-rw` (the current primary), `-ro` (hot
standbys) and `-r` (any instance). Pointing schautrack at `-ro` or `-r` looks
like it works — reads succeed, the health check passes — and then breaks
Server-Sent Events silently.

`NOTIFY` does not replicate. `internal/sse` publishes cross-instance events with
`pg_notify` and consumes them with a dedicated `LISTEN` connection, so a
listener attached to a standby waits on a channel that never fires. There is no
error: linked-user views simply stop updating, and nothing in the logs says why.

The chart wires this correctly on its own — `DATABASE_URL` comes from the
operator-generated `<cluster>-app` Secret, whose `uri` key resolves to `-rw` —
and `scripts/migrate-to-cnpg.sh` refuses to finish if the DSN it finds does not.
If you override the DSN by hand, keep it on `-rw`.

## Fresh installs

Nothing to do. `postgresql.enabled: true` provisions the Cluster, and the app
reads its credentials from the Secret the operator generates.

```yaml
postgresql:
  enabled: true
  instances: 1        # 3 for real high availability
  storage:
    size: 10Gi
```

`instances: 1` is a single instance with no standby: still a real improvement on
the old Deployment (managed backups, PITR, supervised restarts), but a node loss
is downtime until the volume reattaches. Use 3 for HA. Two gives you a standby
without quorum, so prefer 3 if you can afford the storage.

### Sizing `maxConnections`

The default of 100 is derived, not guessed. `internal/database` pins the pgxpool
to `MaxConns = 20` per replica, and `sse.Listen` holds **one more** connection
outside the pool for the lifetime of the process, because a `LISTEN` occupies
its connection permanently. So the floor is `replicas × 21`, plus CNPG's own
superuser and streaming-replication slots. Two replicas need 42 before overhead;
100 leaves room to scale to four without touching it.

## Migrating an existing install

Two paths. Pick by how your release is deployed, not by preference — the
Helm-managed one **will be reverted** under ArgoCD.

### Helm-managed releases

```bash
scripts/migrate-to-cnpg.sh -n <namespace> -r <release> [-f your-values.yaml]
```

Run it with `--dry-run` first; that stops after preflight without changing
anything.

What it does, and why in this order:

1. **Scales the app to 0.** Downtime starts. Dumping a live database would be
   internally consistent — `pg_dump` is snapshot-based — but rows written after
   the snapshot would be lost at cutover with nobody noticing.
2. **Fingerprints the source** (`scripts/db-fingerprint.sql`): an md5 per table
   over ordered, fully-rendered rows, plus every sequence position.
3. **Dumps** in custom format, then **proves the dump is restorable** by running
   `pg_restore --list` over it *inside the pod* and asserting the expected
   tables carry data. A truncated transfer is caught here, before anything is
   deleted.
4. **Annotates the old PVC** `helm.sh/resource-policy=keep` so Helm leaves it
   behind. This is your rollback; nothing in the script deletes it.
5. **Upgrades the release** with the app pinned at 0 replicas.
6. **Restores** with `pg_restore --role=<app user>`, then asserts every table in
   `public` is owned by that user.
7. **Fingerprints the result and diffs it** against step 2. Row counts are
   excluded from the comparison because `pg_stat_user_tables` is an estimate
   until `ANALYZE` runs; the digests and sequences are exact.
8. **Verifies the app's real DSN** over TCP, and that `LISTEN`/`NOTIFY` actually
   delivers on it.
9. **Scales the app back up.** Downtime ends.

If anything fails before step 5, the app is scaled back up automatically —
nothing was changed. After step 5 it deliberately stays down, because coming up
against a half-restored database is worse than staying dark.

### ArgoCD-managed releases

`scripts/migrate-to-cnpg.sh` is wrong here and running it is actively dangerous.
It drives `helm upgrade`, which an Application with `selfHeal: true` reverts,
and its PVC guard is `helm.sh/resource-policy=keep` — a **Helm** annotation that
ArgoCD does not honour.

With `prune: true`, the moment the new chart syncs, ArgoCD deletes the old
Deployment, Service **and PVC**, because they are no longer in the rendered
manifest set. The `kubernetes.io/pvc-protection` finalizer does not save you: it
only blocks deletion while a Pod is mounting the volume, and that Pod is being
deleted in the same sync.

Do this instead:

```bash
NS=schautrack-staging
APP=schautrack-staging
REL=schautrack-staging

# 1. Protect the volume from the prune, in ArgoCD's own vocabulary.
kubectl -n "$NS" annotate pvc "$REL-postgresql" \
  argocd.argoproj.io/sync-options=Prune=false,Delete=false --overwrite

# 2. Stop ArgoCD from syncing or self-healing mid-migration.
kubectl -n argocd patch application "$APP" --type merge \
  -p '{"spec":{"syncPolicy":{"automated":null}}}'

# 3. Stop writers.
kubectl -n "$NS" scale deploy "$REL" --replicas=0

# 4. Fingerprint and dump, exactly as the script does.
kubectl -n "$NS" exec -i "deploy/$REL-postgresql" -- \
  psql -U schautrack -d schautrack -tA < scripts/db-fingerprint.sql > /tmp/before.txt
kubectl -n "$NS" exec "deploy/$REL-postgresql" -- \
  pg_dump -U schautrack -d schautrack -Fc --no-owner --no-acl > /tmp/schautrack.dump
kubectl -n "$NS" exec -i "deploy/$REL-postgresql" -- pg_restore --list < /tmp/schautrack.dump | head

# 5. Point the Application at the 3.x chart and sync ONCE, manually.
#    (Update targetRevision, then:)
argocd app sync "$APP"

# 6. Restore into the new Cluster, then verify — same steps 6-8 as above.
PRIMARY=$(kubectl -n "$NS" get pods -l "cnpg.io/cluster=$REL-postgresql,cnpg.io/instanceRole=primary" -o name | head -1)
kubectl -n "$NS" exec -i "$PRIMARY" -- pg_restore -U postgres -d schautrack \
  --role=schautrack --no-owner --no-acl --clean --if-exists --exit-on-error < /tmp/schautrack.dump

# 7. Re-enable automation once you are satisfied.
kubectl -n argocd patch application "$APP" --type merge \
  -p '{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}'
```

Leave the old PVC in place until you have watched the new cluster for a while.
It is the only rollback that does not depend on the dump file surviving.

## Other things pointed at the database

The chart only knows about its own Deployment. Anything else in the namespace
holding a DSN has to move too, and will fail quietly rather than loudly:

- **sql-exporter** — repoint at `<release>-postgresql-rw`. Metrics stop being
  collected otherwise, which looks like "no data" on a dashboard rather than an
  error.

## Backups

Off by default, because it cannot work without credentials and a backup that is
silently not running is worse than one you know you have not configured. This is
the main reason to be on CNPG at all, so configure it:

```yaml
postgresql:
  backup:
    enabled: true
    destinationPath: s3://my-bucket/schautrack
    endpointURL: https://minio.example.com   # omit for AWS
    s3Credentials:
      secretName: schautrack-backup-s3
    retentionPolicy: "30d"
    schedule: "0 0 3 * * *"    # SIX fields, seconds first — CNPG's cron, not Kubernetes'
```

Verify a backup completed before believing in it:

```bash
kubectl -n "$NS" get backup
```

## Importing from a PostgreSQL you keep running

`postgresql.bootstrap.importFrom` makes CNPG run `pg_dump | pg_restore` against
an external server as it bootstraps. This is the right tool when the source is a
database you control and can keep running — it is **not** the path off the old
bundled Deployment, because the same Helm upgrade that creates the Cluster
deletes the source before the bootstrap can reach it.

It is read **only** at bootstrap. On an already-initialised Cluster it does
nothing, so leaving it enabled will not re-import or overwrite live data. Set it
back to `false` afterwards anyway, so a future Cluster rebuild does not point at
a server that no longer exists.

## Rollback

Before cutover: scale the app back up. Nothing has changed.

After cutover, before you delete the old PVC: reinstall the 2.x chart with
`postgresql.persistence.existingClaim` set to the retained PVC. The data is
exactly as it was when the app was scaled down, because nothing ever wrote to it
again.

After you delete the old PVC: your only copy is the dump, and a CNPG backup if
you configured one. Do not delete the PVC on migration day.
