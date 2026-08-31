#!/usr/bin/env bash
# Migrate a schautrack release from the pre-3.0 bundled PostgreSQL Deployment
# to a CloudNativePG Cluster.
#
#   scripts/migrate-to-cnpg.sh -n <namespace> -r <release> [-c <kube-context>] \
#     [-C <chart>] [-f <values.yaml>] [--dry-run]
#
# WHY A SCRIPT AND NOT A NOTE IN THE README
#
# The obvious move — `helm upgrade` straight to 3.0.0 — destroys the database.
# One upgrade deletes the old Deployment, Service and PVC and creates an empty
# Cluster, and Helm does all of it before anything can copy the data out. That
# is also why CNPG's own `bootstrap.initdb.import` cannot carry this migration
# on its own: it dumps from a live source over the network, and by the time the
# Cluster bootstraps, Helm has already deleted the source. (importFrom is still
# the right tool when the source is a PostgreSQL you keep running yourself —
# see docs/cloudnativepg.md.)
#
# So the order here is deliberate: stop writers, dump, PROVE the dump is
# usable, only then let Helm near the old objects, restore, and compare a
# content fingerprint before letting traffic back in.
#
# The old PVC is annotated helm.sh/resource-policy=keep before the upgrade, so
# Helm leaves it behind. It is the rollback: nothing in this script deletes it,
# and it is yours to remove once you are satisfied.
set -euo pipefail

NS=""; RELEASE=""; CTX=""; CHART="helm/schautrack"; VALUES=""; DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) NS="$2"; shift 2 ;;
    -r) RELEASE="$2"; shift 2 ;;
    -c) CTX="$2"; shift 2 ;;
    -C) CHART="$2"; shift 2 ;;
    -f) VALUES="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$NS" && -n "$RELEASE" ]] || { echo "usage: $0 -n <namespace> -r <release> [-c ctx] [-C chart] [-f values] [--dry-run]" >&2; exit 2; }

KCTX=(); [[ -n "$CTX" ]] && KCTX=(--context "$CTX")
k() { kubectl "${KCTX[@]}" -n "$NS" "$@"; }
h() { helm ${CTX:+--kube-context "$CTX"} "$@"; }
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

WORKDIR="$(mktemp -d -t schautrack-cnpg-XXXXXX)"
DUMP="$WORKDIR/schautrack.dump"
say "Working directory: $WORKDIR (dump and fingerprints are kept here)"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FINGERPRINT_SQL="$SCRIPT_DIR/db-fingerprint.sql"
[[ -f "$FINGERPRINT_SQL" ]] || die "missing $FINGERPRINT_SQL"

# --- Preflight -------------------------------------------------------------
# Every check here fails BEFORE anything is modified. A half-migrated release
# is much worse than one that refused to start.
say "Preflight"

k get deploy "$RELEASE-schautrack" >/dev/null 2>&1 \
  || die "no Deployment $RELEASE-schautrack in namespace $NS"

PG_DEPLOY="$RELEASE-schautrack-postgresql"
k get deploy "$PG_DEPLOY" >/dev/null 2>&1 \
  || die "no bundled PostgreSQL Deployment $PG_DEPLOY. Already migrated, or not a pre-3.0 release."

kubectl "${KCTX[@]}" get crd clusters.postgresql.cnpg.io >/dev/null 2>&1 \
  || die "the CloudNativePG operator is not installed in this cluster.
  Install it first (cluster-wide, once):
    kubectl apply --server-side -f https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.28/releases/cnpg-1.28.0.yaml"

DB_USER="$(h get values "$RELEASE" -n "$NS" -o json 2>/dev/null | python3 -c 'import json,sys;v=json.load(sys.stdin) or {};print((v.get("postgresql") or {}).get("auth",{}).get("username","schautrack"))' 2>/dev/null || echo schautrack)"
DB_NAME="$(h get values "$RELEASE" -n "$NS" -o json 2>/dev/null | python3 -c 'import json,sys;v=json.load(sys.stdin) or {};print((v.get("postgresql") or {}).get("auth",{}).get("database","schautrack"))' 2>/dev/null || echo schautrack)"
say "Source database: $DB_NAME (owner $DB_USER)"

REPLICAS="$(k get deploy "$RELEASE-schautrack" -o jsonpath='{.spec.replicas}')"
say "App replicas to restore afterwards: $REPLICAS"

if [[ "$DRY_RUN" == 1 ]]; then
  say "Dry run: preflight passed, stopping before any change."
  exit 0
fi

# --- Stop writers ----------------------------------------------------------
# Downtime starts here and ends at the final scale-up. Taking the dump from a
# live database would be consistent (pg_dump is snapshot-based) but the rows
# written after it would be lost silently at cutover, which is worse.
# Until Helm has touched anything, a failure is fully recoverable and the only
# harm done is that the app is down. Put it back up on the way out, so a failed
# dump costs a blip rather than an outage that waits for someone to notice.
# Disarmed just before the upgrade, after which staying down is the safe state.
restore_replicas_on_failure() {
  local code=$?
  [[ $code -eq 0 ]] && return 0
  printf '\n\033[33mNothing has been changed yet — scaling the app back to %s.\033[0m\n' "$REPLICAS" >&2
  k scale deploy "$RELEASE-schautrack" --replicas="$REPLICAS" >/dev/null 2>&1 || true
}
trap restore_replicas_on_failure EXIT

say "Scaling app to 0 (downtime begins)"
k scale deploy "$RELEASE-schautrack" --replicas=0
k rollout status deploy "$RELEASE-schautrack" --timeout=120s >/dev/null 2>&1 || true
for _ in $(seq 1 60); do
  [[ "$(k get pods -l app.kubernetes.io/name=schautrack --no-headers 2>/dev/null | grep -c .)" == "0" ]] && break
  sleep 2
done

# --- Fingerprint + dump the source ----------------------------------------
say "Fingerprinting the source database"
k exec -i "deploy/$PG_DEPLOY" -- psql -U "$DB_USER" -d "$DB_NAME" -tA -v ON_ERROR_STOP=1 \
  < "$FINGERPRINT_SQL" > "$WORKDIR/fingerprint-before.txt" \
  || die "could not fingerprint the source database"
grep -c . "$WORKDIR/fingerprint-before.txt" >/dev/null || die "empty fingerprint"

say "Dumping (custom format)"
k exec "deploy/$PG_DEPLOY" -- pg_dump -U "$DB_USER" -d "$DB_NAME" -Fc --no-owner --no-acl \
  > "$DUMP" || die "pg_dump failed"

# A dump that exists is not a dump that works. pg_restore --list both proves
# the file is a valid archive and lets us assert the tables are really in it,
# which catches a truncated or half-written transfer before it matters.
#
# Run inside the pod, not locally: the archive is written by the server's
# pg_dump, so only a pg_restore of at least that version can read it — and a
# self-hoster driving this from a laptop has no reason to have PostgreSQL
# client tools installed at all. The pod always has the matching pair.
[[ -s "$DUMP" ]] || die "dump is empty"
k exec -i "deploy/$PG_DEPLOY" -- pg_restore --list > "$WORKDIR/dump-toc.txt" < "$DUMP" 2>/dev/null \
  || die "dump is not a readable pg_restore archive"
for t in users calorie_entries weight_entries saved_foods schema_data_migrations; do
  grep -q "TABLE DATA public $t" "$WORKDIR/dump-toc.txt" \
    || die "dump has no data for table '$t' — refusing to continue"
done
say "Dump verified: $(du -h "$DUMP" | cut -f1), $(grep -c 'TABLE DATA' "$WORKDIR/dump-toc.txt") tables with data"

# --- Preserve the old volume ----------------------------------------------
# Do this BEFORE the upgrade. Once Helm has deleted the PVC there is nothing
# left to annotate, and the only copy of the data is the dump in /tmp.
say "Annotating the old PVC to survive the upgrade"
OLD_PVC="$(k get pvc -l app.kubernetes.io/component=database -o name 2>/dev/null | head -1)"
if [[ -n "$OLD_PVC" ]]; then
  k annotate "$OLD_PVC" helm.sh/resource-policy=keep --overwrite >/dev/null
  say "Kept: $OLD_PVC (delete it yourself once you are satisfied)"
else
  say "WARNING: no database PVC found; the old data may have been ephemeral"
fi

# --- Upgrade to the CNPG chart, with the app still at zero -----------------
# From here on, staying down on failure is correct: the old objects are gone
# and the app must not come up against a half-restored database.
trap - EXIT

say "Upgrading release to the CloudNativePG chart (app stays at 0 replicas)"
HELM_ARGS=(upgrade "$RELEASE" "$CHART" -n "$NS" --set replicaCount=0 --wait --timeout 10m)
[[ -n "$VALUES" ]] && HELM_ARGS+=(-f "$VALUES")
h "${HELM_ARGS[@]}" || die "helm upgrade failed; the old PVC is still present for rollback"

CLUSTER="$RELEASE-schautrack-postgresql"
say "Waiting for the CNPG cluster to be ready"
for _ in $(seq 1 120); do
  READY="$(k get cluster "$CLUSTER" -o jsonpath='{.status.readyInstances}' 2>/dev/null || echo 0)"
  [[ "${READY:-0}" -ge 1 ]] && break
  sleep 5
done
[[ "${READY:-0}" -ge 1 ]] || die "CNPG cluster $CLUSTER never became ready"

# --- Restore ---------------------------------------------------------------
# The app ran its own migrations against an empty database when the Cluster
# bootstrapped, so the schema already exists. --clean --if-exists makes the
# restore authoritative over that empty schema instead of colliding with it.
say "Restoring into the CNPG cluster"
PRIMARY="$(k get pods -l "cnpg.io/cluster=$CLUSTER,cnpg.io/instanceRole=primary" -o name | head -1)"
[[ -n "$PRIMARY" ]] || die "could not find the CNPG primary pod"

# --role, not a fix-up afterwards. The dump is --no-owner, so a plain restore
# as postgres creates every table owned by postgres and the app — which
# connects as the CNPG app user — gets permission denied on all of them.
#
# The obvious repair, REASSIGN OWNED BY postgres TO <app>, does not work: it
# refuses with "cannot reassign ownership of objects owned by role postgres
# because they are required by the database system", because it sweeps up
# catalog objects along with ours. --role makes pg_restore SET ROLE first, so
# the objects are created correctly owned and there is nothing to repair.
say "Restoring as role $DB_USER"
k exec -i "$PRIMARY" -- pg_restore -U postgres -d "$DB_NAME" --role="$DB_USER" \
  --no-owner --no-acl --clean --if-exists --exit-on-error < "$DUMP" \
  || die "pg_restore failed. The old PVC is intact; roll back by reinstalling the previous chart."

# Prove the app user really owns what it will have to write to. A restore that
# silently left tables owned by postgres passes every row-count check and then
# fails on the first INSERT in production.
say "Verifying table ownership"
NOT_OWNED="$(k exec -i "$PRIMARY" -- psql -U postgres -d "$DB_NAME" -tAc \
  "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tableowner <> '$DB_USER'" | tr -d '[:space:]')"
[[ "$NOT_OWNED" == "0" ]] \
  || die "$NOT_OWNED table(s) in public are not owned by $DB_USER; the app would hit permission denied"

# --- Prove it --------------------------------------------------------------
# As postgres, over the pod's local socket: inside a CNPG pod the OS user is
# postgres, so peer auth rejects `-U schautrack` outright. The fingerprint is
# pure content, so who reads it does not change the answer — and the app user's
# real access is proven separately below, over TCP, with its actual credentials.
say "Fingerprinting the migrated database"
k exec -i "$PRIMARY" -- psql -U postgres -d "$DB_NAME" -tA -v ON_ERROR_STOP=1 \
  < "$FINGERPRINT_SQL" > "$WORKDIR/fingerprint-after.txt" \
  || die "could not fingerprint the migrated database"

# Row counts come from pg_stat_user_tables, which is populated by ANALYZE and
# is an estimate on a freshly restored cluster — comparing those would produce
# false failures. The digests and sequence values are exact, so they are what
# the comparison is made of.
grep -vE '^rowcount\|' "$WORKDIR/fingerprint-before.txt" | sort > "$WORKDIR/before.cmp"
grep -vE '^rowcount\|' "$WORKDIR/fingerprint-after.txt"  | sort > "$WORKDIR/after.cmp"

if ! diff -u "$WORKDIR/before.cmp" "$WORKDIR/after.cmp" > "$WORKDIR/fingerprint.diff"; then
  cat "$WORKDIR/fingerprint.diff"
  die "the migrated database does not match the source.
  The app is still at 0 replicas and the old PVC is intact — nothing is serving
  bad data. Inspect $WORKDIR, then roll back to the previous chart revision."
fi
say "Fingerprints match: every table digest and sequence position is identical"

# --- Prove the DSN the app will actually use -------------------------------
# Everything above ran as postgres over a local socket. That is not what the
# app does: it connects over TCP as the CNPG app user, using the URI from the
# operator-managed Secret. Test that exact path.
say "Verifying the application DSN"
APP_SECRET="$(k get cluster "$CLUSTER" -o jsonpath='{.metadata.name}')-app"
APP_URI="$(k get secret "$APP_SECRET" -o jsonpath='{.data.uri}' 2>/dev/null | base64 -d)"
[[ -n "$APP_URI" ]] || die "no uri key in Secret $APP_SECRET — the Deployment reads DATABASE_URL from it"

case "$APP_URI" in
  *"-rw"*|*"-rw."*) : ;;
  *) die "the app DSN does not point at the -rw Service.
  NOTIFY does not replicate, so LISTEN on a read Service never fires and
  cross-instance SSE would go silently dead. Refusing to finish." ;;
esac

k exec -i "$PRIMARY" -- psql "$APP_URI" -tAc "SELECT 1" >/dev/null \
  || die "the application DSN cannot connect or authenticate"

# The invariant this whole migration is most likely to break silently.
# One session LISTENs and NOTIFYs itself; psql prints the asynchronous
# notification only if the channel genuinely delivered it.
say "Verifying LISTEN/NOTIFY on the application DSN"
NOTIFY_OUT="$(k exec -i "$PRIMARY" -- psql "$APP_URI" -tA -c "LISTEN schautrack_events;" -c "SELECT pg_notify('schautrack_events','migration-probe');" -c "SELECT pg_sleep(0.2);" 2>&1 || true)"
grep -q 'migration-probe' <<<"$NOTIFY_OUT" \
  || die "LISTEN/NOTIFY did not deliver on the application DSN.
  Server-Sent Events across app replicas depend on this channel; without it
  linked-user views stop updating with no error anywhere.
  psql said: $NOTIFY_OUT"
say "LISTEN/NOTIFY delivers on the app DSN"

# --- Let traffic back in ---------------------------------------------------
say "Scaling app back to $REPLICAS (downtime ends)"
k scale deploy "$RELEASE-schautrack" --replicas="$REPLICAS"
k rollout status deploy "$RELEASE-schautrack" --timeout=300s || die "app did not become ready"

say "Done."
cat <<EOF

  Migrated $RELEASE in $NS to CloudNativePG.

  Evidence:   $WORKDIR
  Rollback:   the old PVC is still there, annotated helm.sh/resource-policy=keep

  Remaining, once you have watched it for a while:
    1. delete the old PVC
    2. set replicaCount back in your values file if you passed it on the CLI
    3. if you run the sql-exporter, repoint its DSN at $CLUSTER-rw
EOF
