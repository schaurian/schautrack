{{/*
Expand the name of the chart.
*/}}
{{- define "schautrack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "schautrack.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "schautrack.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "schautrack.labels" -}}
helm.sh/chart: {{ include "schautrack.chart" . }}
{{ include "schautrack.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "schautrack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "schautrack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
PostgreSQL fullname
*/}}
{{- define "schautrack.postgresql.fullname" -}}
{{- printf "%s-postgresql" (include "schautrack.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
PostgreSQL labels
*/}}
{{- define "schautrack.postgresql.labels" -}}
helm.sh/chart: {{ include "schautrack.chart" . }}
{{ include "schautrack.postgresql.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "schautrack.postgresql.selectorLabels" -}}
app.kubernetes.io/name: {{ include "schautrack.name" . }}-postgresql
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: database
{{- end }}

{{/*
The CNPG read-write Service — the cluster's current primary.

Everything this chart points at the database uses this and only this. CNPG also
publishes -ro (hot standbys) and -r (any instance), and both are wrong here:
NOTIFY does not replicate, so a LISTEN on a standby never fires and the SSE
broker sits on a silent channel forever.
*/}}
{{- define "schautrack.postgresql.rwService" -}}
{{- printf "%s-rw" (include "schautrack.postgresql.fullname" .) }}
{{- end }}

{{/*
Name of the Secret CNPG generates for the application user, and the key in it
holding a ready-made connection URI.

CNPG owns this credential: it is generated at bootstrap and can be rotated by
the operator, so the chart never templates the password and never stores it in
values.yaml. Deployments read DATABASE_URL straight out of this Secret.
*/}}
{{- define "schautrack.postgresql.appSecretName" -}}
{{- if .Values.postgresql.auth.existingSecret }}
{{- .Values.postgresql.auth.existingSecret }}
{{- else }}
{{- printf "%s-app" (include "schautrack.postgresql.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Database URL for everything except CNPG mode.

In CNPG mode there is deliberately no value to render: the URI lives in the
operator-managed Secret and is injected by secretKeyRef, so a password rotation
takes effect without a chart upgrade. The bundled path keeps templating its own
URL exactly as it always has, because changing that would change the Secret
under a running release for no benefit.
*/}}
{{- define "schautrack.databaseUrl" -}}
{{- if include "schautrack.postgresql.isBundled" . }}
{{- printf "postgres://%s:%s@%s:5432/%s" (.Values.postgresql.auth.username | urlquery) (.Values.postgresql.auth.password | urlquery) (include "schautrack.postgresql.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalDatabase.url }}
{{- end }}
{{- end }}

{{/*
The Service the app connects to, whichever engine is running.

CNPG publishes no Service at the Cluster's own name, so the two differ and the
difference is easy to miss — the bundled Service *is* the plain fullname.
*/}}
{{- define "schautrack.postgresql.serviceName" -}}
{{- if include "schautrack.postgresql.isCNPG" . }}
{{- include "schautrack.postgresql.rwService" . }}
{{- else }}
{{- include "schautrack.postgresql.fullname" . }}
{{- end }}
{{- end }}

{{/*
Which in-chart database engine this release runs: "cnpg" or "bundled".

Helm cannot tell a fresh install from an upgrade. A default that resolved to
`cnpg` would therefore move every existing release off the Deployment it has
been running, leaving its data in a PVC nothing mounts any more — the database
would look erased, on an upgrade nobody was warned about.

An earlier draft of this tried to infer the answer from the values file, on the
theory that legacy-only keys prove a pre-3.x release. That was too clever: a
release using a top-level `existingSecret` sets no `postgresql.auth.password`
and none of the Deployment-only keys, so it would have been read as new and
silently migrated. One missed case is one destroyed database, so inference is
the wrong tool.

The default is therefore `bundled` — the boring answer that changes nothing for
anyone — and CloudNativePG is opted into explicitly. Every example in the docs
sets it, so new installs following the documentation get CNPG; a bare
`helm install` with no values keeps the deprecated engine and says so in NOTES.
The default flips in a future major, once CNPG is the well-trodden path.
*/}}
{{- define "schautrack.postgresql.mode" -}}
{{- $mode := .Values.postgresql.mode | default "bundled" }}
{{- if not (has $mode (list "cnpg" "bundled")) }}
{{- fail (printf "postgresql.mode must be \"cnpg\" or \"bundled\", got %q" $mode) }}
{{- end }}
{{- $mode }}
{{- end }}

{{/*
True when this release runs the CloudNativePG Cluster.
*/}}
{{- define "schautrack.postgresql.isCNPG" -}}
{{- and .Values.postgresql.enabled (eq (include "schautrack.postgresql.mode" .) "cnpg") | ternary "true" "" }}
{{- end }}

{{/*
True when this release runs the deprecated bundled Deployment.
*/}}
{{- define "schautrack.postgresql.isBundled" -}}
{{- and .Values.postgresql.enabled (eq (include "schautrack.postgresql.mode" .) "bundled") | ternary "true" "" }}
{{- end }}

{{- define "schautrack.postgresql.validate" -}}
{{- if lt (int (.Values.postgresql.instances | default 1)) 1 }}
{{- fail "postgresql.instances must be at least 1" }}
{{- end }}
{{- /*
  Refuse to switch to cnpg while the bundled PVC still exists.

  Flipping postgresql.mode is a one-word values edit and every example shows it,
  but on its own it is destructive: the PVC leaves the manifest set and Helm
  deletes it in the same pass that creates an empty Cluster. The database is
  gone before anything could have copied it out. Documenting that in
  docs/cloudnativepg.md is not a guard — it only reaches people who read it
  first, and the person most likely to skip it is the one uncommenting
  `mode: cnpg` from the README.

  `lookup` returns empty during `helm template`, `--dry-run` and any
  disconnected render, so this fires only on a real upgrade against a live
  cluster and does not disturb CI or the byte-identical bundled render.

  scripts/migrate-to-cnpg.sh sets the acknowledgement after it has dumped,
  verified the dump is restorable, and annotated the PVC to survive.
*/}}
{{- if and (include "schautrack.postgresql.isCNPG" .)
           (not .Values.postgresql.acknowledgeDataMigration)
           (lookup "v1" "PersistentVolumeClaim" .Release.Namespace (include "schautrack.postgresql.fullname" .)) }}
{{- fail (printf "\n\npostgresql.mode is \"cnpg\", but the bundled PostgreSQL PVC %q still exists in namespace %q.\n\nThis upgrade would DELETE it, along with your database, and start an empty\nCloudNativePG cluster in its place.\n\nMigrate the data first:\n  scripts/migrate-to-cnpg.sh -n %s -r %s\n\nOr, if the data is already elsewhere and the PVC is genuinely disposable, set\npostgresql.acknowledgeDataMigration=true to proceed.\n\nSee docs/cloudnativepg.md.\n" (include "schautrack.postgresql.fullname" .) .Release.Namespace .Release.Namespace .Release.Name) }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "schautrack.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "schautrack.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Recursively render a map of maps/lists/scalars as YAML, indented so block
sequences line up two spaces past their parent key — e.g. exec.command's
list items sit under "command:", not flush with it. Internal to
schautrack.renderProbe below; do not call directly (no handler validation).

This exists instead of the usual `toYaml $val | nindent N` because Helm's
toYaml (sigs.k8s.io/yaml -> yaml.v2) always renders a sequence that's a value
inside a map flush with its key, never indented past it. That's valid YAML
and Kubernetes doesn't care, but it means switching this chart's probes from
a hardcoded block to a values-driven `toYaml` call would have silently
reformatted the exec.command list the postgres probe ships by default —
semantically identical, byte-for-byte different. Recursing key-by-key here
and only ever handing a *bare* list to `nindent` (never a map containing one)
keeps the default output identical to what this chart hardcoded before
probes were overridable, while still accepting any override shape
(httpGet/tcpSocket/exec/grpc + timing fields) uniformly.

`indent` is the absolute column the top-level keys of `.block` start at.
*/}}
{{- define "schautrack.renderProbeYAML" -}}
{{- $indent := .indent -}}
{{- range $k, $v := .block }}
{{- if kindIs "slice" $v }}
{{ printf "%*s" $indent "" }}{{ $k }}:
{{- range $v }}
{{ printf "%*s" (add $indent 2) "" }}- {{ . }}
{{- end }}
{{- else if kindIs "map" $v }}
{{ printf "%*s" $indent "" }}{{ $k }}:
{{- include "schautrack.renderProbeYAML" (dict "block" $v "indent" (add $indent 2)) }}
{{- else }}
{{ printf "%*s" $indent "" }}{{ $k }}: {{ $v }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Validate then render a livenessProbe/readinessProbe-shaped value as YAML.

A Kubernetes Probe accepts exactly one handler (httpGet, tcpSocket, exec, or
grpc); the API server rejects zero or more than one with "may not specify
more than 1 handler type". Helm deep-merges values files with the chart's
defaults, so setting e.g. `tcpSocket` in an override does NOT clear the
default `httpGet` — the merged value ends up with both, which renders fine
but is an invalid object that fails at `kubectl apply`/ArgoCD sync time,
possibly mid-rollout. Counting handler keys here turns that into an
immediate, actionable `helm template`/`helm install` failure instead.

Usage: {{ include "schautrack.renderProbe" (dict "block" .Values.livenessProbe "indent" 12 "name" "livenessProbe") }}
`indent` is the absolute column the top-level keys of `.block` start at.
`name` identifies the probe in the error message (e.g. "livenessProbe",
"postgresql.readinessProbe").
*/}}
{{- define "schautrack.renderProbe" -}}
{{- $block := .block -}}
{{- $name := .name | default "probe" -}}
{{- $handlers := list -}}
{{- range list "httpGet" "tcpSocket" "exec" "grpc" }}
{{- if hasKey $block . }}
{{- $handlers = append $handlers . }}
{{- end }}
{{- end }}
{{- if eq (len $handlers) 0 }}
{{- fail (printf "%s: no probe handler is set (need exactly one of httpGet, tcpSocket, exec, grpc). A probe with no handler is invalid — set one of these keys." $name) }}
{{- else if gt (len $handlers) 1 }}
{{- fail (printf "%s: more than one probe handler is set (%s) — Kubernetes allows exactly one (httpGet, tcpSocket, exec, or grpc). This chart's default already sets one, and Helm deep-merges values files, so adding another handler in an override does not clear it. Keep the one you want and null out the rest, e.g.:\n%s:\n  %s: null" $name (join ", " $handlers) $name (first $handlers)) }}
{{- end }}
{{- include "schautrack.renderProbeYAML" (dict "block" $block "indent" .indent) }}
{{- end -}}
