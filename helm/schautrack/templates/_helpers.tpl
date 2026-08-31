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
Database URL, for the external-database case only.

In CNPG mode there is deliberately no value to render here: the URI lives in
the operator-managed Secret above and is injected by secretKeyRef, so that a
password rotation does not require a chart upgrade to take effect.
*/}}
{{- define "schautrack.databaseUrl" -}}
{{- .Values.externalDatabase.url }}
{{- end }}

{{/*
Reject values that were removed in chart 3.0.0.

These keys configured the single-Pod postgres Deployment the chart used to
ship. Silently ignoring them is the dangerous failure: `persistence.existingClaim`
in particular reads as "keep my data", and a chart that accepted it while
provisioning an empty CNPG volume would look like it had eaten the database.
Failing the render is the only honest answer.
*/}}
{{- define "schautrack.postgresql.validate" -}}
{{- $removed := dict
  "image" "postgresql.image"
  "persistence" "postgresql.persistence"
  "podSecurityContext" "postgresql.podSecurityContext"
  "securityContext" "postgresql.securityContext"
  "livenessProbe" "postgresql.livenessProbe"
  "readinessProbe" "postgresql.readinessProbe"
  "podAnnotations" "postgresql.podAnnotations"
-}}
{{- range $key, $path := $removed }}
{{- if hasKey $.Values.postgresql $key }}
{{- fail (printf "\n\nschautrack chart 3.0.0 replaced the bundled PostgreSQL Deployment with a CloudNativePG Cluster.\n\n  %s is no longer supported and was ignored by this render.\n\nRemove it from your values. The CNPG equivalents are postgresql.instances,\npostgresql.storage, postgresql.resources and postgresql.parameters.\n\nIf you are upgrading an existing install, DO NOT upgrade in place: your data\nlives in a PVC this chart no longer manages. Follow docs/cloudnativepg.md,\nwhich migrates the data first and verifies the row counts before cutover.\n" $path) }}
{{- end }}
{{- end }}
{{- if hasKey .Values.postgresql.auth "password" }}
{{- fail "\n\nschautrack chart 3.0.0: postgresql.auth.password is no longer used.\n\nCloudNativePG generates and owns the application credential. Remove the key.\nTo supply your own, set postgresql.auth.existingSecret to a Secret of type\nkubernetes.io/basic-auth with username and password keys.\n" }}
{{- end }}
{{- if lt (int .Values.postgresql.instances) 1 }}
{{- fail "postgresql.instances must be at least 1" }}
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
