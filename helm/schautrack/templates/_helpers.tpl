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
Database URL
*/}}
{{- define "schautrack.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgres://%s:%s@%s:5432/%s" (.Values.postgresql.auth.username | urlquery) (.Values.postgresql.auth.password | urlquery) (include "schautrack.postgresql.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.externalDatabase.url }}
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
