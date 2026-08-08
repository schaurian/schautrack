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
Render a livenessProbe/readinessProbe-shaped value (or any nested map of
maps/lists/scalars) as YAML, indented so block sequences line up two spaces
past their parent key — e.g. exec.command's list items sit under "command:",
not flush with it.

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

Usage: {{ include "schautrack.renderProbe" (dict "block" .Values.livenessProbe "indent" 12) }}
`indent` is the absolute column the top-level keys of `.block` start at.
*/}}
{{- define "schautrack.renderProbe" -}}
{{- $indent := .indent -}}
{{- range $k, $v := .block }}
{{- if kindIs "slice" $v }}
{{ printf "%*s" $indent "" }}{{ $k }}:
{{- range $v }}
{{ printf "%*s" (add $indent 2) "" }}- {{ . }}
{{- end }}
{{- else if kindIs "map" $v }}
{{ printf "%*s" $indent "" }}{{ $k }}:
{{- include "schautrack.renderProbe" (dict "block" $v "indent" (add $indent 2)) }}
{{- else }}
{{ printf "%*s" $indent "" }}{{ $k }}: {{ $v }}
{{- end }}
{{- end }}
{{- end -}}
