{{/* Chart name (overridable). */}}
{{- define "endoriumfort.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully qualified app name. */}}
{{- define "endoriumfort.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "endoriumfort.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "endoriumfort.labels" -}}
helm.sh/chart: {{ include "endoriumfort.chart" . }}
{{ include "endoriumfort.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "endoriumfort.selectorLabels" -}}
app.kubernetes.io/name: {{ include "endoriumfort.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "endoriumfort.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "endoriumfort.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret holding sensitive env (existing or rendered). */}}
{{- define "endoriumfort.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- include "endoriumfort.fullname" . -}}
{{- end -}}
{{- end -}}

{{/* True when at least one inline secret value is set (render a Secret). */}}
{{- define "endoriumfort.renderSecret" -}}
{{- if .Values.secrets.existingSecret -}}
{{- else if or .Values.secrets.vaultKey .Values.secrets.license .Values.secrets.relayEnrollSecret .Values.secrets.clusterSharedSecret .Values.secrets.siemWebhookToken .Values.secrets.siemSplunkToken .Values.database.postgresql.dsn -}}
true
{{- end -}}
{{- end -}}

{{- define "endoriumfort.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* ── File share service (separate Deployment) ── */}}
{{- define "endoriumfort.files.fullname" -}}
{{- printf "%s-files" (include "endoriumfort.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Distinct name label: the bastion Service must never select these pods. */}}
{{- define "endoriumfort.files.selectorLabels" -}}
app.kubernetes.io/name: {{ include "endoriumfort.name" . }}-files
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "endoriumfort.files.labels" -}}
helm.sh/chart: {{ include "endoriumfort.chart" . }}
{{ include "endoriumfort.files.selectorLabels" . }}
app.kubernetes.io/component: fileshare
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "endoriumfort.files.secretName" -}}
{{- if .Values.fileshare.existingSecret -}}
{{- .Values.fileshare.existingSecret -}}
{{- else -}}
{{- printf "%s-key" (include "endoriumfort.files.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "endoriumfort.files.image" -}}
{{- $tag := default (default .Chart.AppVersion .Values.image.tag) .Values.fileshare.image.tag -}}
{{- printf "%s:%s" .Values.fileshare.image.repository $tag -}}
{{- end -}}

{{/* Fully qualified: nginx resolves it per request, without search domains. */}}
{{- define "endoriumfort.files.upstream" -}}
{{- printf "http://%s.%s.svc.%s:8090" (include "endoriumfort.files.fullname" .) .Release.Namespace .Values.clusterDomain -}}
{{- end -}}
