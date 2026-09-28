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
{{- else if or .Values.secrets.vaultKey .Values.secrets.license .Values.secrets.relayEnrollSecret .Values.secrets.clusterSharedSecret -}}
true
{{- end -}}
{{- end -}}

{{- define "endoriumfort.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
