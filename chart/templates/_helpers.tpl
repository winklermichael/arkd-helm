{{/*
Expand the name of the chart for arkd.
*/}}
{{- define "arkd.name" -}}
{{- default .Chart.Name .Values.arkd.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Expand the name of the chart for arkdwallet.
*/}}
{{- define "arkdwallet.name" -}}
{{- default "arkdwallet" .Values.arkdwallet.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name for arkd.
*/}}
{{- define "arkd.fullname" -}}
{{- if .Values.arkd.fullnameOverride }}
{{- .Values.arkd.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name "arkd" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create a default fully qualified app name for arkdwallet.
*/}}
{{- define "arkdwallet.fullname" -}}
{{- if .Values.arkdwallet.fullnameOverride }}
{{- .Values.arkdwallet.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name "arkdwallet" | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label for arkd.
*/}}
{{- define "arkd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label for arkdwallet.
*/}}
{{- define "arkdwallet.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels for arkd.
*/}}
{{- define "arkd.labels" -}}
helm.sh/chart: {{ include "arkd.chart" . }}
{{ include "arkd.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Common labels for arkdwallet.
*/}}
{{- define "arkdwallet.labels" -}}
helm.sh/chart: {{ include "arkdwallet.chart" . }}
{{ include "arkdwallet.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for arkd.
*/}}
{{- define "arkd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "arkd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for arkdwallet.
*/}}
{{- define "arkdwallet.selectorLabels" -}}
app.kubernetes.io/name: {{ include "arkdwallet.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use for arkd.
*/}}
{{- define "arkd.serviceAccountName" -}}
{{- if .Values.arkd.serviceAccount.create }}
{{- default (include "arkd.fullname" .) .Values.arkd.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.arkd.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the name of the service account to use for arkdwallet.
*/}}
{{- define "arkdwallet.serviceAccountName" -}}
{{- if .Values.arkdwallet.serviceAccount.create }}
{{- default (include "arkdwallet.fullname" .) .Values.arkdwallet.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.arkdwallet.serviceAccount.name }}
{{- end }}
{{- end }}