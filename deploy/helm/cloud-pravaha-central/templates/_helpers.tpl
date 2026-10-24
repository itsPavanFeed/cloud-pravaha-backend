{{- define "central.name" -}}{{ .Release.Name }}-central{{- end -}}
{{- define "central.labels" -}}
app.kubernetes.io/name: cloud-pravaha-central
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}
{{- define "central.selector" -}}
app.kubernetes.io/name: cloud-pravaha-central
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "pravaha.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
capabilities: { drop: [ALL] }
seccompProfile: { type: RuntimeDefault }
{{- end -}}
