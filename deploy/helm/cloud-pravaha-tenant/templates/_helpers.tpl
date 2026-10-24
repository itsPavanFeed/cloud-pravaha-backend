{{- define "tenant.name" -}}{{ .Release.Name }}-tenant{{- end -}}
{{- define "tenant.labels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
cloud-pravaha/tenant: {{ .Values.tenant }}
{{- end -}}
{{- define "pravaha.securityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
runAsUser: 65532
capabilities: { drop: [ALL] }
seccompProfile: { type: RuntimeDefault }
{{- end -}}
