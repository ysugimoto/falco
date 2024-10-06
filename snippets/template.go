package snippets

var tableTemplate = `
table {{ .Name }} STRING {
	{{- range .Items }}
	"{{ .Key }}": "{{ .Value }}",
	{{- end }}
}
`

var aclTemplate = `
acl {{ .Name }} {
	{{- range .Entries }}
	{{ if .Negated }}!{{ end }}"{{ .Ip }}"{{ if .Subnet }}/{{ .Subnet }}{{ end }};{{ if .Comment }}  # {{ .Comment }}{{ end }}
	{{- end }}
}
`

var backendTemplate = `
backend F_{{ .Name }} {
	{{ if .Address }}.host = "{{.Address}}";{{ end }}
}
`

var directorTemplate = `
director {{ .Name }} {{ .Type | printtype }} {
	{{- if .Retries }}
	.retries = {{ .Retries }};
	{{- end }}
	.quorum = {{ .Quorum }}%;
	{{- range .Backends }}
	{ .backend = F_{{ . }}; .weight = 1; }
	{{- end }}
}
`

// Shield director won't be used in custom VCL so we should ignore linting.
var shieldDirectorTemplate = `
// falco-ignore-next-line
director {{ .Name }} {{ .Type | printtype }} {
	{{- range .Backends }}
	{ .backend = {{ . }}; .weight = 1; }
	{{- end }}
}
`
