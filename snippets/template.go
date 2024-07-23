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

// remote director should only have a shield type
var directorTemplate = `
director {{ .Name }} {{ .Type | printtype }} {
	{{- range .Backends }}
	{ .backend = {{ . }}; .weight = 1; }
	{{- end }}
}
`
