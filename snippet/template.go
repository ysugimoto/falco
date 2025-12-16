package snippet

import (
	"bytes"
	"fmt"
	"regexp"
	"sync"
	"text/template"

	"github.com/pkg/errors"
)

var pool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

// Template helper functions

var invalid *regexp.Regexp = regexp.MustCompile(`\W`)

var helperFuncs = template.FuncMap{
	"printtype": func(dtype int) string {
		switch DirectorType(dtype) {
		case Random:
			return "random"
		case Hash:
			return "hash"
		case Client:
			return "client"
		case Shield:
			return "shield"
		}
		return ""
	},
	"sanitize": func(name string) string {
		return invalid.ReplaceAllString(name, "_")
	},
	"objectify": func(p Phase) string {
		switch p {
		case RequestPhase:
			return "req"
		case CachePhase:
			return "beresp"
		case ResponsePhase:
			return "resp"
		}
		return ""
	},
}

// Template declarations

var dictionaryTemplate = template.Must(
	template.New("dictionary").
		Parse(
			`
table {{ .Name }} STRING {
  {{- range .Items }}
  "{{ .Key }}": "{{ .Value }}",
  {{- end }}
}
`,
		))

var aclTemplate = template.Must(
	template.New("acl").
		Parse(
			`
acl {{ .Name }} {
	{{- range .Entries }}
	{{ if .Negated }}!{{ end }}"{{ .Ip }}"{{ if .Subnet }}/{{ .Subnet }}{{ end }};{{ if .Comment }}  # {{ .Comment }}{{ end }}
	{{- end }}
}
`,
		))

var backendTemplate = template.Must(
	template.New("backend").
		Funcs(helperFuncs).
		Parse(
			`
backend F_{{ .Name | sanitize }} {
	{{ if .Address }}.host = "{{.Address}}";{{ end }}
}
`,
		))

// Director name can be registered including "-" string but invalid in the VCL.
// Fastly will replace its name from "-" to "_" so we should follow it.
var directorTemplate = template.Must(
	template.New("director").
		Funcs(helperFuncs).
		Parse(
			`
director {{ .Name | sanitize }} {{ .Type | printtype }} {
	{{- if .Retries }}
	.retries = {{ .Retries }};
	{{- end }}
	.quorum = {{ .Quorum }}%;
	{{- range .Backends }}
	{ .backend = F_{{ . }}; .weight = 1; }
	{{- end }}
}
`,
		))

// Shield director won't be used in custom VCL so we should ignore linting.
var shieldDirectorTemplate = template.Must(
	template.New("shield").
		Funcs(helperFuncs).
		Parse(
			`
// falco-ignore-next-line
director {{ .Name }} {{ .Type | printtype }} {
	{{- range .Backends }}
	{ .backend = {{ . }}; .weight = 1; }
	{{- end }}
}
`,
		))

var headerTemplate = template.Must(
	template.New("header").
		Funcs(helperFuncs).
		Parse(
			`
{{if .ConditionExpression }}if ({{ .ConditionExpression }}) {{"{"}}{{- end}}
{{if .IgnoreIfSet }}if (!{{ .Type | objectify }}.{{ .Destination }}) {{"{"}}{{- end}}
{{if eq .Action "set" -}}
	set {{ .Type | objectify }}.{{ .Destination }} = {{ .Source }};
{{end -}}

{{- if eq .Action "append" -}}
	if (!{{ .Type | objectify }}.{{ .Destination }}) {{"{"}}
		set {{ .Type | objectify }}.{{ .Destination }} = {{ .Source }};
	{{"}"}} else {{"{"}}
		set {{ .Type | objectify }}.{{ .Destination }} = {{ .Type | objectify }}.{{ .Destination }} {{ .Source }};
	{{"}"}}
{{end -}}

{{- if eq .Action "delete" -}}
	unset {{ .Type | objectify }}.{{ .Destination }};
{{end -}}

{{- if eq .Action "regex" -}}
	set {{ .Type | objectify }}.{{ .Destination }} = regsub({{ .Source }}, "{{ .Regex }}", "{{ .Substitution }}");
{{end -}}

{{- if eq .Action "regex_repeat" -}}
	set {{ .Type | objectify }}.{{ .Destination }} = regsuball({{ .Source }}, "{{ .Regex }}", "{{ .Substitution }}");
{{end -}}

{{if .IgnoreIfSet }}{{"}"}}{{- end}}
{{if .ConditionExpression }}{{"}"}}{{- end}}
`,
		))

var responseObjectConditionTemplate = template.Must(
	template.New("responseobject.condition").
		Parse(
			`
{{if .ConditionExpression}} if ({{ .ConditionExpression}}) {{"{"}}{{- end}}
	error {{ .StatusCode }} "Fastly Internal";
{{if .ConditionExpression }}{{"}"}}{{- end}}
`,
		))

var responseObjectTemplate = template.Must(
	template.New("responseobject").
		Parse(
			`
if (obj.status == {{ .StatusCode }}) {{"{"}}
	set obj.status = {{ .Status }};
	set obj.http.Content-Type = "{{ .ContentType }}";
	synthetic {{"{\""}}{{if .Content }}{{ .Content }}{{else}}{{ .Response }}{{end}}{{"\"}"}};
	return(deliver);
{{"}"}}
`,
		))

// Render functions

func renderDictionary(dict *Dictionary) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	if err := dictionaryTemplate.Execute(buf, dict); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name: fmt.Sprintf("Remote.EdgeDictionary:%s", dict.Name),
		Data: buf.String(),
	}, nil
}

func renderAcl(acl *Acl) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	if err := aclTemplate.Execute(buf, acl); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name: fmt.Sprintf("Remote.Acl:%s", acl.Name),
		Data: buf.String(),
	}, nil
}

func renderBackend(backend *Backend) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	if err := backendTemplate.Execute(buf, backend); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name: fmt.Sprintf("Remote.Backend:%s", backend.Name),
		Data: buf.String(),
	}, nil
}

func renderDirector(director *Director, isShield bool) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	tmpl := directorTemplate
	if isShield {
		tmpl = shieldDirectorTemplate
	}
	if err := tmpl.Execute(buf, director); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name: fmt.Sprintf("Remote.Director:%s", director.Name),
		Data: buf.String(),
	}, nil
}

func renderHeader(header *Header) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	if err := headerTemplate.Execute(buf, header); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name:     fmt.Sprintf("Remote.Header:%s", header.Name),
		Data:     buf.String(),
		Priority: header.Priority,
	}, nil
}

func renderResponseObjectCondition(r *ResponseObject) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	if err := responseObjectConditionTemplate.Execute(buf, r); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name: fmt.Sprintf("Remote.ResponseObject.Condition:%s", r.Name),
		Data: buf.String(),
	}, nil
}

func renderResponseObject(r *ResponseObject) (*Item, error) {
	buf := pool.Get().(*bytes.Buffer) // nolint:errcheck
	defer pool.Put(buf)

	buf.Reset()
	if err := responseObjectTemplate.Execute(buf, r); err != nil {
		return nil, errors.WithStack(err)
	}

	return &Item{
		Name: fmt.Sprintf("Remote.ResponseObject:%s", r.Name),
		Data: buf.String(),
	}, nil
}
