package main

import (
	"errors"
	"testing"
)

type mockResolver struct {
	dependency   map[string]string
	main         string
	acls         []Acl
	backends     []Backend
	dictionaries []Dictionary
}

func (m *mockResolver) Acls() ([]Acl, error) {
	return m.acls, nil
}

func (m *mockResolver) Backends() ([]Backend, error) {
	return m.backends, nil
}

func (m *mockResolver) Dictionaries() ([]Dictionary, error) {
	return m.dictionaries, nil
}

func (m *mockResolver) MainVCL() (*VCL, error) {
	return &VCL{
		Name: "main.vcl",
		Data: m.main,
	}, nil
}

func (m *mockResolver) Resolve(module string) (*VCL, error) {
	if v, ok := m.dependency[module]; !ok {
		return nil, errors.New(module + " is not defined")
	} else {
		return &VCL{
			Name: module + ".vcl",
			Data: v,
		}, nil
	}
}

func (m *mockResolver) Name() string {
	return ""
}

func TestResolveExternalWithExternalProperties(t *testing.T) {
	mock := &mockResolver{
		main: `
		sub vcl_recv {
			#FASTLY RECV
			if (req.http.foo ~ acl_foo && table.contains(table_foo, "foo")){
				set req.backend = F_backend_foo;
			}
		 }
		`,
		acls:         []Acl{Acl{Name: "acl_foo"}},
		backends:     []Backend{Backend{Name: "F_backend_foo"}},
		dictionaries: []Dictionary{Dictionary{Name: "table_foo"}},
	}

	r, err := NewRunner(mock, &Config{V: true})
	if err != nil {
		t.Errorf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run()
	if err != nil {
		t.Errorf("Unexpected Run() error: %s", err)
		return
	}
	if ret.Infos > 0 {
		t.Errorf("Infos expects 0, got %d", ret.Infos)
	}
	if ret.Warnings != 0 {
		t.Errorf("Warning expects 0, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
}

func TestResolveIncludeStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
sub foo {
	set req.backend = httpbin_org;
}

sub bar {
	set req.http.Foo = "bar";
}
			`,
		},
		main: `
backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
}

include "deps01";

sub vcl_recv {
   #FASTLY RECV
   call foo;
}
		`,
	}
	r, err := NewRunner(mock, &Config{V: true})
	if err != nil {
		t.Errorf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run()
	if err != nil {
		t.Errorf("Unexpected Run() error: %s", err)
		return
	}
	if ret.Infos > 0 {
		t.Errorf("Infos expects 0, got %d", ret.Infos)
	}
	// Above VCL should have one warning that subroutine "bar" is not defined
	if ret.Warnings != 1 {
		t.Errorf("Warning expects 0, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
	if len(ret.Vcl.AST.Statements) != 4 {
		t.Errorf("Parsed VCL should have 4 statements, got %d", len(ret.Vcl.AST.Statements))
	}
}

func TestResolveNestedIncludeStatement(t *testing.T) {
	mock := &mockResolver{
		dependency: map[string]string{
			"deps01": `
include "deps02";
			`,
			"deps02": `
sub foo {
	set req.backend = httpbin_org;
}
			`,
		},
		main: `
backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
}

include "deps01";

sub vcl_recv {
   #FASTLY RECV
   call foo;
}
		`,
	}
	r, err := NewRunner(mock, &Config{V: true})
	if err != nil {
		t.Errorf("Unexpected runner creation error: %s", err)
		return
	}
	ret, err := r.Run()
	if err != nil {
		t.Errorf("Unexpected Run() error: %s", err)
		return
	}
	if ret.Infos > 0 {
		t.Errorf("Infos expects 0, got %d", ret.Infos)
	}
	if ret.Warnings > 0 {
		t.Errorf("Warning expects 0, got %d", ret.Warnings)
	}
	if ret.Errors > 0 {
		t.Errorf("Errors expects 0, got %d", ret.Errors)
	}
	if len(ret.Vcl.AST.Statements) != 3 {
		t.Errorf("Parsed VCL should have 3 statements, got %d", len(ret.Vcl.AST.Statements))
	}
}
