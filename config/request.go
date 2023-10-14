package config

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/ysugimoto/twist"
)

type RequestConfig struct {
	RemoteIP       string            `yaml:"remote_ip" json:"remote_ip"`
	RequestHeaders map[string]string `yaml:"headers" json:"headers"`
	Path           string            `yaml:"path" json:"path"`
	UserAgent      string            `yaml:"user_agent" json:"user_agent"`
}

func (r *RequestConfig) SetRequest(req *http.Request) {
	if r.RemoteIP != "" {
		req.RemoteAddr = r.RemoteIP
	}
	if r.Path != "" {
		req.URL.Path = r.Path
	}
	if r.UserAgent != "" {
		req.Header.Set("User-Agent", r.UserAgent)
	}
	for key, val := range r.RequestHeaders {
		req.Header.Set(key, val)
	}
}

func LoadRequestConfig(path string) (*RequestConfig, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	var options []twist.Option
	switch filepath.Ext(path) {
	case ".json":
		options = append(options, twist.WithJson(path))
	case ".yaml", ".yml":
		options = append(options, twist.WithYaml(path))
	default:
		// ignore configuration file
		return nil, nil
	}

	var rc RequestConfig
	if err := twist.Mix(&rc, options...); err != nil {
		return nil, err
	}
	return &rc, nil
}
