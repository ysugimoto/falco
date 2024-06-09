package linter

import (
	"bytes"
	gocontext "context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/ast/codec"
	"github.com/ysugimoto/falco/plugin"
)

const CustomCommandPrefix = "falco-"

type CustomLinterCall struct {
	name      string
	arguments []string
}

func (c CustomLinterCall) Rule() string {
	v := c.name
	if len(c.arguments) > 0 {
		v += "/" + strings.Join(c.arguments, ".")
	}
	return v
}

// Find custom linter call annotation from leading comment
func parseCustomLinterCall(meta *ast.Meta) []CustomLinterCall {
	var calls []CustomLinterCall

	for i := range meta.Leading {
		l := strings.TrimLeft(meta.Leading[i].Value, " */#")
		if strings.HasPrefix(l, "@") {
			if !strings.HasPrefix(l, "@custom:") {
				continue
			}
			normalized := strings.TrimSpace(strings.TrimPrefix(l, "@custom:"))
			parsed := strings.Split(normalized, " ")
			call := CustomLinterCall{
				name: CustomCommandPrefix + parsed[0],
			}
			if len(parsed) > 1 {
				call.arguments = parsed[1:]
			}
			calls = append(calls, call)
		}
	}

	return calls
}

func (l *Linter) customLint(stmt ast.Statement) {
	// If custom linter found, call it
	customs := parseCustomLinterCall(stmt.GetMeta())
	if len(customs) == 0 {
		return
	}

	bin, err := codec.NewEncoder().Encode(stmt)
	if err != nil {
		l.Error(&LintError{
			Severity: ERROR,
			Token:    stmt.GetMeta().Token,
			Message:  fmt.Sprintf("Encode error for custom linter: %s", err),
		})
		return
	}

	c := gocontext.Background()

	var wg sync.WaitGroup
	for i := range customs {
		wg.Add(1)
		go func(call CustomLinterCall) {
			defer wg.Done()

			custom, err := exec.LookPath(call.name)
			if err != nil {
				l.Error(CustomLinterCommandNotFound(call.name, stmt.GetMeta()))
				return
			}
			cc, timeout := gocontext.WithTimeout(c, 5*time.Second)
			defer timeout()

			stderr := &bytes.Buffer{}
			cmd := exec.CommandContext(cc, custom, call.arguments...)
			cmd.Stdin = bytes.NewReader(bin)
			cmd.Stderr = stderr
			result, err := cmd.Output()
			if err != nil {
				l.Error(CustomLinterCommandFailed(stderr.String(), stmt.GetMeta()))
				return
			}
			var resp plugin.LinterResponse
			if err := json.Unmarshal(result, &resp); err != nil {
				l.Error(CustomLinterCommandFailed(
					fmt.Sprintf("Custom Linter %s did not respond correct message", custom),
					stmt.GetMeta(),
				))
				return
			}
			for i := range resp.Errors {
				l.Error(FromPluginError(resp.Errors[i], stmt.GetMeta()))
			}
		}(customs[i])
	}

	wg.Wait()
}
