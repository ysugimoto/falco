package interpreter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/exception"
)

// Implements http.Handler
func (i *Interpreter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := i.ProcessInit(r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handleError := func(err error) {
		// If debug is true, print with stacktrace
		i.process.Error = err
		if i.ctx.Debug {
			fmt.Fprintf(os.Stderr, "%+v\n", err)
		}
		if re, ok := errors.Cause(err).(*exception.Exception); ok {
			i.Debugger.Message(re.Error())
		} else {
			i.Debugger.Message(err.Error())
		}
	}

	if err := i.ProcessRecv(); err != nil {
		handleError(err)
	} else if err := checkFastlyResponseLimit(i.ctx.Response); err != nil {
		handleError(err)
	}

	i.process.Restarts = i.ctx.Restarts
	i.process.Backend = i.ctx.Backend
	if i.process.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(i.process) // nolint: errcheck

	i.Debugger.Message("Reuqest finished.")
}
