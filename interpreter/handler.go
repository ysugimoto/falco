package interpreter

import (
	"net/http"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/limitations"
)

// Implements http.Handler
func (i *Interpreter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.Debugger.Message("Request Incoming =========>")
	defer i.Debugger.Message("<========= Request finished")

	if err := i.ProcessInit(r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	handleError := func(err error) {
		// If debug is true, print with stacktrace
		i.process.Error = err
		if re, ok := errors.Cause(err).(*exception.Exception); ok {
			i.Debugger.Message(re.Error())
		} else {
			i.Debugger.Message(err.Error())
		}
	}

	if err := i.ProcessRecv(); err != nil {
		handleError(err)
	} else if err := limitations.CheckFastlyResponseLimit(i.ctx.Response); err != nil {
		handleError(err)
	}

	i.process.Restarts = i.ctx.Restarts
	i.process.Backend = i.ctx.Backend
	if i.process.Error != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	out, err := i.process.Finalize(i.ctx.Response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out) // nolint:errcheck
}
