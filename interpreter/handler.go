package interpreter

import (
	"io"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/interpreter/exception"
	"github.com/ysugimoto/falco/interpreter/limitations"
	"github.com/ysugimoto/falco/interpreter/variable"
)

// Implements http.Handler
func (i *Interpreter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.Debugger.Message("Request Incoming =========>")
	defer i.Debugger.Message("<========= Request finished")
	// Prevent deadlock if simulator is a backend for itself.
	if strings.Contains(r.Header.Get("Fastly-FF"), variable.FALCO_SERVER_HOSTNAME) {
		http.Error(w, "loop detected", http.StatusServiceUnavailable)
		return
	}
	i.lock.Lock()
	defer i.lock.Unlock()

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

	err := i.ProcessRecv()
	if err != nil {
		handleError(err)
	}
	// Check response limitations in Fastly
	if i.ctx.Response != nil {
		if err := limitations.CheckFastlyResponseLimit(i.ctx.Response); err != nil {
			handleError(err)
		}
	}

	i.process.Restarts = i.ctx.Restarts
	i.process.Backend = i.ctx.Backend

	switch {
	case i.ctx.IsPurgeRequest:
		// If the service received purge request, send accepted response
		i.sendPurgeRequestResponse(w, err)
	case i.ctx.IsActualResponse:
		// If we need to respond actual response, send it
		i.sendResponse(w)
	default:
		// Otherwise, responds process flow JSON
		i.sendProcessResponse(w)
	}
}

func (i *Interpreter) sendProcessResponse(w http.ResponseWriter) {
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

func (i *Interpreter) sendResponse(w http.ResponseWriter) {
	h := w.Header()
	for key, val := range i.ctx.Response.Header {
		for i := range val {
			h.Add(key, val[i])
		}
	}
	w.WriteHeader(i.ctx.Response.StatusCode)
	io.Copy(w, i.ctx.Response.Body) // nolint:errcheck
}

func (i *Interpreter) sendPurgeRequestResponse(w http.ResponseWriter, err error) {
	// https://www.fastly.com/documentation/guides/full-site-delivery/purging/authenticating-api-purge-requests/#purging-urls-with-an-api-token
	w.Header().Set("Content-Type", "application/json")

	// If our runtime could not accept purge request, send error response
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"status": "ng", "id": "falco_purge_rejection"}`) // nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, `{"status": "ok", "id": "falco_purge_acceptance"}`) // nolint:errcheck
}
