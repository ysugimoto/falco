package dap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	godap "github.com/google/go-dap"
	"github.com/ysugimoto/falco/config"
	"github.com/ysugimoto/falco/interpreter"
	icontext "github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/resolver"
	"golang.org/x/sync/errgroup"
)

type session struct {
	conn   *bufio.ReadWriter
	config *config.SimulatorConfig
	cancel context.CancelFunc

	sendQueue chan godap.Message
	sendWg    sync.WaitGroup

	server      *http.Server
	interpreter *interpreter.Interpreter
	debugger    *Debugger

	stateCh chan<- interpreter.DebugState
}

func (s *session) start(ctx context.Context) error {
	s.sendQueue = make(chan godap.Message)

	stateCh := make(chan interpreter.DebugState)
	s.stateCh = stateCh

	s.debugger = newDebugger(stateCh)
	s.debugger.notifyStoppedFunc = s.notifyStoppedEvent
	s.debugger.printFunc = s.printConsole

	ctx, s.cancel = context.WithCancel(ctx)
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return s.sendFromQueue(ctx)
	})

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				if err := ctx.Err(); err != context.Canceled {
					return err
				}

				return nil
			default:
				if err := s.handler(ctx); err != nil {
					return err
				}
			}
		}
	})

	s.sendWg.Wait()
	if err := eg.Wait(); err != io.EOF {
		return err
	}

	return nil
}

func (s *session) close() error {
	s.cancel()

	return s.server.Shutdown(context.Background())
}

func (s *session) handler(ctx context.Context) error {
	msg, err := godap.ReadProtocolMessage(s.conn.Reader)
	if err != nil {
		return err
	}

	s.sendWg.Add(1)
	s.sendWg.Go(func() {
		defer s.sendWg.Done()
		if msg, ok := msg.(godap.RequestMessage); ok {
			s.dispatch(ctx, msg)
		}
	})

	return nil
}

func (s *session) dispatch(_ context.Context, msg godap.RequestMessage) {
	var err error

	switch req := msg.(type) {
	case *godap.AttachRequest:
		err = s.onAttachRequest(req)
	case *godap.BreakpointLocationsRequest:
		s.onBreakpointLocationsRequest(req)
	case *godap.ConfigurationDoneRequest:
		s.onConfigurationDoneRequest(req)
	case *godap.ContinueRequest:
		s.onContinueRequest(req)
	case *godap.EvaluateRequest:
		err = s.onEvaluateRequest(req)
	case *godap.InitializeRequest:
		s.onInitializeRequest(req)
	case *godap.LaunchRequest:
		err = s.onLaunchRequest(req)
	case *godap.NextRequest:
		s.onNextRequest(req)
	case *godap.SetBreakpointsRequest:
		err = s.onSetBreakpointsRequest(req)
	case *godap.StackTraceRequest:
		s.onStackTraceRequest(req)
	case *godap.StepInRequest:
		s.onStepInRequest(req)
	case *godap.StepOutRequest:
		s.onStepOutRequest(req)
	case *godap.TerminateRequest:
		err = s.onTerminateRequest(req)
	case *godap.ThreadsRequest:
		s.onThreadsRequest(req)
	case *godap.VariablesRequest:
		s.onVariablesRequest(req)
	default:
		err = fmt.Errorf("handler not found for request")
	}

	if err != nil {
		s.send(newErrorResponse(msg, err))
	}
}

func (s *session) send(msgs ...godap.Message) {
	for _, msg := range msgs {
		s.sendQueue <- msg
	}
}

func (s *session) sendFromQueue(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != context.Canceled {
				return err
			}

			return nil
		case msg := <-s.sendQueue:
			err := godap.WriteProtocolMessage(s.conn.Writer, msg)
			if err != nil {
				return err
			}

			err = s.conn.Flush()
			if err != nil {
				return err
			}
		}
	}
}

func newEvent(event string) godap.Event {
	return godap.Event{
		ProtocolMessage: godap.ProtocolMessage{
			Type: "event",
		},
		Event: event,
	}
}

func newResponse(reqmsg godap.RequestMessage) godap.Response {
	req := reqmsg.GetRequest()

	return godap.Response{
		ProtocolMessage: godap.ProtocolMessage{
			Type: "response",
		},
		Command:    req.Command,
		RequestSeq: req.Seq,
		Success:    true,
	}
}

func newErrorResponse(reqmsg godap.RequestMessage, err error) *godap.ErrorResponse {
	resp := &godap.ErrorResponse{
		Response: newResponse(reqmsg),
	}
	resp.Success = false
	resp.Message = err.Error()

	return resp
}

type notifyStoppedEventParams struct {
	reason        string
	breakpointIDs []int
}

func (s *session) notifyStoppedEvent(params *notifyStoppedEventParams) {
	s.send(&godap.StoppedEvent{
		Event: newEvent("stopped"),
		Body: godap.StoppedEventBody{
			Reason:   params.reason,
			ThreadId: 1,
		},
	})
}

func (s *session) printConsole(msg string) {
	s.send(&godap.OutputEvent{
		Event: newEvent("output"),
		Body: godap.OutputEventBody{
			Category: "console",
			Output:   fmt.Sprintf("%s\n", msg),
		},
	})
}

func (s *session) onAttachRequest(req *godap.AttachRequest) error {
	return fmt.Errorf("attach not supported")
}

func (s *session) onBreakpointLocationsRequest(req *godap.BreakpointLocationsRequest) {
	bps := s.debugger.listBreakpoints(req.Arguments.Source.Path)
	bpls := make([]godap.BreakpointLocation, 0, len(bps))

	for _, bp := range bps {
		bpls = append(bpls, godap.BreakpointLocation{
			Line: bp,
		})
	}

	s.send(&godap.BreakpointLocationsResponse{
		Response: newResponse(req),
		Body: godap.BreakpointLocationsResponseBody{
			Breakpoints: bpls,
		},
	})
}

func (s *session) onConfigurationDoneRequest(req *godap.ConfigurationDoneRequest) {
	s.send(&godap.ConfigurationDoneResponse{
		Response: newResponse(req),
	})
}

func (s *session) onContinueRequest(req *godap.ContinueRequest) {
	s.stateCh <- interpreter.DebugPass

	s.send(&godap.ContinueResponse{
		Response: newResponse(req),
	})
}

func (s *session) onEvaluateRequest(req *godap.EvaluateRequest) error {
	return fmt.Errorf("attach not supported")
}

func (s *session) onInitializeRequest(req *godap.InitializeRequest) {
	s.send(&godap.InitializedEvent{
		Event: newEvent("initialized"),
	}, &godap.InitializeResponse{
		Response: newResponse(req),
		Body: godap.Capabilities{
			SupportsBreakpointLocationsRequest: true,
			SupportsCancelRequest:              true,
			SupportsConfigurationDoneRequest:   true,
			SupportsTerminateRequest:           true,
		},
	})
}

type LaunchArguments struct {
	MainVCL      string   `json:"mainVCL"`
	IncludePaths []string `json:"includePaths"`
}

func (s *session) onLaunchRequest(req *godap.LaunchRequest) error {
	var args *LaunchArguments
	err := json.Unmarshal(req.GetArguments(), &args)
	if err != nil {
		return err
	}

	log.Printf("launch request: %+v", args)

	resolvers, err := resolver.NewFileResolvers(args.MainVCL, args.IncludePaths)
	if err != nil {
		return err
	}
	if len(resolvers) != 1 {
		return fmt.Errorf("invalid number of resolvers")
	}

	s.interpreter = interpreter.New(
		icontext.WithResolver(resolvers[0]),
	)
	s.interpreter.Debugger = s.debugger

	s.launchServer()

	log.Print("debugger launched")

	s.send(&godap.LaunchResponse{
		Response: newResponse(req),
	})

	return nil
}

func (s *session) launchServer() {
	isTLS := s.config.KeyFile != "" && s.config.CertFile != ""

	protocol := "http"
	if isTLS {
		protocol = "https"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			s.send(&godap.TerminatedEvent{
				Event: newEvent("terminated"),
			})

			s.close()
		}()

		s.interpreter.ServeHTTP(w, r)
	})

	s.server = &http.Server{
		Handler: mux,
		Addr:    fmt.Sprintf(":%d", s.config.Port),
	}

	go func() {
		if isTLS {
			if err := s.server.ListenAndServeTLS(
				s.config.CertFile,
				s.config.KeyFile,
			); err != nil {
				s.cancel()
			}
		} else {
			if err := s.server.ListenAndServe(); err != nil {
				s.cancel()
			}
		}
	}()

	s.printConsole(
		fmt.Sprintf(
			"Waiting Request on %s://localhost:%d...",
			protocol,
			s.config.Port,
		),
	)
}

func (s *session) onNextRequest(req *godap.NextRequest) {
	s.stateCh <- interpreter.DebugStepOver

	s.send(&godap.NextResponse{
		Response: newResponse(req),
	})
}

func (s *session) onSetBreakpointsRequest(req *godap.SetBreakpointsRequest) error {
	if req.Arguments.Source.Path == "" {
		return fmt.Errorf("unable to set breakpoints")
	}

	s.debugger.clearBreakpoints(req.Arguments.Source.Path)

	breakpoints := make([]godap.Breakpoint, 0, len(req.Arguments.Breakpoints))

	for _, bp := range req.Arguments.Breakpoints {
		res := s.debugger.setBreakpoint(req.Arguments.Source.Path, bp.Line)

		breakpoints = append(breakpoints, godap.Breakpoint{
			Id:       res.id,
			Source:   &godap.Source{Path: req.Arguments.Source.Path},
			Line:     bp.Line,
			Verified: true,
		})
	}

	s.send(&godap.SetBreakpointsResponse{
		Response: newResponse(req),
		Body: godap.SetBreakpointsResponseBody{
			Breakpoints: breakpoints,
		},
	})

	return nil
}

func (s *session) onStackTraceRequest(req *godap.StackTraceRequest) {
	stacks := s.debugger.listStacks()

	frames := make([]godap.StackFrame, len(stacks))

	for i, stack := range stacks {
		frames[len(frames)-i-1] = godap.StackFrame{
			Id:   stack.id,
			Name: stack.name,
			Source: &godap.Source{
				Path: stack.path,
			},
			Line:   stack.line,
			Column: 1,
		}
	}

	s.send(&godap.StackTraceResponse{
		Response: newResponse(req),
		Body: godap.StackTraceResponseBody{
			StackFrames: frames,
			TotalFrames: len(frames),
		},
	})
}

func (s *session) onStepInRequest(req *godap.StepInRequest) {
	s.stateCh <- interpreter.DebugStepIn

	s.send(&godap.StepInResponse{
		Response: newResponse(req),
	})
}

func (s *session) onStepOutRequest(req *godap.StepOutRequest) {
	s.stateCh <- interpreter.DebugStepOut

	s.send(&godap.StepOutResponse{
		Response: newResponse(req),
	})
}

func (s *session) onTerminateRequest(req *godap.TerminateRequest) error {
	s.send(&godap.TerminateResponse{
		Response: newResponse(req),
	})

	return s.close()
}

func (s *session) onThreadsRequest(req *godap.ThreadsRequest) {
	s.send(&godap.ThreadsResponse{
		Response: newResponse(req),
		Body: godap.ThreadsResponseBody{
			Threads: []godap.Thread{{
				Id:   1,
				Name: "mainVCL",
			}},
		},
	})
}

func (s *session) onVariablesRequest(req *godap.VariablesRequest) {
	s.send(&godap.VariablesResponse{
		Response: newResponse(req),
		Body: godap.VariablesResponseBody{
			Variables: []godap.Variable{},
		},
	})
}
