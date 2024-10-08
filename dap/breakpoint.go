package dap

import "sync"

type breakpointColl struct {
	breakpoints map[string][]breakpoint // map[path][]breakpoint
	counter     int
	mu          sync.Mutex
}

type breakpoint struct {
	path string
	line int
	id   int
}

func (bpc *breakpointColl) newID() int {
	bpc.counter++
	return bpc.counter
}

func (bpc *breakpointColl) add(path string, line int) breakpoint {
	bpc.mu.Lock()
	defer bpc.mu.Unlock()

	bp := breakpoint{
		path: path,
		line: line,
		id:   bpc.newID(),
	}

	bpc.breakpoints[path] = append(bpc.breakpoints[path], bp)

	return bp
}

func (bpc *breakpointColl) clear(path string) {
	bpc.mu.Lock()
	defer bpc.mu.Unlock()

	delete(bpc.breakpoints, path)
}

func (bpc *breakpointColl) list(path string) []breakpoint {
	bpc.mu.Lock()
	defer bpc.mu.Unlock()

	bps, ok := bpc.breakpoints[path]
	if !ok {
		return []breakpoint{}
	}

	return bps
}

func (bpc *breakpointColl) getBreakpoint(path string, line int) *breakpoint {
	bpc.mu.Lock()
	defer bpc.mu.Unlock()

	bps, ok := bpc.breakpoints[path]
	if !ok {
		return nil
	}

	for _, bp := range bps {
		if bp.line == line {
			return &bp
		}
	}

	return nil
}
