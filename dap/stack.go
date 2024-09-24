package dap

import (
	"sync"
)

type stackColl struct {
	stacks  []stack
	counter int
	mu      sync.Mutex
}

type stack struct {
	name string
	path string
	id   int
	line int
}

func (sc *stackColl) newID() int {
	sc.counter++
	return sc.counter
}

func (sc *stackColl) append(name, path string, line int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.stacks = append(sc.stacks, stack{
		name: name,
		path: path,
		line: line,
		id:   sc.newID(),
	})
}

func (sc *stackColl) list() []stack {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	return sc.stacks
}
