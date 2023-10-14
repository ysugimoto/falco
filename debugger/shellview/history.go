package shellview

const maxHistoryLength = 100

type History struct {
	stack   []string
	pointer int
}

func (h *History) Append(cmd string) {
	h.stack = append(h.stack, cmd)
	if len(h.stack) > maxHistoryLength {
		h.stack = h.stack[1:len(h.stack)]
	}
}

func (h *History) Reset() {
	h.pointer = len(h.stack)
}

func (h *History) Up() string {
	if len(h.stack) == 0 {
		return ""
	}
	h.pointer--
	if h.pointer < 0 {
		h.pointer = 0
	}
	return h.stack[h.pointer]
}

func (h *History) Down() string {
	if len(h.stack) == 0 {
		return ""
	}
	if h.pointer+1 > len(h.stack)-1 {
		h.pointer = len(h.stack)
		return ""
	}
	h.pointer++
	return h.stack[h.pointer]
}
