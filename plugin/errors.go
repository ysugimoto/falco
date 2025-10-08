package plugin

type LinterRequestError struct {
	Message string
}

func (e *LinterRequestError) Error() string {
	return e.Message
}

type ErrorSeverity int

const (
	ERROR ErrorSeverity = iota + 1
	WARNING
	INFO
)

type Error struct {
	Severity ErrorSeverity
	Message  string
}
