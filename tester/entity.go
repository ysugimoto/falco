package tester

import (
	"encoding/json"

	i "github.com/ysugimoto/falco/interpreter"
	"github.com/ysugimoto/falco/interpreter/function/errors"
	"github.com/ysugimoto/falco/lexer"
)

type TestCase struct {
	Name     string
	Group    string
	Error    error
	Scope    string
	Time     int64 // msec order
	Coverage i.Coverage
}

func (t *TestCase) MarshalJSON() ([]byte, error) {
	v := struct {
		Name  string `json:"name"`
		Error string `json:"error,omitempty"`
		Group string `json:"group,omitempty"`
		Scope string `json:"scope"`
		Time  int64  `json:"elapsed_time"`
	}{
		Name:  t.Name,
		Group: t.Group,
		Scope: t.Scope,
		Time:  t.Time,
	}
	if t.Error != nil {
		switch e := t.Error.(type) {
		case *errors.AssertionError:
			v.Error = e.Message
		case *errors.TestingError:
			v.Error = e.Message
		default:
			v.Error = e.Error()
		}
	}
	return json.Marshal(v)
}

type TestResult struct {
	Filename string       `json:"file"`
	Cases    []*TestCase  `json:"suites"`
	Lexer    *lexer.Lexer `json:"-"`
}

func (t *TestResult) IsPassed() bool {
	for i := range t.Cases {
		if t.Cases[i].Error != nil {
			return false
		}
	}
	return true
}

type TestFactory struct {
	Results    []*TestResult
	Statistics *TestCounter
	Coverage   *TestCoverage
	Logs       []string
}

type TestCounter struct {
	Asserts int `json:"asserts"`
	Passes  int `json:"passes"`
	Fails   int `json:"fails"`
}

func NewTestCounter() *TestCounter {
	return &TestCounter{}
}

func (c *TestCounter) Pass() {
	c.Asserts++
	c.Passes++
}

func (c *TestCounter) Fail() {
	c.Asserts++
	c.Fails++
}
