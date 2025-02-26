package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/pkg/errors"
)

const (
	fastlyDocDomain = "https://developer.fastly.com"
)

type Variable struct {
	name string
	url  string
}

type Function struct {
	name string
	url  string
}

func main() {
	ctx, timeout := context.WithTimeout(context.Background(), 5*time.Minute)
	defer timeout()

	variables, functions, err := _main(ctx)
	if err != nil {
		panic(err)
	}

	if len(variables) > 0 {
		fmt.Fprintln(os.Stdout, "====== Lacked predefiend variables found ======")
		for _, v := range variables {
			fmt.Fprintf(os.Stdout, "%s: %s\n", v.name, v.url)
		}
		fmt.Fprintln(os.Stdout, "")
	}
	if len(functions) > 0 {
		fmt.Fprintln(os.Stdout, "====== Lacked builtin functions found ======")
		for _, v := range functions {
			fmt.Fprintf(os.Stdout, "%s: %s\n", v.name, v.url)
		}
		fmt.Fprintln(os.Stdout, "")
	}
}

func _main(ctx context.Context) ([]Variable, []Function, error) {
	variables, err := factoryVariables(ctx)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	lackedVariables, err := checkVariables(variables)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	functions, err := factoryFunctions(ctx)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	lackedFunctions, err := checkFunctions(functions)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	return lackedVariables, lackedFunctions, nil
}
