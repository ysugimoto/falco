package dap

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"

	"github.com/ysugimoto/falco/config"
)

type Adapter struct {
	config *config.SimulatorConfig
	session *session
}

func New(sc *config.SimulatorConfig) *Adapter {
	return &Adapter{
		config: sc,
	}
}

func (a *Adapter) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.session = &session{
 		conn: bufio.NewReadWriter(
 			bufio.NewReader(os.Stdin),
 			bufio.NewWriter(os.Stdout),
 		),
		config: a.config,
 	}

	log.SetOutput(io.Discard)

	return a.session.start(ctx)
}
