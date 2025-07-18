package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cyberok-org/cokmap/internal/cokmap"
)

var (
	version string
)

func main() {
	flag.Usage = func() {
		fmt.Printf("\033[32mcokmap %s\n\033[0m", version)
		flag.PrintDefaults()
	}
	flag.Parse()
	fmt.Printf("\033[32mcokmap v%s\n\033[0m", version)

	cfg := NewCfg()
	mainCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(mainCtx, cfg); err != nil {
		slog.Info("scanner shutdown", "error", err)
	}
}

func run(ctx context.Context, cfg *cokmap.Config) error {
	signalHandler := make(chan os.Signal, 1)
	signal.Notify(signalHandler, os.Interrupt, syscall.SIGTERM)

	done := make(chan struct{})
	defer close(done)
	go func() {
		start(ctx, cfg)
		done <- struct{}{}
	}()

	go func() {
		<-signalHandler
		done <- struct{}{}
	}()

	<-done

	return nil
}
