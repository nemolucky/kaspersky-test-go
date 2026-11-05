package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/nemolucky/kaspersky-test-go/internal/adapter/postgres"
	"github.com/nemolucky/kaspersky-test-go/internal/config"
	"github.com/nemolucky/kaspersky-test-go/internal/handler"
	"github.com/nemolucky/kaspersky-test-go/internal/usecase"
)

func main() {
	if err := run(); err != nil {
		slog.Error("application failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := config.NewLogger(cfg.App.LogLevel)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	db, err := postgres.Connect(ctx, cfg.Postgres.DSN())
	if err != nil {
		return err
	}
	defer db.Close()

	threatUsecase := usecase.NewThreatUsecase(db)

	threatHandler := handler.NewHandler(
		threatUsecase,
		logger,
	)

	server := &http.Server{
		Addr:         cfg.HTTP.Address(),
		Handler:      threatHandler.Routes(),
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
	}

	serverErr := make(chan error, 1)

	go func() {
		logger.Info("HTTP server started", slog.String("address", server.Addr))

		serverErr <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}

	case <-ctx.Done():
		logger.Info("shutting down HTTP server")
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		cfg.HTTP.ShutdownTimeout,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return err
	}

	logger.Info("HTTP server stopped")

	return nil
}
