package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nemolucky/kaspersky-test-go/internal/adapter/postgres"
	"github.com/nemolucky/kaspersky-test-go/internal/config"
)

func main() {
	if err := run(); err != nil {
		slog.Error("application stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	level := slog.LevelInfo
	if err := level.UnmarshalText([]byte(cfg.App.LogLevel)); err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	dbCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	db, err := postgres.Connect(dbCtx, cfg.Postgres.BuildDSN())
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer db.Close()

	logger.Info("postgres connected")

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.HTTP.Host, cfg.HTTP.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	serverErr := make(chan error, 1)

	go func() {
		logger.Info("http server starting", "addr", server.Addr)
		serverErr <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")

	case err := <-serverErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}

	stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		cfg.HTTP.ShutdownTimeout,
	)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		return fmt.Errorf("shutdown http server: %w", err)
	}

	logger.Info("http server stopped gracefully")

	return nil
}
