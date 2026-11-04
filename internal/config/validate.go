package config

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}

	switch c.App.Env {
	case "development", "production", "test":
	default:
		return fmt.Errorf("invalid APP_ENV: %q", c.App.Env)
	}

	switch strings.ToLower(c.App.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid LOG_LEVEL: %q", c.App.LogLevel)
	}

	if err := validatePort(c.HTTP.Port); err != nil {
		return fmt.Errorf("invalid HTTP_PORT: %w", err)
	}

	if ip := net.ParseIP(c.HTTP.Host); ip == nil {
		return fmt.Errorf("invalid HTTP_HOST: %q", c.HTTP.Host)
	}

	if err := validateDuration("HTTP_READ_TIMEOUT", c.HTTP.ReadTimeout); err != nil {
		return err
	}

	if err := validateDuration("HTTP_WRITE_TIMEOUT", c.HTTP.WriteTimeout); err != nil {
		return err
	}

	if err := validateDuration("HTTP_IDLE_TIMEOUT", c.HTTP.IdleTimeout); err != nil {
		return err
	}

	if err := validateDuration("HTTP_SHUTDOWN_TIMEOUT", c.HTTP.ShutdownTimeout); err != nil {
		return err
	}

	if strings.TrimSpace(c.Postgres.Host) == "" {
		return fmt.Errorf("POSTGRES_HOST is required")
	}

	if err := validatePort(c.Postgres.Port); err != nil {
		return fmt.Errorf("invalid POSTGRES_PORT: %w", err)
	}

	if strings.TrimSpace(c.Postgres.User) == "" {
		return fmt.Errorf("POSTGRES_USER is required")
	}

	if c.Postgres.Password == "" {
		return fmt.Errorf("POSTGRES_PASSWORD is required")
	}

	if strings.TrimSpace(c.Postgres.DB) == "" {
		return fmt.Errorf("POSTGRES_DB is required")
	}

	switch c.Postgres.SSLMode {
	case "disable", "allow", "prefer", "require", "verify-ca", "verify-full":
	default:
		return fmt.Errorf("invalid POSTGRES_SSL: %q", c.Postgres.SSLMode)
	}

	return nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("port must be a number: %w", err)
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	return nil
}

func validateDuration(name string, value time.Duration) error {
	if value <= 0 {
		return fmt.Errorf("%s must be greater than zero", name)
	}

	return nil
}
