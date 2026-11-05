package config

import (
	"fmt"
	"net/url"
)

type PostgresConfig struct {
	Host     string `env:"POSTGRES_HOST,required"`
	Port     string `env:"POSTGRES_PORT" envDefault:"5432"`
	User     string `env:"POSTGRES_USER,required"`
	Password string `env:"POSTGRES_PASSWORD,required"`
	DB       string `env:"POSTGRES_DB,required"`
	SSLMode  string `env:"POSTGRES_SSL" envDefault:"disable"`
}

func (pc PostgresConfig) DSN() string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(pc.User, pc.Password),
		Host:   fmt.Sprintf("%s:%s", pc.Host, pc.Port),
		Path:   pc.DB,
	}

	q := u.Query()
	q.Set("sslmode", pc.SSLMode)
	u.RawQuery = q.Encode()

	return u.String()
}
