package config

type AppConfig struct {
	Env      string `env:"APP_ENV" envDefault:"development"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"debug"`
}
