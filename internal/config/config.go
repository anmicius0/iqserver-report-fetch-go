// internal/config/config.go
package config

import (
	"github.com/caarlos0/env/v11"
	"github.com/go-playground/validator/v10"
	"github.com/joho/godotenv"
)

type Config struct {
	// IQ Server config
	IQServerURL string `env:"IQ_SERVER_URL,required" validate:"required,url"`
	IQUsername  string `env:"IQ_USERNAME,required" validate:"required"`
	IQPassword  string `env:"IQ_PASSWORD,required" validate:"required"`

	// Task config
	OrganizationID string `env:"ORGANIZATION_ID" validate:"omitempty"`

	// IO config
	OutputDir string `validate:"required"`
}

func Load() (*Config, error) {
	_ = godotenv.Load("config/.env")

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	cfg.OutputDir = "reports_output"

	// Validate the config
	validate := validator.New()
	if err := validate.Struct(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}
