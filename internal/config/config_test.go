// internal/config/config_test.go
package config

import (
	"os"
	"testing"
)

func TestLoad_WithEnvVars_Succeeds(t *testing.T) {
	t.Setenv("IQ_SERVER_URL", "http://example.com/api/v2")
	t.Setenv("IQ_USERNAME", "user")
	t.Setenv("IQ_PASSWORD", "pass")
	// Ensure ORGANIZATION_ID may be empty
	t.Setenv("ORGANIZATION_ID", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.IQServerURL != "http://example.com/api/v2" {
		t.Errorf("IQServerURL = %q", cfg.IQServerURL)
	}
	if cfg.IQUsername != "user" || cfg.IQPassword != "pass" {
		t.Errorf("credentials not parsed")
	}
	if cfg.OutputDir != "reports_output" {
		t.Errorf("OutputDir = %q", cfg.OutputDir)
	}
}

func TestLoad_MissingRequired_Fails(t *testing.T) {
	// Clear env
	for _, k := range []string{"IQ_SERVER_URL", "IQ_USERNAME", "IQ_PASSWORD", "ORGANIZATION_ID"} {
		os.Unsetenv(k)
	}
	if _, err := Load(); err == nil {
		t.Fatalf("expected error for missing required env")
	}
}
