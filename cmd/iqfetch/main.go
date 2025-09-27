// cmd/iqfetch/main.go
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/client"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/config"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/services"
)

func main() {
	// Load config from config/.env and environment
	cfg, err := config.Load()
	if err != nil {
		// Log fatal failure to standard error stream, as slog setup hasn't completed yet
		fmt.Fprintf(os.Stderr, "FATAL: failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Open project-root/app.log for append; create if missing
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// Log fatal failure to standard error stream, as slog setup hasn't completed yet
		fmt.Fprintf(os.Stderr, "FATAL: failed to open app.log: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	// Logger setup (duplicate to stdout and file using io.MultiWriter)
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	multiWriter := io.MultiWriter(logFile, os.Stdout)
	logger := slog.New(slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	slog.Info("Loaded configuration",
		"IQServerURL", cfg.IQServerURL,
		"OrganizationID", cfg.OrganizationID,
	)

	// Build client
	slog.Info("Creating IQ client", "url", cfg.IQServerURL)
	iqClient, err := client.NewClient(cfg.IQServerURL, cfg.IQUsername, cfg.IQPassword, slog.Default())
	if err != nil {
		slog.Error("failed to create client", "err", err)
		os.Exit(1)
	}
	slog.Info("IQ client created")

	// Service
	reportService := services.NewIQReportService(cfg, iqClient, slog.Default())
	slog.Info("Report service initialized", "outputDir", cfg.OutputDir)

	// Context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Optional organization filter
	var orgIDPointer *string
	if cfg.OrganizationID != "" {
		orgID := cfg.OrganizationID
		orgIDPointer = &orgID
	}

	// Output filename
	filename := time.Now().Format("2006-01-02_15-04-05") + ".csv"
	slog.Info("Report filename set", "filename", filename)

	// Ensure output directory exists
	_ = os.MkdirAll(cfg.OutputDir, 0o755)

	// Generate report
	slog.Info("Starting report generation", "orgID", cfg.OrganizationID)
	path, err := reportService.GenerateLatestPolicyReport(ctx, orgIDPointer, filename)
	if err != nil {
		slog.Error("report generation failed", "err", err)
		os.Exit(1)
	}

	slog.Info("Report generation completed", "path", filepath.Clean(path))
	fmt.Printf("Wrote report: %s\n", filepath.Clean(path))
}
