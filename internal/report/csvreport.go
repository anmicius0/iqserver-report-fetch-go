// internal/report/csvreport.go
package report

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rs/zerolog"
)

// Row represents a single policy violation row for CSV output.
type Row struct {
	Application    string
	Organization   string
	Policy         string
	Component      string
	Threat         int
	PolicyAction   string
	ConstraintName string
	Condition      string
	CVE            string
}

// csvHeaders returns the CSV header row in the required order.
func csvHeaders() []string {
	return []string{
		"No.",
		"Application",
		"Organization",
		"Policy",
		"Component",
		"Threat",
		"Policy/Action",
		"Constraint Name",
		"Condition",
		"CVE",
	}
}

// WriteCSV writes rows to a CSV file at path, ensuring the directory exists
// and performing an atomic rename for safety.
func WriteCSV(path string, rows []Row, logger zerolog.Logger) error {
	dir := filepath.Dir(path)
	logger.Debug().Str("dir", dir).Msg("preparing output directory")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error().Err(err).Str("dir", dir).Msg("failed to create output dir")
		return fmt.Errorf("prepare output dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*.csv")
	if err != nil {
		logger.Error().Err(err).Str("dir", dir).Msg("create temp file failed")
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	logger.Debug().Str("tmp", tmpPath).Msg("created temp file")
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	w := csv.NewWriter(tmp)

	// header
	if err := w.Write(csvHeaders()); err != nil {
		logger.Error().Err(err).Msg("write header failed")
		return fmt.Errorf("write header: %w", err)
	}

	// rows
	for i, r := range rows {
		record := []string{
			strconv.Itoa(i + 1),
			r.Application,
			r.Organization,
			r.Policy,
			r.Component,
			strconv.Itoa(r.Threat),
			r.PolicyAction,
			r.ConstraintName,
			r.Condition,
			r.CVE,
		}
		if err := w.Write(record); err != nil {
			logger.Error().Err(err).Int("row", i+1).Msg("write row failed")
			return fmt.Errorf("write row %d: %w", i+1, err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		logger.Error().Err(err).Msg("csv flush error")
		return fmt.Errorf("flush csv: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		logger.Error().Err(err).Str("tmp", tmpPath).Msg("fsync temp file failed")
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		logger.Error().Err(err).Str("tmp", tmpPath).Msg("close temp file failed")
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		logger.Error().Err(err).Str("tmp", tmpPath).Str("dest", path).Msg("atomic rename failed")
		return fmt.Errorf("atomic rename: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		logger.Warn().Err(err).Str("path", path).Msg("chmod failed")
		return fmt.Errorf("chmod: %w", err)
	}
	logger.Info().Str("path", path).Int("rows", len(rows)).Msg("csv file written successfully")
	return nil
}
