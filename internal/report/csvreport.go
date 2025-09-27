// internal/report/csvreport.go
package report

import (
	"encoding/csv"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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
func WriteCSV(path string, rows []Row, logger *slog.Logger) error {
	dir := filepath.Dir(path)
	if logger != nil {
		logger.Debug("preparing output directory", "dir", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		if logger != nil {
			logger.Error("failed to create output dir", "dir", dir, "err", err)
		}
		return fmt.Errorf("prepare output dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*.csv")
	if err != nil {
		if logger != nil {
			logger.Error("create temp file failed", "dir", dir, "err", err)
		}
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if logger != nil {
		logger.Debug("created temp file", "tmp", tmpPath)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	w := csv.NewWriter(tmp)

	// header
	if err := w.Write(csvHeaders()); err != nil {
		if logger != nil {
			logger.Error("write header failed", "err", err)
		}
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
			if logger != nil {
				logger.Error("write row failed", "row", i+1, "err", err)
			}
			return fmt.Errorf("write row %d: %w", i+1, err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		if logger != nil {
			logger.Error("csv flush error", "err", err)
		}
		return fmt.Errorf("flush csv: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		if logger != nil {
			logger.Error("fsync temp file failed", "tmp", tmpPath, "err", err)
		}
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		if logger != nil {
			logger.Error("close temp file failed", "tmp", tmpPath, "err", err)
		}
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if logger != nil {
			logger.Error("atomic rename failed", "tmp", tmpPath, "dest", path, "err", err)
		}
		return fmt.Errorf("atomic rename: %w", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		if logger != nil {
			logger.Warn("chmod failed", "path", path, "err", err)
		}
		return fmt.Errorf("chmod: %w", err)
	}
	if logger != nil {
		logger.Info("csv file written successfully", "path", path, "rows", len(rows))
	}
	return nil
}
