// internal/services/iqreport.go
package services

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"github.com/anmicius0/iqserver-report-fetch-go/internal/client"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/config"
	"github.com/anmicius0/iqserver-report-fetch-go/internal/report"
)

// IQReportService orchestrates fetching data and exporting CSV reports.
type IQReportService struct {
	cfg    *config.Config
	cl     *client.Client
	logger *slog.Logger
}

// AppReportResult holds the violation rows and any error encountered
// while processing a single application concurrently.
type AppReportResult struct {
	Rows []report.Row
	Err  error
}

// NewIQReportService constructs a new service.
func NewIQReportService(cfg *config.Config, cl *client.Client, logger *slog.Logger) *IQReportService {
	return &IQReportService{cfg: cfg, cl: cl, logger: logger}
}

// GenerateLatestPolicyReport fetches latest policy violations for applications (optionally filtered by orgID)
// and writes a CSV to cfg.OutputDir/filename. It returns the absolute file path.
func (s *IQReportService) GenerateLatestPolicyReport(ctx context.Context, orgID *string, filename string) (string, error) {
	s.logger.Info("GenerateLatestPolicyReport invoked", "orgID", orgID, "filename", filename)

	// =================================================================
	// 1. APPLICATION AND ORGANIZATION FETCHING (Sequential Setup)
	// =================================================================

	// Fetch application list
	apps, err := s.cl.GetApplications(ctx, orgID)
	if err != nil {
		s.logger.Error("failed to retrieve application list", "orgID", orgID, "err", err)
		return "", fmt.Errorf("get applications: %w", err)
	}
	s.logger.Info("Fetched applications", "count", len(apps))

	if len(apps) == 0 {
		s.logger.Warn("Task finished: no applications found matching criteria", "orgID", orgID)
		return "", fmt.Errorf("no applications found")
	}

	// Fetch organizations to create an ID-to-name map
	orgs, err := s.cl.GetOrganizations(ctx)
	if err != nil {
		s.logger.Error("failed to retrieve organization list", "err", err)
		return "", fmt.Errorf("get organizations: %w", err)
	}
	orgIDToName := make(map[string]string)
	for _, org := range orgs {
		orgIDToName[org.ID] = org.Name
	}
	s.logger.Info("Created organization ID-to-name map", "count", len(orgIDToName))

	// =================================================================
	// 2. PROCESS APPLICATIONS CONCURRENTLY
	// =================================================================

	// Setup concurrency primitives: semaphore (max 10), channel for results, WaitGroup
	sem := make(chan struct{}, 10) // Bounded semaphore: max 10 concurrent
	resultsChan := make(chan AppReportResult, len(apps))
	var wg sync.WaitGroup

	s.logger.Info("Starting concurrent report fetching for applications", "appsToProcess", len(apps), "maxConcurrent", 10)

	// Launch a goroutine for each application
	for _, a := range apps {
		wg.Add(1)

		// Capture loop variable 'a' for use in the goroutine closure
		app := a

		go func() {
			sem <- struct{}{} // Acquire semaphore
			defer func() {
				<-sem // Release semaphore
				wg.Done()
			}()

			// Check for context cancellation/timeout early
			if ctx.Err() != nil {
				resultsChan <- AppReportResult{Err: ctx.Err()}
				return
			}

			appLogger := s.logger.With("appPublicID", app.PublicID, "appInternalID", app.ID)

			// 2a. Fetch latest report info
			reportInfo, err := s.cl.GetLatestReportInfo(ctx, app.ID)
			if err != nil {
				resultsChan <- AppReportResult{Err: fmt.Errorf("latest report for %s: %w", app.PublicID, err)}
				return
			}

			// Skip if no report available
			if reportInfo == nil || strings.TrimSpace(reportInfo.ReportHTMLURL) == "" {
				appLogger.Info("No recent report found for application, skipping")
				resultsChan <- AppReportResult{}
				return
			}

			// 2b. Extract report ID and validate
			_, reportID, found := strings.Cut(reportInfo.ReportHTMLURL, "/report/")
			if !found || reportID == "" {
				resultsChan <- AppReportResult{Err: fmt.Errorf("cannot parse report id from %q", reportInfo.ReportHTMLURL)}
				return
			}
			appLogger.Debug("Parsed report ID", "reportID", reportID, "stage", reportInfo.Stage)

			// 2c. Look up organization name
			orgName, ok := orgIDToName[app.OrganizationID]
			if !ok {
				orgName = app.OrganizationID
				appLogger.Warn("organization name not found, using ID as fallback", "orgID", app.OrganizationID)
			}

			// 2d. Fetch policy violations (Returns []client.ViolationRow)
			clientRows, err := s.cl.GetPolicyViolations(ctx, app.PublicID, reportID, orgName)
			if err != nil {
				resultsChan <- AppReportResult{Err: fmt.Errorf("policy violations for %s: %w", app.PublicID, err)}
				return
			}
			appLogger.Debug("Fetched policy violations", "rowsCount", len(clientRows))

			// 2e. Convert client rows to report rows (report.Row is the expected output type)
			reportRows := make([]report.Row, len(clientRows))
			for i, r := range clientRows {
				reportRows[i] = report.Row{
					Application:    r.Application,
					Organization:   r.Organization,
					Policy:         r.Policy,
					Component:      r.Component,
					Threat:         r.Threat,
					PolicyAction:   r.PolicyAction,
					ConstraintName: r.ConstraintName,
					Condition:      r.Condition,
					CVE:            r.CVE,
				}
			}

			// 2f. Send successful results to the channel
			resultsChan <- AppReportResult{Rows: reportRows}
		}()
	}

	// Wait for all goroutines to finish, then close the channel in a non-blocking way
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Aggregate results
	var allViolationRows []report.Row
	for res := range resultsChan {
		if res.Err != nil {
			// Fail fast if any application processing encountered a critical error
			return "", res.Err
		}
		// Append successful rows
		allViolationRows = append(allViolationRows, res.Rows...)
	}

	// =================================================================
	// 3. CSV GENERATION AND FINAL PATH RETURN
	// =================================================================

	target := filepath.Join(s.cfg.OutputDir, filename)
	s.logger.Info("Writing CSV report", "path", target, "totalRows", len(allViolationRows))

	if err := report.WriteCSV(target, allViolationRows, s.logger); err != nil {
		return "", fmt.Errorf("write csv: %w", err)
	}

	s.logger.Info("Report written successfully", "path", target)

	return target, nil
}
