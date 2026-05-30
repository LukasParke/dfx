package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LukasParke/dfx/internal/defaults"
)

type openTestJSONFixturePayload struct {
	Error  string `json:"error"`
	Report struct {
		Target      defaults.Target `json:"target"`
		ActualApp   string          `json:"actual_app"`
		ExpectedApp string          `json:"expected_app"`
		Matched     *bool           `json:"matched"`
		Launched    bool            `json:"launched"`
		Launch      *struct {
			Subject string `json:"subject"`
			Command string `json:"command"`
			Args    []string `json:"args"`
		} `json:"launch"`
		Notes       []string        `json:"notes"`
		Evidence    []string        `json:"evidence"`
	} `json:"report"`
	Status struct {
		ExitCode  int  `json:"exit_code"`
		WouldFail bool `json:"would_fail"`
		Launched  bool `json:"launched"`
	} `json:"status"`
}

type openTestFixtureResult struct {
	code    int
	payload openTestJSONFixturePayload
	stdout  string
	stderr  string
}

func runOpenTestJSON(t *testing.T, provider defaults.Provider, args ...string) openTestFixtureResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	allArgs := append([]string{"--json"}, args...)
	code := openTest(context.Background(), provider, allArgs, &stdout, &stderr)
	var payload openTestJSONFixturePayload
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("open-test json unmarshal failed: %v\nstdout=%q\nstderr=%q", err, stdout.String(), stderr.String())
	}
	return openTestFixtureResult{
		code:    code,
		payload: payload,
		stdout:  stdout.String(),
		stderr:  stderr.String(),
	}
}

func installOpenTestFixtureFile(t *testing.T, fixture string, destination string, mode os.FileMode) {
	t.Helper()
	source := filepath.Join("testdata", "open-test", fixture)
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read fixture %q: %v", source, err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(destination), err)
	}
	if err := os.WriteFile(destination, data, mode); err != nil {
		t.Fatalf("write fixture to %q: %v", destination, err)
	}
}

func prependOpenTestFixturePath(t *testing.T, dir string) {
	t.Helper()
	pathValue := os.Getenv("PATH")
	if pathValue == "" {
		pathValue = os.Getenv("Path")
	}
	combined := dir + string(os.PathListSeparator) + pathValue
	t.Setenv("PATH", combined)
	t.Setenv("Path", combined)
}

func assertOpenTestMatched(t *testing.T, result openTestFixtureResult, expectedApp string) {
	t.Helper()
	if result.code != 0 {
		t.Fatalf("open-test exit code=%d payload=%+v stderr=%q", result.code, result.payload, result.stderr)
	}
	if result.payload.Status.ExitCode != 0 || result.payload.Status.WouldFail || result.payload.Status.Launched {
		t.Fatalf("open-test status mismatch: %+v", result.payload.Status)
	}
	if result.payload.Report.Launched || result.payload.Report.Matched == nil || !*result.payload.Report.Matched {
		t.Fatalf("open-test report indicates mismatch: %+v", result.payload.Report)
	}
	if strings.TrimSpace(result.payload.Report.ActualApp) != expectedApp || strings.TrimSpace(result.payload.Report.ExpectedApp) != expectedApp {
		t.Fatalf("open-test app mismatch: actual=%q expected=%q report=%+v stdout=%q stderr=%q", result.payload.Report.ActualApp, expectedApp, result.payload.Report, result.stdout, result.stderr)
	}
}

func assertOpenTestMismatch(t *testing.T, result openTestFixtureResult, expectedApp, actualApp string) {
	t.Helper()
	if result.code != 1 {
		t.Fatalf("open-test exit code=%d payload=%+v stderr=%q", result.code, result.payload, result.stderr)
	}
	if result.payload.Status.ExitCode != 1 || !result.payload.Status.WouldFail || result.payload.Status.Launched {
		t.Fatalf("open-test status mismatch: %+v", result.payload.Status)
	}
	if result.payload.Report.Launched || result.payload.Report.Matched == nil || *result.payload.Report.Matched {
		t.Fatalf("open-test report indicates unexpected match: %+v", result.payload.Report)
	}
	if strings.TrimSpace(result.payload.Report.ExpectedApp) != expectedApp || strings.TrimSpace(result.payload.Report.ActualApp) != actualApp {
		t.Fatalf("open-test report app mismatch: actual=%q expected=%q report=%+v", result.payload.Report.ActualApp, expectedApp, result.payload.Report)
	}
}

func assertOpenTestLaunchSkippedAfterMismatch(t *testing.T, result openTestFixtureResult) {
	t.Helper()
	assertOpenTestMismatch(t, result, strings.TrimSpace(result.payload.Report.ExpectedApp), strings.TrimSpace(result.payload.Report.ActualApp))
	skipped := false
	for _, line := range result.payload.Report.Evidence {
		if strings.Contains(line, "launch skipped because expected handler did not match") {
			skipped = true
			break
		}
	}
	if !skipped {
		t.Fatalf("open-test evidence missing launch-skip marker: %+v", result.payload.Report.Evidence)
	}
	if len(result.payload.Report.Evidence) < 2 {
		t.Fatalf("open-test evidence too short: %+v", result.payload.Report.Evidence)
	}
	if result.payload.Report.Launch != nil {
		t.Fatalf("launch details should be absent when launch is skipped: %+v", result.payload.Report.Launch)
	}
}
