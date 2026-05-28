package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/LukasParke/dfx/internal/defaults"
)

type fakeProvider struct {
	set []defaults.Association
}

func (f *fakeProvider) Inspect(context.Context) defaults.InspectReport {
	return defaults.InspectReport{
		Platform: "test",
		Provider: "fake",
		CanRead:  true,
		CanWrite: true,
		Capabilities: defaults.Capabilities{
			CanReadCurrent:        true,
			CanWriteUserDefault:   true,
			CanWriteSystemDefault: false,
			PolicyRestricted:      false,
			SupportsBrowser:       true,
			SupportsScheme:        true,
			SupportsMIME:          true,
			SupportsContentType:   false,
		},
	}
}

func (f *fakeProvider) Get(_ context.Context, target defaults.Target) (string, error) {
	return target.Value + ".app", nil
}

func (f *fakeProvider) Doctor(context.Context, defaults.DoctorOptions) (defaults.DoctorReport, error) {
	return defaults.DoctorReport{
		Platform: "test",
		Scope:    "browser",
		Healthy:  true,
		Findings: []defaults.DoctorFinding{
			{ID: "L01", Severity: "warning", Summary: "example finding"},
		},
	}, nil
}

func (f *fakeProvider) DoctorFix(context.Context, defaults.DoctorFixOptions) (defaults.DoctorFixResult, error) {
	return defaults.DoctorFixResult{
		Changed:    true,
		Operations: []string{"xdg-mime default firefox.desktop text/html"},
	}, nil
}

func (f *fakeProvider) Set(_ context.Context, association defaults.Association, options defaults.SetOptions) (defaults.SetResult, error) {
	f.set = append(f.set, association)
	return defaults.SetResult{Changed: !options.DryRun, Operations: []string{"set " + association.Target().String()}}, nil
}

func TestTargetFromFlagsRequiresExactlyOneTarget(t *testing.T) {
	if _, err := targetFromFlags("", "", false); err == nil {
		t.Fatal("expected missing target error")
	}
	if _, err := targetFromFlags("text/html", "https", false); err == nil {
		t.Fatal("expected mutually exclusive target error")
	}
	if _, err := targetFromFlags("", "https", true); err == nil {
		t.Fatal("expected mutually exclusive browser target error")
	}
}

func TestTargetFromFlagsSupportsBrowser(t *testing.T) {
	target, err := targetFromFlags("", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if target.Kind != defaults.KindBrowser {
		t.Fatalf("kind=%q", target.Kind)
	}
}

func TestRunApplyValidatesAndAppliesProfile(t *testing.T) {
	provider := &fakeProvider{}
	temp := t.TempDir()
	path := temp + "/dfx.json"
	t.Setenv("DFX_TEST_PROFILE", path)
	if err := writeTestProfile(path); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", path}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 2 {
		t.Fatalf("set count=%d", len(provider.set))
	}
	if !strings.Contains(stdout.String(), "changed: true") {
		t.Fatalf("stdout missing changed marker: %s", stdout.String())
	}
}

func TestInspectVerbosePrintsCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"inspect", "--verbose"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "capability.can_write_user_default: true") {
		t.Fatalf("stdout missing verbose capability data: %s", stdout.String())
	}
}

func TestInspectJSONIncludesCapabilities(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"inspect", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var report defaults.InspectReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Provider != "fake" || !report.Capabilities.SupportsBrowser {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestDoctorBrowserText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "finding: [L01] warning example finding") {
		t.Fatalf("missing finding output: %s", stdout.String())
	}
}

func TestDoctorBrowserJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report defaults.DoctorReport `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.Scope != "browser" {
		t.Fatalf("scope=%q", payload.Report.Scope)
	}
}

func TestDoctorBrowserStrictFailsOnWarnings(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--strict"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestDoctorBrowserFixText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix", "--dry-run"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "fix.changed: true") {
		t.Fatalf("missing fix output: %s", stdout.String())
	}
}

func TestDoctorBrowserFixJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["fix"]; !ok {
		t.Fatalf("missing fix payload: %s", stdout.String())
	}
}

func runWithProvider(args []string, provider defaults.Provider, stdout, stderr *bytes.Buffer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "inspect":
		return inspect(context.Background(), provider, args[1:], stdout, stderr)
	case "doctor":
		return doctor(context.Background(), provider, args[1:], stdout, stderr)
	case "apply":
		return apply(context.Background(), provider, args[1:], stdout, stderr)
	default:
		return Run(args, stdout, stderr)
	}
}
