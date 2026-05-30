package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
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

func (f *fakeProvider) DoctorFix(_ context.Context, options defaults.DoctorFixOptions) (defaults.DoctorFixResult, error) {
	return defaults.DoctorFixResult{
		Changed:    !options.DryRun,
		Operations: []string{"xdg-mime default firefox.desktop text/html"},
	}, nil
}

func (f *fakeProvider) Set(_ context.Context, association defaults.Association, options defaults.SetOptions) (defaults.SetResult, error) {
	f.set = append(f.set, association)
	return defaults.SetResult{Changed: !options.DryRun, Operations: []string{"set " + association.Target().String()}}, nil
}

type resolvingProvider struct {
	fakeProvider
	resolutions map[string]string
}

func (f *resolvingProvider) ResolveApp(_ context.Context, query string, target defaults.Target) (defaults.AppResolution, error) {
	if app := f.resolutions[query]; app != "" {
		return defaults.AppResolution{
			Query:      query,
			App:        app,
			Source:     "test",
			Candidates: []string{app},
		}, nil
	}
	return defaults.AppResolution{}, errors.New("unresolved app query: " + query + " for " + target.String())
}

type doctorReportProvider struct {
	fakeProvider
	report defaults.DoctorReport
}

func (f *doctorReportProvider) Doctor(context.Context, defaults.DoctorOptions) (defaults.DoctorReport, error) {
	return f.report, nil
}

type doctorFixErrorProvider struct {
	fakeProvider
}

func (f *doctorFixErrorProvider) DoctorFix(context.Context, defaults.DoctorFixOptions) (defaults.DoctorFixResult, error) {
	return defaults.DoctorFixResult{}, errors.New("fix unavailable")
}

type doctorFixPlanErrorProvider struct {
	fakeProvider
	changed bool
}

func (f *doctorFixPlanErrorProvider) DoctorFix(context.Context, defaults.DoctorFixOptions) (defaults.DoctorFixResult, error) {
	return defaults.DoctorFixResult{
		Changed:    f.changed,
		Operations: []string{"open settings", "apply policy"},
	}, errors.New("writes unsupported")
}

type getErrorProvider struct {
	fakeProvider
}

func (f *getErrorProvider) Get(context.Context, defaults.Target) (string, error) {
	return "", errors.New("get unavailable")
}

type setErrorProvider struct {
	fakeProvider
}

func (f *setErrorProvider) Set(context.Context, defaults.Association, defaults.SetOptions) (defaults.SetResult, error) {
	return defaults.SetResult{}, errors.New("set unavailable")
}

type setPlanErrorProvider struct {
	fakeProvider
	changed bool
}

func (f *setPlanErrorProvider) Set(context.Context, defaults.Association, defaults.SetOptions) (defaults.SetResult, error) {
	return defaults.SetResult{
		Changed:    f.changed,
		Operations: []string{"open settings", "apply policy"},
	}, errors.New("writes unsupported")
}

type secondSetPlanErrorProvider struct {
	fakeProvider
	calls int
}

func (f *secondSetPlanErrorProvider) Set(_ context.Context, association defaults.Association, options defaults.SetOptions) (defaults.SetResult, error) {
	f.calls++
	if f.calls == 1 {
		f.set = append(f.set, association)
		return defaults.SetResult{Changed: !options.DryRun, Operations: []string{"set " + association.Target().String()}}, nil
	}
	return defaults.SetResult{Operations: []string{"repair second"}}, errors.New("second failed")
}

func assertJSONError(t *testing.T, stdout *bytes.Buffer, wantError string, wantExit int) {
	t.Helper()
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, wantError) || payload.Status.ExitCode != wantExit || !payload.Status.WouldFail {
		t.Fatalf("payload=%+v", payload)
	}
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

func TestTargetFromFlagsNormalizesSchemeURI(t *testing.T) {
	target, err := targetFromFlags("", "HTTPS://example.test/callback", false)
	if err != nil {
		t.Fatal(err)
	}
	if target.Kind != defaults.KindScheme || target.Value != "https" {
		t.Fatalf("target=%+v", target)
	}

	target, err = targetFromFlags("", "x-scheme-handler/Example.App", false)
	if err != nil {
		t.Fatal(err)
	}
	if target.Kind != defaults.KindScheme || target.Value != "example.app" {
		t.Fatalf("target=%+v", target)
	}

	if _, err := targetFromFlags("", "://missing", false); err == nil {
		t.Fatal("expected malformed scheme URI to fail")
	}
	if _, err := targetFromFlags("", "bad_scheme", false); err == nil {
		t.Fatal("expected invalid scheme characters to fail")
	}
	if _, err := targetFromFlags("text", "", false); err == nil {
		t.Fatal("expected invalid MIME to fail")
	}
}

func TestOpenTestTargetFromFlagsRequiresExactlyOneTarget(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	if _, err := openTestTargetFromFlags("", "", false, false); err == nil {
		t.Fatal("expected missing target error")
	}
	if _, err := openTestTargetFromFlags("text/html", "https", false, false); err == nil {
		t.Fatal("expected mutually exclusive target error")
	}
	if _, err := openTestTargetFromFlags("", "https", true, true); err == nil {
		t.Fatal("expected mutually exclusive callback/browser/scheme error")
	}
	if _, err := openTestTargetFromFlags("text/html", "", true, true); err == nil {
		t.Fatal("expected mutually exclusive callback/mime/browser error")
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
	if provider.set[0].Value != "text/html" {
		t.Fatalf("normalized MIME association=%+v", provider.set[0])
	}
	if provider.set[1].Value != "https" || provider.set[1].App != "firefox.desktop" {
		t.Fatalf("normalized association=%+v", provider.set[1])
	}
	if !strings.Contains(stdout.String(), "dry_run: false") || !strings.Contains(stdout.String(), "changed: true") {
		t.Fatalf("stdout missing changed marker: %s", stdout.String())
	}
}

func TestRunApplyExpandsProfilePath(t *testing.T) {
	profileDir := t.TempDir()
	profileFile := profileDir + "/dfx.json"
	if err := writeTestProfile(profileFile); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DFX_PROFILE_DIR", profileDir)

	provider := &fakeProvider{}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "%DFX_PROFILE_DIR%/dfx.json"}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 2 {
		t.Fatalf("set count=%d", len(provider.set))
	}
}

func TestExpandPolicyFilePath(t *testing.T) {
	t.Setenv("DFX_PROFILE_PATH", "/tmp/dfx-policy")
	t.Setenv("DFX_CASE_TOKEN", "CaseValue")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "dollar", in: "$DFX_PROFILE_PATH/dfx.json", want: "/tmp/dfx-policy/dfx.json"},
		{name: "braced", in: "${DFX_PROFILE_PATH}/dfx.json", want: "/tmp/dfx-policy/dfx.json"},
		{name: "percent case-insensitive", in: "%dFx_CaSe_ToKeN%/sub", want: "CaseValue/sub"},
		{name: "percent with spacing", in: "  %DFX_PROFILE_PATH%/expanded  ", want: "/tmp/dfx-policy/expanded"},
		{name: "unmatched percent", in: "/tmp/%DFX_PROFILE_PATH", want: "/tmp/%DFX_PROFILE_PATH"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := expandPolicyFilePath(test.in); got != test.want {
				t.Fatalf("expandPolicyFilePath(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

func TestSetTextIncludesDryRunStatus(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "--dry-run"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "dry_run: true") || !strings.Contains(stdout.String(), "changed: false") {
		t.Fatalf("stdout missing dry-run/change markers: %s", stdout.String())
	}
}

func TestRunApplyValidatesAllDefaultsBeforeApplying(t *testing.T) {
	provider := &fakeProvider{}
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "mime", "value": "text/html", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "bad_scheme", "app": "firefox.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", path}, provider, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 0 {
		t.Fatalf("apply should not partially apply invalid profile: %#v", provider.set)
	}
	if !strings.Contains(stderr.String(), "defaults[1]") {
		t.Fatalf("stderr missing failing index: %s", stderr.String())
	}
}

func TestRunApplyRejectsDuplicateNormalizedTargets(t *testing.T) {
	provider := &fakeProvider{}
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "scheme", "value": "https", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "https://example.test/path", "app": "chromium.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", path}, provider, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 0 {
		t.Fatalf("apply should not partially apply duplicate profile: %#v", provider.set)
	}
	if !strings.Contains(stderr.String(), "duplicate target scheme:https") || !strings.Contains(stderr.String(), "defaults[0]") {
		t.Fatalf("stderr missing duplicate details: %s", stderr.String())
	}
}

func TestRunApplyRejectsBrowserTargetOverlap(t *testing.T) {
	provider := &fakeProvider{}
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "browser", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "https", "app": "chromium.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", path}, provider, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 0 {
		t.Fatalf("apply should not partially apply overlapping profile: %#v", provider.set)
	}
	if !strings.Contains(stderr.String(), "overlapping target scheme:https") || !strings.Contains(stderr.String(), "defaults[0]") {
		t.Fatalf("stderr missing overlap details: %s", stderr.String())
	}
}

func TestRunApplyRejectsTrailingJSON(t *testing.T) {
	provider := &fakeProvider{}
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "mime", "value": "text/html", "app": "firefox.desktop" }
  ]
}
{ "defaults": [] }`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", path}, provider, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 0 {
		t.Fatalf("apply should not apply profile with trailing JSON: %#v", provider.set)
	}
	if !strings.Contains(stderr.String(), "trailing JSON") {
		t.Fatalf("stderr missing trailing JSON detail: %s", stderr.String())
	}
}

func TestRunApplyJSONValidationError(t *testing.T) {
	provider := &fakeProvider{}
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "scheme", "value": "bad_scheme", "app": "firefox.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--dry-run", "--json", path}, provider, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 0 {
		t.Fatalf("apply should not partially apply invalid profile: %#v", provider.set)
	}
	var payload struct {
		Error       string               `json:"error"`
		FailedIndex int                  `json:"failed_index"`
		Association defaults.Association `json:"association"`
		Status      struct {
			ExitCode  int   `json:"exit_code"`
			WouldFail bool  `json:"would_fail"`
			Changed   *bool `json:"changed"`
			DryRun    *bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "defaults[0]") || payload.FailedIndex != 0 || payload.Association.Value != "bad_scheme" || payload.Status.ExitCode != 2 || !payload.Status.WouldFail || payload.Status.Changed == nil || *payload.Status.Changed || payload.Status.DryRun == nil || !*payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunApplyJSONRuntimeErrorPreservesPlan(t *testing.T) {
	provider := &setPlanErrorProvider{changed: true}
	path := t.TempDir() + "/dfx.json"
	if err := writeTestProfile(path); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--json", path}, provider, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error       string               `json:"error"`
		FailedIndex int                  `json:"failed_index"`
		Result      defaults.SetResult   `json:"result"`
		Results     []json.RawMessage    `json:"results"`
		Association defaults.Association `json:"association"`
		Status      struct {
			Changed bool `json:"changed"`
			DryRun  bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "defaults[0]") || payload.FailedIndex != 0 || len(payload.Result.Operations) != 2 || len(payload.Results) != 0 || payload.Association.Value != "text/html" || !payload.Status.Changed || payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunApplyJSONRuntimeErrorReportsPreviousChanges(t *testing.T) {
	provider := &secondSetPlanErrorProvider{}
	path := t.TempDir() + "/dfx.json"
	if err := writeTestProfile(path); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--json", path}, provider, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		FailedIndex int `json:"failed_index"`
		Results     []struct {
			Result defaults.SetResult `json:"result"`
		} `json:"results"`
		Status struct {
			Changed bool `json:"changed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.FailedIndex != 1 || len(payload.Results) != 1 || !payload.Results[0].Result.Changed || !payload.Status.Changed {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestRunApplyJSON(t *testing.T) {
	provider := &fakeProvider{}
	temp := t.TempDir()
	path := temp + "/dfx.json"
	if err := writeTestProfile(path); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--json", path}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Results []struct {
			Index       int                  `json:"index"`
			Association defaults.Association `json:"association"`
			Result      defaults.SetResult   `json:"result"`
		} `json:"results"`
		Status struct {
			ExitCode int  `json:"exit_code"`
			Changed  bool `json:"changed"`
			DryRun   bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"changed"`) || strings.Contains(stdout.String(), `"Changed"`) {
		t.Fatalf("result should use lowercase JSON fields: %s", stdout.String())
	}
	if len(payload.Results) != 2 || payload.Results[0].Index != 0 || !payload.Results[0].Result.Changed || payload.Results[1].Association.Value != "https" || payload.Status.ExitCode != 0 || !payload.Status.Changed || payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestApplyJSONParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--json", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestApplyJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, jsonFlag := range []string{"--json=false", "--json=0", "--json=f"} {
		stdout.Reset()
		stderr.Reset()
		code := runWithProvider([]string{"apply", jsonFlag, "--dry-run", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%s: code=%d stderr=%s", jsonFlag, code, stderr.String())
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("%s: stdout=%s stderr=%s", jsonFlag, stdout.String(), stderr.String())
		}
	}
}

func TestApplyJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--json=maybe", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestProfileValidateJSON(t *testing.T) {
	path := t.TempDir() + "/dfx.json"
	if err := writeTestProfile(path); err != nil {
		t.Fatal(err)
	}
	provider := &fakeProvider{}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "validate", "--json", path}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Profile struct {
			Path     string                 `json:"path"`
			Valid    bool                   `json:"valid"`
			Count    int                    `json:"count"`
			Defaults []defaults.Association `json:"defaults"`
		} `json:"profile"`
		Status struct {
			ExitCode int  `json:"exit_code"`
			Valid    bool `json:"valid"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Profile.Path != path || !payload.Profile.Valid || payload.Profile.Count != 2 || len(payload.Profile.Defaults) != 2 || payload.Profile.Defaults[1].Value != "https" || payload.Status.ExitCode != 0 || !payload.Status.Valid {
		t.Fatalf("payload=%+v", payload)
	}
	if len(provider.set) != 0 {
		t.Fatalf("profile validate should not call provider.Set: %#v", provider.set)
	}
}

func TestProfileValidateExpandsProfilePath(t *testing.T) {
	profileDir := t.TempDir()
	profileFile := profileDir + "/dfx.json"
	if err := writeTestProfile(profileFile); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DFX_PROFILE_DIR", profileDir)

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "validate", "--json", "%DFX_PROFILE_DIR%/dfx.json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Profile struct {
			Path  string `json:"path"`
			Count int    `json:"count"`
		} `json:"profile"`
		Status struct {
			ExitCode int  `json:"exit_code"`
			Valid    bool `json:"valid"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Profile.Path != profileFile || payload.Profile.Count != 2 || !payload.Status.Valid || payload.Status.ExitCode != 0 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestProfileValidateJSONReportsDuplicateTargets(t *testing.T) {
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "scheme", "value": "https", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "https://example.test/path", "app": "chromium.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "validate", "--json", path}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error       string               `json:"error"`
		FailedIndex int                  `json:"failed_index"`
		Association defaults.Association `json:"association"`
		Status      struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Valid     bool `json:"valid"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "duplicate or overlapping target scheme:https") || payload.FailedIndex != 1 || payload.Association.Value != "https" || payload.Status.ExitCode != 2 || !payload.Status.WouldFail || payload.Status.Valid {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestProfileValidatePositionalArgJSON(t *testing.T) {
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "browser", "app": "firefox.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "validate", "--json", path, "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestProfileValidatePositionalArgNonJSON(t *testing.T) {
	path := t.TempDir() + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "browser", "app": "firefox.desktop" }
  ]
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "validate", path, "--json=false", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output, got stdout=%s", stdout.String())
	}
}

func TestProfileTemplateText(t *testing.T) {
	provider := &fakeProvider{}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "template", "--app", "firefox.desktop"}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var cfg profile
	if err := json.Unmarshal(stdout.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	associations, _, _, err := validateProfile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(associations) != 1 || associations[0].Kind != defaults.KindBrowser || associations[0].App != "firefox.desktop" {
		t.Fatalf("profile=%+v associations=%+v", cfg, associations)
	}
	if len(provider.set) != 0 {
		t.Fatalf("profile template should not call provider.Set: %#v", provider.set)
	}
}

func TestProfileTemplateJSONIncludesCallback(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "template", "--app", "firefox.desktop", "--callback-scheme", "MyApp://oauth/callback", "--callback-app", "myapp.desktop", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Profile profile `json:"profile"`
		Status  struct {
			ExitCode int  `json:"exit_code"`
			Valid    bool `json:"valid"`
			Count    int  `json:"count"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status.ExitCode != 0 || !payload.Status.Valid || payload.Status.Count != 2 || len(payload.Profile.Defaults) != 2 {
		t.Fatalf("payload=%+v", payload)
	}
	callback := payload.Profile.Defaults[1]
	if callback.Kind != defaults.KindScheme || callback.Value != "myapp" || callback.App != "myapp.desktop" {
		t.Fatalf("callback=%+v payload=%+v", callback, payload)
	}
}

func TestProfileTemplateRejectsOverlappingCallbackScheme(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "template", "--app", "firefox.desktop", "--callback-scheme", "https", "--callback-app", "myapp.desktop", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "overlapping target scheme:https", 2)
}

func TestProfileTemplateRequiresApp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "template", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "requires --app", 2)
}

func TestProfileTemplateRejectsInvalidCallbackScheme(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "template", "--app", "firefox.desktop", "--callback-scheme", "bad scheme", "--callback-app", "myapp.desktop", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "invalid URL scheme", 2)
}

func TestProfileValidateJSONFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "validate", "--json=false", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
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
	var payload struct {
		Status struct {
			ExitCode int `json:"exit_code"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status.ExitCode != 0 {
		t.Fatalf("missing status: %+v", payload)
	}
}

func TestInspectJSONPositionalError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"inspect", "--json", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional", 2)
}

func TestInspectPositionalError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"inspect", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestInspectJSONParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"inspect", "--json", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestInspectJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, jsonFlag := range []string{"--json=false", "--json=0", "--json=f"} {
		stdout.Reset()
		stderr.Reset()
		code := runWithProvider([]string{"inspect", jsonFlag, "--unknown"}, &fakeProvider{}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%s: code=%d stderr=%s", jsonFlag, code, stderr.String())
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("%s: stdout=%s stderr=%s", jsonFlag, stdout.String(), stderr.String())
		}
	}
}

func TestInspectJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"inspect", "--json=maybe", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestGetJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--scheme", "https://example.test/path", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Target defaults.Target `json:"target"`
		App    string          `json:"app"`
		Status struct {
			ExitCode int `json:"exit_code"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Target.Kind != defaults.KindScheme || payload.App != "https.app" || payload.Status.ExitCode != 0 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestProfileCommandUnknownSubcommandJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "bogus", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, `unknown profile subcommand "bogus"`, 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestProfileCommandNoSubcommandJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "profile requires validate or template", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestProfileCommandNoSubcommandJSONDisabled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "profile requires validate or template") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestProfileCommandUnknownSubcommandJSONDisabled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"profile", "bogus", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown profile subcommand "bogus"`) {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestGetJSONError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--scheme", "https", "--json"}, &getErrorProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "get unavailable", 1)
}

func TestOpenTestJSONMatchesExpectedHandler(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--scheme", "HTTPS://example.test/callback", "--expected", "https.app", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report struct {
			Target    defaults.Target `json:"target"`
			ActualApp string          `json:"actual_app"`
			Matched   bool            `json:"matched"`
			Launched  bool            `json:"launched"`
			Notes     []string        `json:"notes"`
		} `json:"report"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Launched  bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.Target.Kind != defaults.KindScheme || payload.Report.Target.Value != "https" || payload.Report.ActualApp != "https.app" || !payload.Report.Matched || payload.Report.Launched || payload.Status.ExitCode != 0 || payload.Status.WouldFail || payload.Status.Launched || len(payload.Report.Notes) == 0 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestOpenTestJSONMismatchFailsWithoutLaunching(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "firefox.desktop", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report struct {
			ActualApp   string `json:"actual_app"`
			ExpectedApp string `json:"expected_app"`
			Matched     bool   `json:"matched"`
			Launched    bool   `json:"launched"`
		} `json:"report"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Launched  bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.ActualApp != "text/html.app" || payload.Report.ExpectedApp != "firefox.desktop" || payload.Report.Matched || payload.Report.Launched || payload.Status.ExitCode != 1 || !payload.Status.WouldFail || payload.Status.Launched {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestOpenTestLaunchUsesExplicitLauncherAfterMatch(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--scheme", "myapp://oauth/callback", "--expected", "myapp.app", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report struct {
			Launched bool `json:"launched"`
			Launch   struct {
				Subject string   `json:"subject"`
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"launch"`
		} `json:"report"`
		Status struct {
			Launched bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if launchedSubject != "myapp://oauth/callback" || !payload.Report.Launched || payload.Report.Launch.Command != "fake-open" || len(payload.Report.Launch.Args) != 1 || !payload.Status.Launched {
		t.Fatalf("subject=%q payload=%+v", launchedSubject, payload)
	}
}

func TestOpenTestLaunchExpandsMimePathBeforeLaunch(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	tempPath := t.TempDir() + "/sample.html"
	if err := os.WriteFile(tempPath, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DFX_OPEN_PATH", tempPath)

	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--path", "$DFX_OPEN_PATH", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}

	var payload struct {
		Report struct {
			Launch struct {
				Subject string `json:"subject"`
			} `json:"launch"`
			Launched bool `json:"launched"`
		} `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if launchedSubject != tempPath || !payload.Report.Launched || payload.Report.Launch.Subject != tempPath {
		t.Fatalf("payload=%+v launchedSubject=%q", payload, launchedSubject)
	}
}

func TestOpenTestLaunchExpandsPercentMimePathBeforeLaunch(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	tempPath := t.TempDir() + "/sample.html"
	if err := os.WriteFile(tempPath, []byte("<html></html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DFX_OPEN_TEST_PATH", tempPath)

	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--path", "%DFX_OPEN_TEST_PATH%", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}

	var payload struct {
		Report struct {
			Launch struct {
				Subject string `json:"subject"`
			} `json:"launch"`
			Launched bool `json:"launched"`
		} `json:"report"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if launchedSubject != tempPath || !payload.Report.Launched || payload.Report.Launch.Subject != tempPath {
		t.Fatalf("payload=%+v launchedSubject=%q", payload, launchedSubject)
	}
}

func TestOpenTestLaunchErrorsOnMissingMimePath(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		t.Fatal("launcher should not run without a valid MIME path")
		return "", nil, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--path", "/tmp/dfx-does-not-exist.html", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "existing --path file", 1)
}

func TestOpenTestLaunchErrorsOnMissingMimePathText(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		t.Fatal("launcher should not run without a valid MIME path")
		return "", nil, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--path", "/tmp/dfx-does-not-exist.html", "--launch", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output on stderr only: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "open-test --launch with --mime requires --path to an existing file") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestOpenTestLaunchErrorsOnMimeDirectoryPath(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		t.Fatal("launcher should not run for directory path")
		return "", nil, nil
	}

	path := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--path", path, "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "not a file", 1)
}

func TestOpenTestLaunchErrorsOnMimeDirectoryPathText(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		t.Fatal("launcher should not run for directory path")
		return "", nil, nil
	}

	path := t.TempDir()

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--path", path, "--launch", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output on stderr only: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "open-test --launch with --mime requires --path to a file, not a directory") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestOpenTestLaunchSkipsWhenExpectedHandlerMismatches(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		t.Fatal("launcher should not run on mismatch")
		return "", nil, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--scheme", "myapp://oauth/callback", "--expected", "other.app", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report struct {
			Launched bool     `json:"launched"`
			Evidence []string `json:"evidence"`
		} `json:"report"`
		Status struct {
			Launched bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.Launched || payload.Status.Launched || len(payload.Report.Evidence) != 2 || !strings.Contains(payload.Report.Evidence[1], "skipped") {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestOpenTestLaunchMimeSkipsPathRequirementOnExpectedMismatch(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	launched := false
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		launched = true
		return "should-not-run", []string{"should-not-run"}, errors.New("launcher should not run")
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "other.app", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error  string `json:"error"`
		Report struct {
			ActualApp   string `json:"actual_app"`
			ExpectedApp string `json:"expected_app"`
			Matched     *bool  `json:"matched"`
			Launched    bool   `json:"launched"`
			Launch      any    `json:"launch"`
		} `json:"report"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Launched  bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error != "" || payload.Report.ActualApp != "text/html.app" || payload.Report.ExpectedApp != "other.app" || payload.Report.Matched == nil || *payload.Report.Matched || payload.Report.Launched || payload.Status.ExitCode != 1 || !payload.Status.WouldFail || payload.Status.Launched || payload.Report.Launch != nil || launched {
		t.Fatalf("payload=%+v launched=%t", payload, launched)
	}
}

func TestOpenTestLaunchMimeRequiresPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error  string `json:"error"`
		Report struct {
			Launched bool `json:"launched"`
		} `json:"report"`
		Status struct {
			Launched bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "--path") || payload.Report.Launched || payload.Status.Launched {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestOpenTestLaunchMimeRequiresPathText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "text/html.app", "--launch", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse/validation output on stderr only: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "requires --path") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestOpenTestLaunchMimeMismatchSkipsPathRequirementText(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		t.Fatal("launcher should not run when expected handler does not match")
		return "", nil, nil
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--mime", "text/html", "--expected", "other.app", "--launch", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected plain-text mismatch report on stdout")
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output on non-JSON mismatch report, got=%s", stderr.String())
	}
	if strings.Contains(stdout.String(), "launch.subject:") {
		t.Fatalf("stdout should not include launch details when launch is skipped: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch skipped because expected handler did not match") {
		t.Fatalf("stdout missing launch-skip evidence: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "matched: false") {
		t.Fatalf("stdout missing match state: %s", stdout.String())
	}
}

func TestOpenTestCallbackLaunchSkipsOnMismatchText(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	launched := false
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		launched = true
		return "should-not-run", []string{"should-not-run"}, errors.New("launcher should not run")
	}

	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--expected", "wrong.app", "--launch", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected plain-text mismatch report on stdout")
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output on non-JSON mismatch report, got=%s", stderr.String())
	}
	if launched {
		t.Fatal("launcher should not run on callback mismatch")
	}
	if !strings.Contains(stdout.String(), "target: scheme:myapp") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "expected: wrong.app") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "actual: myapp.app") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "matched: false") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "launch.subject:") {
		t.Fatalf("stdout should not include launch details when launch is skipped: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch skipped because expected handler did not match") {
		t.Fatalf("stdout missing launch-skip evidence: %s", stdout.String())
	}
}

func TestOpenTestCallbackLaunchSkipsOnMismatchJSON(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })
	launched := false
	runOpenTestLauncher = func(context.Context, string) (string, []string, error) {
		launched = true
		return "should-not-run", []string{"should-not-run"}, errors.New("launcher should not run on callback mismatch")
	}

	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--expected", "wrong.app", "--launch", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report struct {
			ActualApp   string `json:"actual_app"`
			ExpectedApp string `json:"expected_app"`
			Matched     *bool  `json:"matched"`
			Launched    bool   `json:"launched"`
			Launch      any    `json:"launch"`
		} `json:"report"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Launched  bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.ActualApp != "myapp.app" || payload.Report.ExpectedApp != "wrong.app" || payload.Report.Matched == nil || *payload.Report.Matched || payload.Report.Launched || payload.Status.ExitCode != 1 || !payload.Status.WouldFail || payload.Status.Launched || payload.Report.Launch != nil || launched {
		t.Fatalf("payload=%+v launched=%t", payload, launched)
	}
}

func TestOpenTestSchemeLaunchSkipsPathInput(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })

	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	path := t.TempDir() + "/does-not-exist.txt"
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--scheme", "myapp", "--expected", "myapp.app", "--launch", "--path", path, "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output on scheme launch: %s", stderr.String())
	}
	if launchedSubject != "myapp:" {
		t.Fatalf("launchedSubject=%q", launchedSubject)
	}
	if !strings.Contains(stdout.String(), "evidence: provided --path is ignored for non-MIME launch targets") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch.subject: myapp:") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestOpenTestCallbackLaunchSkipsPathInput(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })

	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	path := t.TempDir() + "/does-not-exist.txt"
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--expected", "myapp.app", "--launch", "--path", path, "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output on callback launch: %s", stderr.String())
	}
	if launchedSubject != "myapp://oauth/callback" {
		t.Fatalf("launchedSubject=%q", launchedSubject)
	}
	if !strings.Contains(stdout.String(), "evidence: provided --path is ignored for non-MIME launch targets") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch.subject: myapp://oauth/callback") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestOpenTestBrowserLaunchSkipsPathInput(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })

	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	path := t.TempDir() + "/does-not-exist.txt"
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--browser", "--expected", "default.app", "--launch", "--path", path, "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output on browser launch: %s", stderr.String())
	}
	if launchedSubject != "https://example.com/" {
		t.Fatalf("launchedSubject=%q", launchedSubject)
	}
	if !strings.Contains(stdout.String(), "evidence: provided --path is ignored for non-MIME launch targets") {
		t.Fatalf("stdout=%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "launch.subject: https://example.com/") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestOpenTestCallbackUsesCallbackScheme(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--expected", "myapp.app"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "target: scheme:myapp") || !strings.Contains(stdout.String(), "matched: true") || !strings.Contains(stdout.String(), "launched: false") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestOpenTestCallbackLaunchUsesCallbackSchemeText(t *testing.T) {
	oldLauncher := runOpenTestLauncher
	t.Cleanup(func() { runOpenTestLauncher = oldLauncher })

	var launchedSubject string
	runOpenTestLauncher = func(_ context.Context, subject string) (string, []string, error) {
		launchedSubject = subject
		return "fake-open", []string{subject}, nil
	}

	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--expected", "myapp.app", "--launch", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected plain-text launch report on stdout")
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr, got=%s", stderr.String())
	}
	if launchedSubject != "myapp://oauth/callback" {
		t.Fatalf("launchedSubject=%q", launchedSubject)
	}
	if !strings.Contains(stdout.String(), "launch.subject: myapp://oauth/callback") {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestOpenTestJSONValidationError(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Launched  bool `json:"launched"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "DFX_CALLBACK_SCHEME") || payload.Status.ExitCode != 2 || !payload.Status.WouldFail || payload.Status.Launched {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestOpenTestCallbackRequiresEnvironmentVariableText(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--json=false", "--expected", "com.example.app"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "DFX_CALLBACK_SCHEME") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestOpenTestCallbackInvalidScheme(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://bad scheme/callback")
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--callback", "--expected", "myapp.app", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "invalid URL scheme", 2)
}

func TestWindowsPolicyValidateJSON(t *testing.T) {
	path := t.TempDir() + "/DefaultAssociations.xml"
	if err := os.WriteFile(path, []byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier="https" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".html" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier="myapp" ProgId="ExampleApp" Suggested="true" />
</DefaultAssociations>`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--file", path, "--callback-scheme", "myapp://oauth/callback", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Validation defaults.WindowsPolicyValidation `json:"validation"`
		Status     struct {
			ExitCode int  `json:"exit_code"`
			Valid    bool `json:"valid"`
			Complete bool `json:"complete"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status.ExitCode != 0 || !payload.Status.Valid || !payload.Status.Complete || !payload.Validation.Valid || !payload.Validation.Complete || len(payload.Validation.Records) != 5 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestWindowsPolicyValidateRequiresFileJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertJSONError(t, &stdout, "requires --file", 2)
}

func TestWindowsPolicyValidateRequiresFileNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires --file") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyValidateExpandsPolicyPath(t *testing.T) {
	policyDir := t.TempDir()
	policyFile := policyDir + "/DefaultAssociations.xml"
	if err := os.WriteFile(policyFile, []byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier="https" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".html" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier="myapp" ProgId="ExampleApp" Suggested="true" />
</DefaultAssociations>`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DFX_POLICY_DIR", policyDir)

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--file", "%DFX_POLICY_DIR%/DefaultAssociations.xml", "--callback-scheme", "myapp://oauth/callback", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Validation defaults.WindowsPolicyValidation `json:"validation"`
		Status     struct {
			ExitCode int `json:"exit_code"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status.ExitCode != 0 || !payload.Validation.Valid || !payload.Validation.Complete || len(payload.Validation.Records) != 5 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestWindowsPolicyValidatePositionalArgJSON(t *testing.T) {
	path := t.TempDir() + "/DefaultAssociations.xml"
	if err := os.WriteFile(path, []byte(`<DefaultAssociations />`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--json", "--file", path, "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestWindowsPolicyValidateMissingFileJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--file", "missing.xml", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "missing.xml") || payload.Status.ExitCode != 1 || !payload.Status.WouldFail {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestWindowsPolicyValidateMissingFileNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--file", "missing.xml", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing.xml") || !strings.Contains(stderr.String(), "no such file") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyAuditRequiresProgID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "audit", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "requires --prog-id", 2)
}

func TestWindowsPolicyAuditRequiresProgIDNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "audit", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy audit requires --prog-id") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyAuditPositionalArgJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "audit", "--json", "--prog-id", "ChromeHTML", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestWindowsPolicyAuditPositionalArgNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "audit", "--prog-id", "ChromeHTML", "extra", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyValidateJSONReportsMissingTargets(t *testing.T) {
	path := t.TempDir() + "/DefaultAssociations.xml"
	if err := os.WriteFile(path, []byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier="https" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".html" ProgId="ChromeHTML" Suggested="true" />
</DefaultAssociations>`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--file", path, "--callback-scheme", "myapp", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Validation defaults.WindowsPolicyValidation `json:"validation"`
		Status     struct {
			WouldFail bool `json:"would_fail"`
			Complete  bool `json:"complete"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Status.WouldFail || payload.Status.Complete || strings.Join(payload.Validation.Missing, ",") != "application/xhtml+xml,myapp" {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestWindowsPolicyTemplateJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--prog-id", "ChromeHTML", "--application-name", `Chrome & "Beta"`, "--callback-scheme", "myapp://oauth/callback", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		XML    string `json:"xml"`
		Status struct {
			ExitCode int `json:"exit_code"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<DefaultAssociations>`,
		`Identifier="http" ProgId="ChromeHTML"`,
		`Identifier=".xhtml" ProgId="ChromeHTML"`,
		`Identifier="myapp" ProgId="ChromeHTML"`,
		`ApplicationName="Chrome &amp; &quot;Beta&quot;"`,
	} {
		if !strings.Contains(payload.XML, want) {
			t.Fatalf("missing %q in XML:\n%s", want, payload.XML)
		}
	}
	if payload.Status.ExitCode != 0 {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestWindowsPolicyTemplatePositionalArgJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--json", "--prog-id", "ChromeHTML", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestWindowsPolicyTemplatePositionalArgNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--prog-id", "ChromeHTML", "extra", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyTemplateRequiresProgID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "prog id is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected plain-text error path, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyTemplateInvalidCallbackScheme(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--prog-id", "ChromeHTML", "--callback-scheme", "bad scheme"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid callback scheme") {
		t.Fatalf("stderr=%s", stderr.String())
	}
}

func TestWindowsPolicyTemplateJSONParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--json", "--prog-id", "ChromeHTML", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestWindowsPolicyTemplateJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--prog-id", "ChromeHTML", "--json=false", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestWindowsPolicyTemplateJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "template", "--prog-id", "ChromeHTML", "--json=maybe", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestWindowsPolicyValidateJSONFalseParseErrorUsesStderr(t *testing.T) {
	path := t.TempDir() + "/DefaultAssociations.xml"
	if err := os.WriteFile(path, []byte(`<DefaultAssociations />`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "validate", "--file", path, "--json=false", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestWindowsPolicyAuditJSONFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "audit", "--prog-id", "ChromeHTML", "--json=false", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestWindowsPolicyCommandUnknownSubcommandJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "bogus", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, `unknown windows-policy subcommand "bogus"`, 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestWindowsPolicyCommandNoSubcommandJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "windows-policy requires audit, validate, or template", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestWindowsPolicyCommandNoSubcommandJSONDisabled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy requires audit, validate, or template") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestWindowsPolicyCommandUnknownSubcommandJSONDisabled(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"windows-policy", "bogus", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown windows-policy subcommand "bogus"`) {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestGetJSONParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--json", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestGetRequiresTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertJSONError(t, &stdout, "one of --mime, --scheme, or --browser is required", 2)
}

func TestGetRequiresTargetTextError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "one of --mime, --scheme, or --browser is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestGetJSONEqualsTrueParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--json=true", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestGetJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, jsonFlag := range []string{"--json=false", "--json=0", "--json=f"} {
		stdout.Reset()
		stderr.Reset()
		code := runWithProvider([]string{"get", jsonFlag, "--unknown"}, &fakeProvider{}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%s: code=%d stderr=%s", jsonFlag, code, stderr.String())
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("%s: stdout=%s stderr=%s", jsonFlag, stdout.String(), stderr.String())
		}
	}
}

func TestGetJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--json=maybe", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestGetPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--json", "--mime", "text/html", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestGetPositionalArgumentText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--mime", "text/html", "extra", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON path, got stdout=%s", stdout.String())
	}
}

func TestGetMutuallyExclusiveTargetsArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"get", "--json", "--mime", "text/html", "--scheme", "https"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "mutually exclusive", 2)
}

func TestOpenTestJSONParseErrorUsesStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--json", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestOpenTestJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--json=false", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestOpenTestJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--json=maybe", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestOpenTestRequiresTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--expected", "firefox.desktop"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "one of --mime, --scheme, --browser, or --callback is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON target validation path, got stdout=%s", stdout.String())
	}
}

func TestOpenTestRequiresTargetJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--expected", "firefox.desktop", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertJSONError(t, &stdout, "one of --mime, --scheme, --browser, or --callback is required", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON target validation path, got stderr=%s", stderr.String())
	}
}

func TestOpenTestPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--json", "--scheme", "https", "--expected", "com.example.app", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestOpenTestPositionalArgumentText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--scheme", "https", "extra", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestOpenTestMutuallyExclusiveTargetsArgument(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"open-test", "--json", "--callback", "--scheme", "https", "--expected", "com.example.app"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "mutually exclusive", 2)

	stdout.Reset()
	stderr.Reset()
	code = runWithProvider([]string{"open-test", "--callback", "--mime", "text/html", "--json=false", "--expected", "com.example.app"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "mutually exclusive") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runWithProvider([]string{"open-test", "--json", "--callback", "--browser"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "mutually exclusive", 2)
}

func TestArgsWantJSONMirrorsFlagParsing(t *testing.T) {
	tests := []struct {
		name string
		args []string
		scan jsonFlagScan
		want bool
	}{
		{name: "open-test json enabled", args: []string{"--json", "--callback"}, scan: openTestJSONFlags, want: true},
		{name: "open-test json false assignment", args: []string{"--json=false", "--callback"}, scan: openTestJSONFlags, want: false},
		{name: "open-test json after bool flag is parsed", args: []string{"--launch", "--json"}, scan: openTestJSONFlags, want: true},
		{name: "bare json flag", args: []string{"--json"}, scan: getJSONFlags, want: true},
		{name: "json true assignment", args: []string{"--json=true"}, scan: getJSONFlags, want: true},
		{name: "json false assignment", args: []string{"--json=false"}, scan: getJSONFlags, want: false},
		{name: "json after terminator is positional", args: []string{"--", "--json"}, scan: getJSONFlags, want: false},
		{name: "json after positional is positional", args: []string{"profile.json", "--json"}, scan: getJSONFlags, want: false},
		{name: "json after value flag is still parsed", args: []string{"--scheme", "https", "--json"}, scan: getJSONFlags, want: true},
		{name: "value flag consumes json token", args: []string{"--scheme", "--json"}, scan: getJSONFlags, want: false},
		{name: "json after unknown flag is not reached", args: []string{"--unknown", "--json"}, scan: getJSONFlags, want: false},
		{name: "json after bool flag is parsed", args: []string{"--browser", "--json"}, scan: getJSONFlags, want: true},
		{name: "json after false bool assignment is parsed", args: []string{"--browser=false", "--json"}, scan: getJSONFlags, want: true},
		{name: "json after invalid bool assignment is not reached", args: []string{"--browser=maybe", "--json"}, scan: getJSONFlags, want: false},
		{name: "json after flag from another command is not reached", args: []string{"--scheme", "https", "--json"}, scan: applyJSONFlags, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := argsWantJSON(test.args, test.scan); got != test.want {
				t.Fatalf("argsWantJSON(%v) = %v, want %v", test.args, got, test.want)
			}
		})
	}
}

func TestSetJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "--dry-run", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Association defaults.Association `json:"association"`
		Result      defaults.SetResult   `json:"result"`
		Status      struct {
			ExitCode int  `json:"exit_code"`
			Changed  bool `json:"changed"`
			DryRun   bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"changed"`) || strings.Contains(stdout.String(), `"Changed"`) {
		t.Fatalf("result should use lowercase JSON fields: %s", stdout.String())
	}
	if payload.Association.App != "firefox.desktop" || payload.Result.Changed || payload.Status.ExitCode != 0 || payload.Status.Changed || !payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestSetPositionalAppResolves(t *testing.T) {
	provider := &resolvingProvider{resolutions: map[string]string{"vivaldi": "vivaldi-stable.desktop"}}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "vivaldi", "--browser", "--dry-run", "--json"}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Association   defaults.Association   `json:"association"`
		AppResolution defaults.AppResolution `json:"app_resolution"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(provider.set) != 1 || provider.set[0].App != "vivaldi-stable.desktop" || payload.Association.App != "vivaldi-stable.desktop" || payload.AppResolution.Query != "vivaldi" {
		t.Fatalf("set=%+v payload=%+v", provider.set, payload)
	}
}

func TestSetAppFlagResolves(t *testing.T) {
	provider := &resolvingProvider{resolutions: map[string]string{"vivaldi": "vivaldi-stable.desktop"}}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--browser", "--app", "vivaldi", "--dry-run", "--json"}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if len(provider.set) != 1 || provider.set[0].App != "vivaldi-stable.desktop" {
		t.Fatalf("set=%+v", provider.set)
	}
}

func TestApplyResolvesProfileApps(t *testing.T) {
	provider := &resolvingProvider{resolutions: map[string]string{"vivaldi": "vivaldi-stable.desktop"}}
	temp := t.TempDir()
	path := temp + "/dfx.json"
	if err := os.WriteFile(path, []byte(`{"defaults":[{"kind":"scheme","value":"https","app":"vivaldi"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"apply", "--json", path}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Results []struct {
			Association   defaults.Association   `json:"association"`
			AppResolution defaults.AppResolution `json:"app_resolution"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(provider.set) != 1 || provider.set[0].App != "vivaldi-stable.desktop" || len(payload.Results) != 1 || payload.Results[0].Association.App != "vivaldi-stable.desktop" || payload.Results[0].AppResolution.Query != "vivaldi" {
		t.Fatalf("set=%+v payload=%+v", provider.set, payload)
	}
}

func TestSetJSONParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "--json", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestSetJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, jsonFlag := range []string{"--json=false", "--json=0", "--json=f"} {
		stdout.Reset()
		stderr.Reset()
		code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", jsonFlag, "--unknown"}, &fakeProvider{}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%s: code=%d stderr=%s", jsonFlag, code, stderr.String())
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("%s: stdout=%s stderr=%s", jsonFlag, stdout.String(), stderr.String())
		}
	}
}

func TestSetJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "--json=maybe", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestSetRequiresTarget(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--mime", "text/html", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	assertJSONError(t, &stdout, "app is required", 2)
}

func TestSetRequiresTargetTextError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--mime", "text/html"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "app is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error path, got stdout=%s", stdout.String())
	}
}

func TestSetJSONValidationError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "bad_scheme", "--app", "firefox.desktop", "--dry-run", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int   `json:"exit_code"`
			WouldFail bool  `json:"would_fail"`
			Changed   *bool `json:"changed"`
			DryRun    *bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "invalid URL scheme") || payload.Status.ExitCode != 2 || !payload.Status.WouldFail || payload.Status.Changed == nil || *payload.Status.Changed || payload.Status.DryRun == nil || !*payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestSetJSONRuntimeError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "--json"}, &setErrorProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "set unavailable", 1)
}

func TestSetJSONRuntimeErrorPreservesPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "--json"}, &setPlanErrorProvider{changed: true}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error  string             `json:"error"`
		Result defaults.SetResult `json:"result"`
		Status struct {
			Changed bool `json:"changed"`
			DryRun  bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error != "writes unsupported" || len(payload.Result.Operations) != 2 || !payload.Result.Changed || !payload.Status.Changed || payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestSetTextRuntimeErrorPreservesPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop"}, &setPlanErrorProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "open settings") || !strings.Contains(stdout.String(), "dry_run: false") || !strings.Contains(stdout.String(), "changed: false") || !strings.Contains(stderr.String(), "writes unsupported") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestSetPositionalArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--json", "--scheme", "https", "firefox", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "at most one positional app query", 2)
}

func TestSetPositionalArgumentText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--scheme", "https", "--app", "firefox.desktop", "extra", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "either --app or one positional app query") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON path, got stdout=%s", stdout.String())
	}
}

func TestSetMutuallyExclusiveTargetsArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"set", "--json", "--scheme", "https", "--mime", "text/html", "--app", "firefox.desktop"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "mutually exclusive", 2)
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
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.Scope != "browser" || payload.Status.ExitCode != 0 || payload.Status.WouldFail {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestDoctorJSONValidationError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "requires --browser", 2)
}

func TestDoctorJSONParseError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--json", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected JSON parse error on stdout only, stderr=%s", stderr.String())
	}
}

func TestDoctorPositionalError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--json", "--browser", "extra"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
}

func TestDoctorPositionalErrorNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "extra", "--json=false"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON error output, got stdout=%s", stdout.String())
	}
}

func TestDoctorJSONEqualsFalseParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	for _, jsonFlag := range []string{"--json=false", "--json=0", "--json=f"} {
		stdout.Reset()
		stderr.Reset()
		code := runWithProvider([]string{"doctor", "--browser", jsonFlag, "--unknown"}, &fakeProvider{}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("%s: code=%d stderr=%s", jsonFlag, code, stderr.String())
		}
		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined") {
			t.Fatalf("%s: stdout=%s stderr=%s", jsonFlag, stdout.String(), stderr.String())
		}
	}
}

func TestDoctorJSONInvalidBooleanParseErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--json=maybe", "--browser", "--unknown"}, &fakeProvider{}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestDoctorBrowserStrictFailsOnWarnings(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--strict"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestDoctorBrowserStrictIgnoresInfoFindings(t *testing.T) {
	provider := &doctorReportProvider{report: defaults.DoctorReport{
		Platform: "test",
		Scope:    "browser",
		Healthy:  true,
		Findings: []defaults.DoctorFinding{{ID: "I01", Severity: "info", Summary: "advisory"}},
	}}
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--strict"}, provider, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestDoctorBrowserStrictJSONEmitsReportBeforeFailing(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--strict", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Report defaults.DoctorReport `json:"report"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
			Strict    bool `json:"strict"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Report.Findings) != 1 || payload.Report.Findings[0].ID != "L01" || payload.Status.ExitCode != 1 || !payload.Status.WouldFail || !payload.Status.Strict {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestDoctorBrowserFixText(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix", "--dry-run"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "fix.dry_run: true") || !strings.Contains(stdout.String(), "fix.changed: false") {
		t.Fatalf("missing fix output: %s", stdout.String())
	}
}

func TestDoctorBrowserFixErrorStillPrintsReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix"}, &doctorFixErrorProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "finding: [L01] warning example finding") || !strings.Contains(stdout.String(), "fix.dry_run: false") || !strings.Contains(stdout.String(), "fix.error: fix unavailable") {
		t.Fatalf("missing report or fix error output: %s", stdout.String())
	}
}

func TestDoctorBrowserFixErrorStillPrintsPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix"}, &doctorFixPlanErrorProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "fix: open settings") || !strings.Contains(stdout.String(), "fix.changed: false") || !strings.Contains(stdout.String(), "fix.error: writes unsupported") {
		t.Fatalf("missing fix plan or error output: %s", stdout.String())
	}
}

func TestDoctorBrowserFixErrorJSONStillPrintsReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix", "--json"}, &doctorFixErrorProvider{}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		Report   defaults.DoctorReport `json:"report"`
		FixError string                `json:"fix_error"`
		Status   struct {
			ExitCode  int  `json:"exit_code"`
			FixFailed bool `json:"fix_failed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Report.Scope != "browser" || payload.FixError != "fix unavailable" || payload.Status.ExitCode != 1 || !payload.Status.FixFailed {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestDoctorBrowserFixErrorJSONStillPrintsPlan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix", "--json"}, &doctorFixPlanErrorProvider{changed: true}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		Fix      defaults.DoctorFixResult `json:"fix"`
		FixError string                   `json:"fix_error"`
		Status   struct {
			Changed bool `json:"changed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.FixError != "writes unsupported" || len(payload.Fix.Operations) != 2 || !payload.Fix.Changed || !payload.Status.Changed {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestDoctorBrowserFixJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithProvider([]string{"doctor", "--browser", "--fix", "--json"}, &fakeProvider{}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var payload struct {
		Fix    defaults.DoctorFixResult `json:"fix"`
		Status struct {
			Changed bool `json:"changed"`
			DryRun  bool `json:"dry_run"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.Fix.Changed || !payload.Status.Changed || payload.Status.DryRun {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestHelpIncludesOperationalNotes(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	help := stdout.String()
	for _, want := range []string{
		"dfx open-test",
		"dfx profile validate",
		"dfx windows-policy",
		"--mime expects a MIME type",
		"DFX_CALLBACK_SCHEME",
		"safe handler-resolution preflight",
		"enterprise default-association XML",
		"--fix --dry-run emits the supported remediation plan",
		"JSON output includes a status object",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help missing %q:\n%s", want, help)
		}
	}
}

func TestRunNoArgsPrintsUsageToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(nil, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("missing usage:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout usage, got %s", stdout.String())
	}
}

func TestRunUnknownCommandPrintsUsageToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Fatalf("missing unknown command message: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("missing usage:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout usage, got %s", stdout.String())
	}
}

func TestRunUnknownCommandJSONError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected JSON output on stdout")
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, `unknown command "bogus"`) || payload.Status.ExitCode != 2 || !payload.Status.WouldFail {
		t.Fatalf("payload=%+v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunUnknownCommandJSONFalseUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=false", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Fatalf("missing unknown command message: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage with non-JSON unknown command: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunUnknownCommandShortJSONFalseUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=false", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Fatalf("missing unknown command message: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage with non-JSON unknown command: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunUnknownCommandJSONZeroUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Fatalf("missing unknown command message: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage with non-JSON unknown command: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunUnknownCommandJSONOneUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=1", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected JSON output on stdout")
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, `unknown command "bogus"`) || payload.Status.ExitCode != 2 || !payload.Status.WouldFail {
		t.Fatalf("payload=%+v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunUnknownCommandShortJSONZeroUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), `unknown command "bogus"`) {
		t.Fatalf("missing unknown command message: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage with non-JSON unknown command: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunUnknownCommandShortJSONOneUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=1", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected JSON output on stdout")
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode  int  `json:"exit_code"`
			WouldFail bool `json:"would_fail"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, `unknown command "bogus"`) || payload.Status.ExitCode != 2 || !payload.Status.WouldFail {
		t.Fatalf("payload=%+v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeInspectCommandParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "inspect", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenInspectJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "inspect", "--bad", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenInspectJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "inspect", "--bad", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeGetPositionalErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "get", "foo"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "get does not accept positional arguments", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenGetJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "get", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "get requires exactly one target selector") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenGetJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "get", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "get requires exactly one target selector") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeProfileValidateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "profile", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenProfileJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "profile", "validate", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "profile validate requires exactly one profile path") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenProfileJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "profile", "validate", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "profile validate requires exactly one profile path") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeProfileWithoutSubcommandUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "profile"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "profile requires validate or template", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenProfileTemplateJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "profile", "template", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "profile template requires --app") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenProfileTemplateJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "profile", "template", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "profile template requires --app") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONBeforeProfileSubcommandParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "profile", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "unknown profile subcommand \"--bad\"", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeUnknownProfileSubcommandUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "profile", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, `unknown profile subcommand "bogus"`, 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeWindowsPolicyWithoutSubcommandUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "windows-policy requires audit, validate, or template", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeWindowsPolicyWithoutSubcommandUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "windows-policy requires audit, validate, or template", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeUnknownWindowsPolicySubcommandUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, `unknown windows-policy subcommand "bogus"`, 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenWindowsPolicyValidateJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "validate", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy validate requires --file") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenWindowsPolicyValidateJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy", "validate", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy validate requires --file") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenWindowsPolicyAuditJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy", "audit", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy audit requires --prog-id") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONThenWindowsPolicyAuditJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "audit", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy audit requires --prog-id") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONThenWindowsPolicyTemplateJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "template", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "prog id is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenWindowsPolicyTemplateJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy", "template", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "prog id is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeGetRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "get"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "get requires exactly one target selector", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeOpenTestParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "open-test", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenOpenTestJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "open-test", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "one of --mime, --scheme, --browser, or --callback is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONThenOpenTestJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "open-test", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "one of --mime, --scheme, --browser, or --callback is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeOpenTestPositionalErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "open-test", "--scheme", "https", "--expected", "com.example.app", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONFalseBeforeGetRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "get"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "get requires exactly one target selector") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONFalseBeforeOpenTestParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "open-test", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONFalseBeforeOpenTestPositionalErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "open-test", "--scheme", "https", "--expected", "com.example.app", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not accept positional arguments") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONBeforeOpenTestRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "open-test"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "one of --mime, --scheme, --browser, or --callback is required", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeOpenTestPositionalErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "open-test", "--scheme", "https", "--expected", "com.example.app", "extra"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "does not accept positional arguments", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeGetRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "get"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "get requires exactly one target selector", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeOpenTestRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "open-test"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "one of --mime, --scheme, --browser, or --callback is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeWindowsPolicySubcommandParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "unknown windows-policy subcommand \"--bad\"", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeGetRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "get"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "get requires exactly one target selector") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeSetRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "set", "--scheme", "https"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "app is required", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeSetRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "set", "--scheme", "https"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "app is required", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeApplyRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "apply requires exactly one profile path", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeApplyRequiresTargetUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "apply requires exactly one profile path", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONFalseBeforeSetRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "set", "--scheme", "https"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "app is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeSetRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "set", "--scheme", "https"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "app is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONFalseBeforeApplyRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "apply requires exactly one profile path") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeApplyRequiresTargetUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "apply requires exactly one profile path") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeInspectParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "inspect", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeWindowsPolicyValidateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeWindowsPolicyValidateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeWindowsPolicyTemplateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "windows-policy", "template", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeWindowsPolicyTemplateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy", "template", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeWindowsPolicySubcommandParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "windows-policy", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "unknown windows-policy subcommand \"--bad\"", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeProfileSubcommandParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "profile", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "unknown profile subcommand \"--bad\"", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeProfileValidateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "profile", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeProfileTemplateParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "profile", "template", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONFalseBeforeInspectParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "inspect", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeDoctorRequiresBrowserUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "doctor"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "doctor currently requires --browser", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortGlobalJSONBeforeDoctorRequiresBrowserUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "doctor"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "doctor currently requires --browser", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONBeforeDoctorParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "doctor", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenDoctorJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "doctor", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "doctor currently requires --browser") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONFalseBeforeDoctorParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "doctor", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONThenSetJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "set", "--scheme", "https", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "app is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONThenSetJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "set", "--scheme", "https", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "app is required") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONFalseBeforeDoctorParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "doctor", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONBeforeSetParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json", "set", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunShortJSONFalseBeforeSetParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "set", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValueBeforeDoctorParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "doctor", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONBeforeApplyParseErrorUsesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "apply", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	assertJSONError(t, &stdout, "flag provided but not defined", 2)
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunGlobalJSONThenApplyJSONFalseUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "apply", "--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "apply requires exactly one profile path") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONFalseBeforeApplyParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "apply", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValueBeforeSetParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "set", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValueBeforeApplyParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "apply", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunGlobalJSONFalseBeforeWindowsPolicySubcommandUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=0", "windows-policy", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "unknown windows-policy subcommand") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeWindowsPolicyValidateParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "windows-policy", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeProfileWithoutSubcommandUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "profile"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "profile requires validate or template") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortGlobalJSONFalseBeforeWindowsPolicyWithoutSubcommandUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=0", "windows-policy"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "windows-policy requires audit, validate, or template") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "bogus"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValueBeforeProfileParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "profile", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunJSONMalformedValueBeforeProfileParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=maybe", "profile", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValueBeforeWindowsPolicyParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "windows-policy", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunJSONMalformedValueBeforeWindowsPolicyParseErrorUsesNonJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=maybe", "windows-policy", "validate", "--bad"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunJSONOnlyMissingCommandError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var payload struct {
		Error  string `json:"error"`
		Status struct {
			ExitCode int `json:"exit_code"`
		} `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload.Error, "missing command") || payload.Status.ExitCode != 2 {
		t.Fatalf("payload=%+v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
	}
}

func TestRunJSONFalseOnlyMissingCommandUsesUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=false"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("expected usage on missing command: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output: %s", stdout.String())
	}
}

func TestRunJSONShortFalseOnlyMissingCommandUsesUsage(t *testing.T) {
	for _, arg := range []string{"-json=0", "-json=false"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{arg}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Usage:") {
				t.Fatalf("expected usage on missing command: %s", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("expected no stdout output: %s", stdout.String())
			}
		})
	}
}

func TestRunJSONShortMissingCommandReturnsJSONError(t *testing.T) {
	for _, arg := range []string{"-json", "-json=1"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{arg}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Fatalf("expected JSON output on stdout")
			}
			var payload struct {
				Error  string `json:"error"`
				Status struct {
					ExitCode int `json:"exit_code"`
				} `json:"status"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(payload.Error, "missing command") || payload.Status.ExitCode != 2 {
				t.Fatalf("payload=%+v", payload)
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected no stderr for JSON output: %s", stderr.String())
			}
		})
	}
}

func TestRunJSONMalformedValue(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=maybe", "inspect"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunJSONMalformedValueBeforeHelpUsesUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--json=maybe", "help"},
		{"--json=maybe", "--help"},
		{"--json=maybe", "-h"},
		{"--json=maybe", "help", "inspect"},
		{"--json=maybe", "--help", "inspect"},
		{"--json=maybe", "-h", "inspect"},
		{"--json=maybe", "help", "inspect", "--unknown"},
		{"--json=maybe", "--help", "inspect", "--unknown"},
		{"--json=maybe", "-h", "inspect", "--unknown"},
		{"-json=maybe", "help"},
		{"-json=maybe", "--help"},
		{"-json=maybe", "-h"},
		{"-json=maybe", "help", "inspect"},
		{"-json=maybe", "--help", "inspect"},
		{"-json=maybe", "-h", "inspect"},
		{"-json=maybe", "help", "inspect", "--unknown"},
		{"-json=maybe", "--help", "inspect", "--unknown"},
		{"-json=maybe", "-h", "inspect", "--unknown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("missing usage in help output:\n%s", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected no stderr on help: %s", stderr.String())
			}
		})
	}
}

func TestRunJSONMalformedValueOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json=maybe"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunShortJSONMalformedValueOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunJSONMalformedValueWithShortFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-json=maybe", "inspect"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid boolean value") {
		t.Fatalf("stderr=%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected non-JSON parse error on stderr only: %s", stdout.String())
	}
}

func TestRunJSONWithHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--json", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Fatalf("expected usage output on help")
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("missing usage on help output:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr on help: %s", stderr.String())
	}
}

func TestRunJSONAliasWithHelpUsesUsage(t *testing.T) {
	for _, args := range [][]string{
		{"--json", "help"},
		{"--json", "--help"},
		{"--json", "-h"},
		{"-json", "help"},
		{"-json=0", "help"},
		{"-json=1", "help"},
		{"--json=0", "help"},
		{"--json=1", "help"},
		{"--json=0", "--help"},
		{"--json=1", "--help"},
		{"--json=0", "-h"},
		{"--json=1", "-h"},
		{"-json=0", "--help"},
		{"-json=1", "--help"},
		{"-json=0", "-h"},
		{"-json=1", "-h"},
		{"--json=false", "help"},
		{"-json=false", "help"},
		{"help", "--json"},
		{"help", "--json=false"},
		{"help", "--json=0"},
		{"help", "--json=1"},
		{"help", "-json=0"},
		{"help", "-json=1"},
		{"help", "-json"},
		{"help", "-json=false"},
		{"--help", "--json=false"},
		{"--help", "--json=0"},
		{"--help", "--json=1"},
		{"--help", "--json"},
		{"-h", "--json"},
		{"-h", "--json=false"},
		{"-h", "--json=0"},
		{"-h", "--json=1"},
		{"--help", "--json=maybe"},
		{"help", "--json=maybe"},
		{"-h", "--json=maybe"},
		{"help", "--json=maybe", "inspect"},
		{"--help", "--json=maybe", "inspect"},
		{"-h", "--json=maybe", "inspect"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("missing usage in stdout:\n%s", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected no stderr on help: %s", stderr.String())
			}
		})
	}
}

func TestRunCommandLevelHelpPrintsUsageToStdout(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "inspect", args: []string{"inspect", "--help"}},
		{name: "inspect-json-maybe", args: []string{"inspect", "--help", "--json=maybe"}},
		{name: "inspect-json-maybe-short", args: []string{"inspect", "-h", "--json=maybe"}},
		{name: "inspect-json-false-short", args: []string{"-json=0", "inspect", "-h"}},
		{name: "inspect-json-false", args: []string{"-json=0", "inspect", "--help"}},
		{name: "inspect-json-true", args: []string{"--json=1", "inspect", "--help"}},
		{name: "inspect-json-true-short", args: []string{"--json=1", "inspect", "-h"}},
		{name: "inspect-json-override-false", args: []string{"--json", "inspect", "--help", "--json=false"}},
		{name: "inspect-help-json-false", args: []string{"inspect", "--help", "--json=false"}},
		{name: "inspect-help-json-true", args: []string{"inspect", "--help", "--json=1"}},
		{name: "inspect-json-prefix-short", args: []string{"-json", "inspect", "-h"}},
		{name: "get", args: []string{"get", "--help"}},
		{name: "get-json-false", args: []string{"-json=0", "get", "--help"}},
		{name: "get-json-true", args: []string{"--json=1", "get", "-h"}},
		{name: "get-help-json-false", args: []string{"get", "--help", "--json=false"}},
		{name: "get-help-json-true", args: []string{"get", "--help", "--json=1"}},
		{name: "get-short", args: []string{"get", "-h"}},
		{name: "set", args: []string{"set", "--help"}},
		{name: "set-json-false", args: []string{"-json=0", "set", "--help"}},
		{name: "set-json-true", args: []string{"--json=1", "set", "-h"}},
		{name: "set-help-json-false", args: []string{"set", "--help", "--json=false"}},
		{name: "set-help-json-true", args: []string{"set", "--help", "--json=1"}},
		{name: "set-short", args: []string{"set", "-h"}},
		{name: "apply", args: []string{"apply", "--help"}},
		{name: "apply-json-maybe", args: []string{"apply", "--help", "--json=maybe"}},
		{name: "apply-help-json-maybe", args: []string{"apply", "-h", "--json=maybe"}},
		{name: "apply-json-true", args: []string{"--json=1", "apply", "-h"}},
		{name: "apply-help-json-false", args: []string{"apply", "--help", "--json=false"}},
		{name: "apply-help-json-true", args: []string{"apply", "--help", "--json=1"}},
		{name: "apply-json-short", args: []string{"-json=0", "apply", "-h"}},
		{name: "doctor", args: []string{"doctor", "--help"}},
		{name: "doctor-json-false", args: []string{"-json=0", "doctor", "--help"}},
		{name: "doctor-json-true", args: []string{"--json=1", "doctor", "-h"}},
		{name: "doctor-help-json-false", args: []string{"doctor", "--help", "--json=false"}},
		{name: "doctor-help-json-true", args: []string{"doctor", "--help", "--json=1"}},
		{name: "doctor-short", args: []string{"doctor", "-h"}},
		{name: "open-test", args: []string{"open-test", "--help"}},
		{name: "open-test-short", args: []string{"open-test", "-h"}},
		{name: "open-test-json-false", args: []string{"--json=false", "open-test", "--help"}},
		{name: "open-test-json-false-0", args: []string{"-json=0", "open-test", "--help"}},
		{name: "open-test-json-false-short", args: []string{"-json=0", "open-test", "-h"}},
		{name: "open-test-json-true", args: []string{"-json=1", "open-test", "--help"}},
		{name: "open-test-json-true-short-val", args: []string{"-json=1", "open-test", "-h"}},
		{name: "open-test-json-true-short", args: []string{"--json", "open-test", "-h"}},
		{name: "open-test-json-override", args: []string{"-json", "open-test", "--help", "--json=false"}},
		{name: "open-test-help-json-false", args: []string{"open-test", "--help", "--json=false"}},
		{name: "open-test-help-json-true", args: []string{"open-test", "--help", "--json=1"}},
		{name: "profile-root", args: []string{"profile", "--help"}},
		{name: "profile-root-json", args: []string{"--json=1", "profile", "--help"}},
		{name: "profile-root-json-override", args: []string{"-json", "profile", "--help", "--json=false"}},
		{name: "profile-root-json-explicit-false", args: []string{"--json=false", "profile", "--help"}},
		{name: "profile-root-help-json-false", args: []string{"profile", "--help", "--json=false"}},
		{name: "profile-root-help-json-true", args: []string{"profile", "--help", "--json=1"}},
		{name: "windows-policy-root", args: []string{"windows-policy", "--help"}},
		{name: "windows-policy-root-json", args: []string{"-json=0", "windows-policy", "--help"}},
		{name: "windows-policy-root-json-override", args: []string{"--json", "windows-policy", "--help", "--json=false"}},
		{name: "windows-policy-root-json-explicit-false", args: []string{"--json=false", "windows-policy", "--help"}},
		{name: "windows-policy-root-help-json-false", args: []string{"windows-policy", "--help", "--json=false"}},
		{name: "windows-policy-root-help-json-true", args: []string{"windows-policy", "--help", "--json=1"}},
		{name: "profile-subcommand", args: []string{"profile", "validate", "--help"}},
		{name: "profile-subcommand-json", args: []string{"-json=1", "profile", "validate", "--help"}},
		{name: "profile-subcommand-json-short", args: []string{"profile", "validate", "-h", "--json=1"}},
		{name: "profile-subcommand-json-false", args: []string{"--json=false", "profile", "validate", "--help"}},
		{name: "profile-subcommand-short", args: []string{"profile", "validate", "-h"}},
		{name: "profile-subcommand-help-json-false", args: []string{"profile", "validate", "--help", "--json=false"}},
		{name: "profile-subcommand-help-json-true", args: []string{"profile", "validate", "--help", "--json=1"}},
		{name: "profile-template-subcommand", args: []string{"profile", "template", "--help"}},
		{name: "profile-template-subcommand-json", args: []string{"--json=1", "profile", "template", "-h"}},
		{name: "profile-template-subcommand-json-false", args: []string{"--json=false", "profile", "template", "-h"}},
		{name: "profile-template-subcommand-help-json-false", args: []string{"profile", "template", "--help", "--json=false"}},
		{name: "profile-template-subcommand-help-json-true", args: []string{"profile", "template", "--help", "--json=1"}},
		{name: "windows-policy-subcommand", args: []string{"windows-policy", "validate", "--help"}},
		{name: "windows-policy-subcommand-json", args: []string{"-json=1", "windows-policy", "validate", "--help"}},
		{name: "windows-policy-subcommand-json-short", args: []string{"windows-policy", "validate", "-h", "--json=1"}},
		{name: "windows-policy-subcommand-json-false", args: []string{"--json=false", "windows-policy", "validate", "--help"}},
		{name: "windows-policy-subcommand-short", args: []string{"windows-policy", "validate", "-h"}},
		{name: "windows-policy-subcommand-help-json-false", args: []string{"windows-policy", "validate", "--help", "--json=false"}},
		{name: "windows-policy-subcommand-help-json-true", args: []string{"windows-policy", "validate", "--help", "--json=1"}},
		{name: "windows-policy-audit", args: []string{"windows-policy", "audit", "--help"}},
		{name: "windows-policy-audit-short", args: []string{"windows-policy", "audit", "-h"}},
		{name: "windows-policy-audit-json", args: []string{"--json=1", "windows-policy", "audit", "--help"}},
		{name: "windows-policy-audit-json-false", args: []string{"--json=false", "windows-policy", "audit", "-h"}},
		{name: "windows-policy-audit-help-json-false", args: []string{"windows-policy", "audit", "--help", "--json=false"}},
		{name: "windows-policy-audit-help-json-true", args: []string{"windows-policy", "audit", "--help", "--json=1"}},
		{name: "windows-policy-json-prefix", args: []string{"-json", "windows-policy", "template", "-h"}},
		{name: "windows-policy-template-json-false", args: []string{"--json=false", "windows-policy", "template", "--help"}},
		{name: "windows-policy-template-json", args: []string{"--json=1", "windows-policy", "template", "-h"}},
		{name: "windows-policy-template-help-json-false", args: []string{"windows-policy", "template", "--help", "--json=false"}},
		{name: "windows-policy-template-help-json-true", args: []string{"windows-policy", "template", "--help", "--json=1"}},
		{name: "inspect-json-prefix", args: []string{"-json=1", "inspect", "-h"}},
		{name: "get-json-maybe", args: []string{"get", "--help", "--json=maybe"}},
		{name: "set-json-maybe", args: []string{"set", "--help", "--json=maybe"}},
		{name: "doctor-json-maybe", args: []string{"doctor", "--help", "--json=maybe"}},
		{name: "open-test-json-maybe", args: []string{"open-test", "--help", "--json=maybe"}},
		{name: "profile-root-json-maybe", args: []string{"profile", "--help", "--json=maybe"}},
		{name: "profile-subcommand-json-maybe", args: []string{"profile", "validate", "--help", "--json=maybe"}},
		{name: "windows-policy-root-json-maybe", args: []string{"windows-policy", "--help", "--json=maybe"}},
		{name: "windows-policy-subcommand-json-maybe", args: []string{"windows-policy", "validate", "--help", "--json=maybe"}},
		{name: "windows-policy-template-json-maybe", args: []string{"windows-policy", "template", "--help", "--json=maybe"}},
		{name: "windows-policy-audit-json-maybe", args: []string{"windows-policy", "audit", "--help", "--json=maybe"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tc.args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("missing usage in stdout:\n%s", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected no stderr on help: %s", stderr.String())
			}
		})
	}
}

func TestRunCommandLevelHelpWithPositionalArgsPrintsUsage(t *testing.T) {
	tests := [][]string{
		{"inspect", "--help", "extra"},
		{"get", "--help", "extra"},
		{"set", "--help", "extra"},
		{"apply", "--help", "extra"},
		{"doctor", "--help", "extra"},
		{"open-test", "--help", "extra"},
		{"profile", "--help", "extra"},
		{"profile", "validate", "--help", "extra"},
		{"windows-policy", "validate", "--help", "extra"},
		{"windows-policy", "audit", "--help", "extra"},
		{"windows-policy", "template", "--help", "extra"},
		{"profile", "template", "--help", "extra"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("missing usage in stdout:\n%s", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected no stderr usage, got %s", stderr.String())
			}
		})
	}
}

func TestRunHelpAliasesPrintUsageToStdout(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run([]string{arg}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Fatalf("missing usage in stdout:\n%s", stdout.String())
			}
			if !strings.Contains(stdout.String(), "dfx inspect [--verbose] [--json]") {
				t.Fatalf("unexpected usage output:\n%s", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected no stderr usage, got %s", stderr.String())
			}
		})
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
	case "get":
		return get(context.Background(), provider, args[1:], stdout, stderr)
	case "open-test":
		return openTest(context.Background(), provider, args[1:], stdout, stderr)
	case "profile":
		return profileCommand(args[1:], stdout, stderr)
	case "windows-policy":
		return windowsPolicy(args[1:], stdout, stderr)
	case "set":
		return set(context.Background(), provider, args[1:], stdout, stderr)
	case "apply":
		return apply(context.Background(), provider, args[1:], stdout, stderr)
	default:
		return Run(args, stdout, stderr)
	}
}
