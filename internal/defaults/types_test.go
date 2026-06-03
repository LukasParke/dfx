package defaults

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type remediationFakeProvider struct {
	report DoctorReport
	err    error
}

func (f remediationFakeProvider) Inspect(context.Context) InspectReport {
	return InspectReport{}
}

func (f remediationFakeProvider) Doctor(context.Context, DoctorOptions) (DoctorReport, error) {
	return f.report, f.err
}

func (f remediationFakeProvider) DoctorFix(context.Context, DoctorFixOptions) (DoctorFixResult, error) {
	return DoctorFixResult{}, nil
}

func (f remediationFakeProvider) Get(context.Context, Target) (string, error) {
	return "", nil
}

func (f remediationFakeProvider) Set(context.Context, Association, SetOptions) (SetResult, error) {
	return SetResult{}, nil
}

func TestAppendFindingRemediationOperations(t *testing.T) {
	operations := appendFindingRemediationOperations(context.Background(), remediationFakeProvider{
		report: DoctorReport{
			Findings: []DoctorFinding{
				{ID: "X01", Remediation: "repair this"},
				{ID: "X01", Remediation: " repair this "},
				{ID: "X02"},
			},
		},
	}, []string{"base"})
	joined := strings.Join(operations, "\n")
	if !strings.Contains(joined, "base") || !strings.Contains(joined, "Remediate X01: repair this") || strings.Contains(joined, "X02") {
		t.Fatalf("operations=%v", operations)
	}
	if strings.Count(joined, "Remediate X01") != 1 {
		t.Fatalf("expected duplicate remediation to be suppressed: %v", operations)
	}
}

func TestAppendFindingRemediationOperationsReportsDoctorError(t *testing.T) {
	operations := appendFindingRemediationOperations(context.Background(), remediationFakeProvider{
		err: errors.New("not available"),
	}, nil)
	if len(operations) != 1 || !strings.Contains(operations[0], "not available") {
		t.Fatalf("operations=%v", operations)
	}
}

func TestNormalizeCallbackScheme(t *testing.T) {
	cases := map[string]string{
		" Example.App ":                   "example.app",
		"Example.App:":                    "example.app",
		"Example.App://callback/path":     "example.app",
		"x-scheme-handler/Example.App":    "example.app",
		"x-scheme-handler/Example.App://": "example.app",
		"://missing":                      "",
	}
	for raw, want := range cases {
		if got := normalizeCallbackScheme(raw); got != want {
			t.Fatalf("normalizeCallbackScheme(%q)=%q, want %q", raw, got, want)
		}
	}
}

func TestTargetAndAssociationNormalizeInputs(t *testing.T) {
	target := Target{Kind: KindScheme, Value: "HTTPS://example.test/path"}.Normalized()
	if target.Kind != KindScheme || target.Value != "https" {
		t.Fatalf("target=%+v", target)
	}
	target = Target{Kind: "MIME", Value: "Text/HTML"}.Normalized()
	if target.Kind != KindMIME || target.Value != "text/html" {
		t.Fatalf("mime target=%+v", target)
	}
	target = Target{Kind: KindBrowser}.Normalized()
	if target.Kind != KindBrowser || target.Value != "default" {
		t.Fatalf("browser target=%+v", target)
	}
	target = Target{Kind: KindContentType, Value: "Public.HTML"}.Normalized()
	if target.Kind != KindContentType || target.Value != "public.html" {
		t.Fatalf("content-type target=%+v", target)
	}
	if err := (Target{Kind: KindScheme, Value: "HTTPS://example.test/path"}).Validate(); err != nil {
		t.Fatalf("validate normalized scheme: %v", err)
	}
	if err := (Target{Kind: KindContentType, Value: "public.html"}).Validate(); err != nil {
		t.Fatalf("validate content-type: %v", err)
	}
	if err := (Target{Kind: KindContentType, Value: ""}).Validate(); err == nil {
		t.Fatal("expected empty content-type to fail validation")
	}
	association := (Association{Kind: "SCHEME", Value: "Example.App://callback", App: " app.desktop "}).Normalized()
	if association.Kind != KindScheme || association.Value != "example.app" || association.App != "app.desktop" {
		t.Fatalf("association=%+v", association)
	}
}

func TestTargetValidateRejectsExtensionMIMEInput(t *testing.T) {
	err := (Target{Kind: KindMIME, Value: ".pdf"}).Validate()
	if err == nil || !strings.Contains(err.Error(), "file extension") || !strings.Contains(err.Error(), "application/pdf") {
		t.Fatalf("expected extension-specific MIME error, got %v", err)
	}
}

func TestTargetValidateRejectsInvalidMIMETypes(t *testing.T) {
	for _, raw := range []string{"text", "text/", "/html", "text/html/extra", "text html/html", "text/html; charset=utf-8"} {
		if err := (Target{Kind: KindMIME, Value: raw}).Validate(); err == nil {
			t.Fatalf("expected invalid MIME type %q to fail", raw)
		}
	}
	for _, raw := range []string{"text/html", "application/xhtml+xml", "application/vnd.example+json", "application/x-www-form-urlencoded"} {
		if err := (Target{Kind: KindMIME, Value: raw}).Validate(); err != nil {
			t.Fatalf("expected valid MIME type %q: %v", raw, err)
		}
	}
}

func TestTargetValidateRejectsInvalidURLSchemes(t *testing.T) {
	for _, raw := range []string{"1app", "bad scheme", "bad_scheme", "http?query", "://missing"} {
		if err := (Target{Kind: KindScheme, Value: raw}).Validate(); err == nil {
			t.Fatalf("expected invalid scheme %q to fail", raw)
		}
	}
	for _, raw := range []string{"example.app+v1", "Example.App+v1://callback"} {
		if err := (Target{Kind: KindScheme, Value: raw}).Validate(); err != nil {
			t.Fatalf("expected valid scheme %q: %v", raw, err)
		}
	}
}

func TestUnsupportedProviderValidatesInputsBeforeUnsupportedError(t *testing.T) {
	provider := unsupportedProvider{platform: "plan9", reason: "not implemented"}
	if _, err := provider.Get(context.Background(), Target{Kind: KindScheme, Value: "bad_scheme"}); err == nil || !strings.Contains(err.Error(), "invalid URL scheme") {
		t.Fatalf("expected validation error, got %v", err)
	}
	if _, err := provider.Set(context.Background(), Association{Kind: KindScheme, Value: "https", App: ""}, SetOptions{}); err == nil || !strings.Contains(err.Error(), "app is required") {
		t.Fatalf("expected app validation error, got %v", err)
	}
	if _, err := provider.Get(context.Background(), Target{Kind: KindScheme, Value: "https://example.test"}); err == nil || !strings.Contains(err.Error(), "support is unavailable") {
		t.Fatalf("expected unsupported error, got %v", err)
	}
}

func TestUnsupportedProviderValidatesDoctorOptionsBeforeUnsupportedError(t *testing.T) {
	provider := unsupportedProvider{platform: "plan9", reason: "not implemented"}
	if _, err := provider.Doctor(context.Background(), DoctorOptions{}); err == nil || !strings.Contains(err.Error(), "doctor requires exactly one scope flag") {
		t.Fatalf("expected doctor option validation error, got %v", err)
	}
	if _, err := provider.DoctorFix(context.Background(), DoctorFixOptions{}); err == nil || !strings.Contains(err.Error(), "doctor fix requires exactly one scope flag") {
		t.Fatalf("expected doctor fix option validation error, got %v", err)
	}
	if _, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true}); err == nil || !strings.Contains(err.Error(), "support is unavailable") {
		t.Fatalf("expected unsupported doctor error, got %v", err)
	}
}
