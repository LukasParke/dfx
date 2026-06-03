//go:build darwin

package defaults

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type darwinFakeRunner struct {
	paths   map[string]bool
	outputs map[string]string
}

func (f *darwinFakeRunner) LookPath(name string) (string, error) {
	if f.paths[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f *darwinFakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name
	for _, arg := range args {
		call += " " + arg
	}
	if output, ok := f.outputs[call]; ok {
		return output, nil
	}
	return "", errors.New("unexpected command: " + call)
}

func hasDarwinFindingID(findings []DoctorFinding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func darwinBrowserLaunchServicesJSON(app string, extraHandlers ...string) string {
	handlers := []string{
		`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"` + app + `"}`,
		`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"` + app + `"}`,
		`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"` + app + `"}`,
		`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"` + app + `"}`,
	}
	handlers = append(handlers, extraHandlers...)
	return `{"LSHandlers":[` + strings.Join(handlers, ",") + `]}`
}

func darwinDoctorProviderWithHandlers(t *testing.T, paths map[string]bool, handlersJSON string) (darwinProvider, *darwinFakeRunner) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	runner := &darwinFakeRunner{
		paths:   paths,
		outputs: map[string]string{},
	}
	provider := darwinProvider{runner: runner}
	cachePath := provider.launchServicesPlistPath()
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.outputs["plutil -convert json -o - "+cachePath] = handlersJSON
	return provider, runner
}

func TestDarwinContentTypeSignatureUsesMapMembership(t *testing.T) {
	got := darwinWebContentTypeDeclarationSignature(map[string]struct{}{
		"public.html":  {},
		"public.xhtml": {},
	})
	if got != "application/xhtml+xml,text/html" {
		t.Fatalf("signature=%q", got)
	}
}

func TestDarwinChannelInference(t *testing.T) {
	family, channel := inferDarwinBrowserChannel("com.google.Chrome.canary")
	if family != "com.google.chrome" || channel != "canary" {
		t.Fatalf("family=%q channel=%q", family, channel)
	}
	family, channel = inferDarwinBrowserChannel("org.mozilla.firefox")
	if family != "org.mozilla.firefox" || channel != "stable" {
		t.Fatalf("family=%q channel=%q", family, channel)
	}
}

func TestDarwinResolveAppUsesApplicationName(t *testing.T) {
	runner := &darwinFakeRunner{
		paths: map[string]bool{"osascript": true},
		outputs: map[string]string{
			`osascript -e id of application "vivaldi"`: "com.vivaldi.Vivaldi",
			`osascript -e id of application "Vivaldi"`: "com.vivaldi.Vivaldi",
		},
	}
	provider := darwinProvider{runner: runner}

	resolution, err := provider.ResolveApp(context.Background(), "vivaldi", Target{Kind: KindBrowser, Value: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.App != "com.vivaldi.Vivaldi" || resolution.Source != "macOS application name" {
		t.Fatalf("resolution=%+v", resolution)
	}
}

func TestDarwinResolveAppUsesKnownAlias(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{paths: map[string]bool{}}}
	resolution, err := provider.ResolveApp(context.Background(), "vivaldi", Target{Kind: KindBrowser, Value: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.App != "com.vivaldi.Vivaldi" || resolution.Source != "known macOS browser alias" {
		t.Fatalf("resolution=%+v", resolution)
	}
}

func TestDarwinResolveAppUsesKnownAliasPrefix(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{paths: map[string]bool{}}}
	resolution, err := provider.ResolveApp(context.Background(), "viv", Target{Kind: KindBrowser, Value: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.App != "com.vivaldi.Vivaldi" || resolution.Source != "known macOS browser alias" {
		t.Fatalf("resolution=%+v", resolution)
	}
}

func TestDarwinDoctorReportsMixedBrowserChannels(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.google.Chrome"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.google.Chrome.canary"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.google.Chrome"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.google.Chrome.canary"}`+
			`]}`,
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M04") {
		t.Fatalf("expected M04 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorReportsUpdateReclaimRisk(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.other.browser"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.other.browser"}`+
			`]}`,
	)
	cacheTime := time.Now()
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"com.example.browser", "com.other.browser"} {
		bundlePath := filepath.Join(t.TempDir(), app+".app")
		infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
		updaterPath := filepath.Join(bundlePath, "Contents", "Helpers", "ExampleUpdater")
		if err := os.MkdirAll(filepath.Dir(updaterPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(updaterPath, []byte("updater"), 0o700); err != nil {
			t.Fatal(err)
		}
		plistTime := cacheTime.Add(-time.Hour)
		if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
			t.Fatal(err)
		}
		runner.outputs[`osascript -e id of application id "`+app+`"`] = app
		runner.outputs[`osascript -e POSIX path of application id "`+app+`"`] = bundlePath
		runner.outputs["plutil -convert json -o - "+infoPath] = `{
			"SUFeedURL":"https://updates.example.test/feed.xml",
			"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
			"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
		}`
	}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M05") {
		t.Fatalf("expected M05 finding, got %#v", report.Findings)
	}
}

func TestDarwinRoleMismatch(t *testing.T) {
	roles := map[string]string{
		"LSHandlerRoleAll":    "com.example.browser",
		"LSHandlerRoleViewer": "com.other.browser",
	}
	if !hasRoleMismatch(roles) {
		t.Fatal("expected role mismatch")
	}
	if got := roleSummary(roles); !strings.Contains(got, "All=") || !strings.Contains(got, "Viewer=") {
		t.Fatalf("summary=%q", got)
	}
}

func TestDarwinTargetRoleCollision(t *testing.T) {
	issue, err := darwinProvider{}.getTargetRoleCollisionFromHandlers(Target{Kind: KindScheme, Value: "https"}, []map[string]any{
		{"LSHandlerURLScheme": "https", "LSHandlerRoleAll": "com.example.browser"},
		{"LSHandlerURLScheme": "https", "LSHandlerRoleAll": "com.other.browser"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(issue, "detected 2 unique handlers") {
		t.Fatalf("issue=%q", issue)
	}
}

func TestDarwinPromptPartialCoverageSignal(t *testing.T) {
	got := macosBrowserPromptPartialCoverageSignal(
		"com.example.browser",
		"com.example.browser",
		"com.other.viewer",
		"",
		nil,
		errors.New("missing xhtml"),
	)
	if !strings.Contains(got, `text/html="com.other.viewer"`) || !strings.Contains(got, "application/xhtml+xml missing") {
		t.Fatalf("signal=%q", got)
	}
}

func TestDarwinDoctorDetectsBrowserPromptPartialCoverage(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.other.browser"}`+
			`]}`,
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M13") {
		t.Fatalf("expected M13 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsSchemeFileAndUTIDivergence(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.other.browser"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.other.browser"}`+
			`]}`,
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"M01", "M06"} {
		if !hasDarwinFindingID(report.Findings, want) {
			t.Fatalf("expected %s finding, got %#v", want, report.Findings)
		}
	}
}

func TestDarwinDoctorDetectsAliasRoleAndCollisionIssues(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser","LSHandlerRoleViewer":"com.other.browser"},`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.third.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"public.html","LSHandlerRoleAll":"com.other.browser"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.example.browser"}`+
			`]}`,
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"M07", "M08", "M24"} {
		if !hasDarwinFindingID(report.Findings, want) {
			t.Fatalf("expected %s finding, got %#v", want, report.Findings)
		}
	}
}

func TestDarwinDoctorDetectsEnvironmentAndSessionContext(t *testing.T) {
	t.Setenv("TERM_PROGRAM", "Terminal")
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1 127.0.0.1 2")
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"M21", "M22"} {
		if !hasDarwinFindingID(report.Findings, want) {
			t.Fatalf("expected %s finding, got %#v", want, report.Findings)
		}
	}
}

func TestDarwinDoctorDetectsMalformedLaunchServicesCache(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	runner.outputs["plutil -convert json -o - "+provider.launchServicesPlistPath()] = `{"LSHandlers":`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M23") {
		t.Fatalf("expected M23 finding, got %#v", report.Findings)
	}
}

func TestDarwinManifestClaimChecks(t *testing.T) {
	req := &darwinAppManifestRequirement{
		schemes: map[string]struct{}{"http": {}, "https": {}},
		mimes:   map[string]struct{}{"text/html": {}, "application/xhtml+xml": {}},
	}
	plist := map[string]any{
		"CFBundleURLTypes": []any{
			map[string]any{"CFBundleURLSchemes": []any{"http"}},
		},
		"CFBundleDocumentTypes": []any{
			map[string]any{"LSItemContentTypes": []any{"public.html"}},
		},
	}
	missingSchemes, missingMimes := darwinProvider{}.missingBrowserManifestClaimsFromInfo(plist, req)
	if strings.Join(missingSchemes, ",") != "https" {
		t.Fatalf("missing schemes=%v", missingSchemes)
	}
	if strings.Join(missingMimes, ",") != "application/xhtml+xml" {
		t.Fatalf("missing mimes=%v", missingMimes)
	}
}

func TestDarwinMalformedManifestDeclarationIssues(t *testing.T) {
	urlIssues, documentIssues := darwinMalformedManifestDeclarationIssues(map[string]any{
		"CFBundleURLTypes": []any{
			map[string]any{"CFBundleURLSchemes": []any{"https", "bad scheme"}},
			"not-a-dictionary",
			map[string]any{},
		},
		"CFBundleDocumentTypes": []any{
			map[string]any{"LSItemContentTypes": []any{"public.html", "bad type"}},
			map[string]any{"CFBundleTypeExtensions": []any{"html", "bad/ext"}},
			map[string]any{},
		},
	})
	joinedURL := strings.Join(urlIssues, "\n")
	for _, want := range []string{
		`CFBundleURLTypes[0] has invalid scheme "bad scheme"`,
		"CFBundleURLTypes[1] is not a dictionary",
		"CFBundleURLTypes[2] has no CFBundleURLSchemes",
	} {
		if !strings.Contains(joinedURL, want) {
			t.Fatalf("missing URL issue %q in %v", want, urlIssues)
		}
	}
	joinedDocuments := strings.Join(documentIssues, "\n")
	for _, want := range []string{
		`CFBundleDocumentTypes[0] has invalid content type "bad type"`,
		`CFBundleDocumentTypes[1] has invalid file extension "bad/ext"`,
		"CFBundleDocumentTypes[2] has no LSItemContentTypes or CFBundleTypeExtensions",
	} {
		if !strings.Contains(joinedDocuments, want) {
			t.Fatalf("missing document issue %q in %v", want, documentIssues)
		}
	}
}

func TestDarwinManifestDeclarationIssuesAllowValidForms(t *testing.T) {
	urlIssues, documentIssues := darwinMalformedManifestDeclarationIssues(map[string]any{
		"CFBundleURLTypes": []any{
			map[string]any{"CFBundleURLSchemes": []any{"https", "example.app+v1"}},
		},
		"CFBundleDocumentTypes": []any{
			map[string]any{"LSItemContentTypes": []any{"public.html", "com.example.web-content", "text/html"}},
			map[string]any{"CFBundleTypeExtensions": []any{"html", ".xhtml", "x-test_1"}},
		},
	})
	if len(urlIssues) != 0 || len(documentIssues) != 0 {
		t.Fatalf("urlIssues=%v documentIssues=%v", urlIssues, documentIssues)
	}
}

func TestDarwinNormalizeMacContentTypeAliases(t *testing.T) {
	htmlAliases := strings.Join(normalizeMacContentType("text/html"), ",")
	if htmlAliases != "text/html,public.html" {
		t.Fatalf("html aliases=%q", htmlAliases)
	}
	xhtmlAliases := strings.Join(normalizeMacContentType("application/xhtml+xml"), ",")
	if !strings.Contains(xhtmlAliases, "public.xhtml") || !strings.Contains(xhtmlAliases, "public.xhtml+xml") {
		t.Fatalf("xhtml aliases=%q", xhtmlAliases)
	}
}

func TestDarwinLoadLaunchServicesMalformedCache(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{
		paths: map[string]bool{"plutil": true},
		outputs: map[string]string{
			"plutil -convert json -o - /tmp/ls.plist": `{bad json`,
		},
	}}
	_, err := provider.loadLaunchServicesHandlersFromPath(context.Background(), "/tmp/ls.plist")
	if err == nil || !strings.Contains(err.Error(), "parse LaunchServices cache") {
		t.Fatalf("err=%v", err)
	}
}

func TestDarwinEnvironmentAndSessionSignals(t *testing.T) {
	t.Setenv("TERM_PROGRAM", "Terminal")
	t.Setenv("SSH_CONNECTION", "127.0.0.1 1 127.0.0.1 2")
	provider := darwinProvider{}
	if got := strings.Join(provider.macosEnvironmentSignals(), "; "); !strings.Contains(got, "TERM_PROGRAM=Terminal") {
		t.Fatalf("environment signals=%q", got)
	}
	if got := strings.Join(provider.macosSessionSignals(), "; "); !strings.Contains(got, "SSH_CONNECTION set") {
		t.Fatalf("session signals=%q", got)
	}
}

func TestDarwinLaunchServicesPolicySignal(t *testing.T) {
	payload := map[string]any{
		"PayloadContent": []any{
			map[string]any{"com.apple.LaunchServices": map[string]any{"LSHandlers": []any{}}},
		},
	}
	if !hasLaunchServicesPolicySignal(payload) {
		t.Fatal("expected LaunchServices policy signal")
	}
}

func TestDarwinDoctorDetectsMissingOsascript(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M19") {
		t.Fatalf("expected M19 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorContinuesCacheChecksWithoutOsascript(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "com.example.callback://oauth/return")
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		darwinBrowserLaunchServicesJSON(
			"com.example.browser",
			`{"LSHandlerURLScheme":"com.example.callback","LSHandlerRoleAll":"com.example.browser"}`,
		),
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M19") {
		t.Fatalf("expected M19 finding, got %#v", report.Findings)
	}
	if !hasDarwinFindingID(report.Findings, "M30") {
		t.Fatalf("expected M30 finding despite missing osascript, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsManagedLaunchServicesPolicy(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(home, "Library", "Managed Preferences", "com.apple.LaunchServices.plist")
	if err := os.MkdirAll(filepath.Dir(policyPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner.outputs["plutil -convert json -o - "+policyPath] = `{"com.apple.LaunchServices":{"LSHandlers":[]}}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M12") {
		t.Fatalf("expected M12 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorReportsAPIDriftAdvisory(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "sw_vers": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	runner.outputs["sw_vers -productVersion"] = "16.0"

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M20") {
		t.Fatalf("expected M20 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsStaleLaunchServicesReference(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.missing.browser"),
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"M02", "M09", "M26"} {
		if !hasDarwinFindingID(report.Findings, want) {
			t.Fatalf("expected %s finding, got %#v", want, report.Findings)
		}
	}
}

func TestDarwinDoctorDetectsMissingURLSchemeManifestClaim(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now()
	plistTime := cacheTime.Add(-time.Hour)
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.example.browser"`] = "com.example.browser"
	runner.outputs[`osascript -e POSIX path of application id "com.example.browser"`] = bundlePath
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M03") {
		t.Fatalf("expected M03 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsLaunchServicesRegistrationLag(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now().Add(-2 * time.Hour)
	plistTime := time.Now()
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.example.browser"`] = "com.example.browser"
	runner.outputs[`osascript -e POSIX path of application id "com.example.browser"`] = bundlePath
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M10") {
		t.Fatalf("expected M10 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsBrowserArchitectureMismatch(t *testing.T) {
	archOutput := ""
	switch runtime.GOARCH {
	case "arm64":
		archOutput = "Non-fat file: Browser is architecture: x86_64"
	case "amd64", "386":
		archOutput = "Non-fat file: Browser is architecture: arm64"
	default:
		t.Skipf("no architecture mismatch expectation for GOARCH=%s", runtime.GOARCH)
	}

	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true, "lipo": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	executablePath := filepath.Join(bundlePath, "Contents", "MacOS", "Browser")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now()
	plistTime := cacheTime.Add(-time.Hour)
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.example.browser"`] = "com.example.browser"
	runner.outputs[`osascript -e POSIX path of application id "com.example.browser"`] = bundlePath
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleExecutable":"Browser",
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`
	runner.outputs["lipo -info "+executablePath] = archOutput

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M16") {
		t.Fatalf("expected M16 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsSandboxPathRisk(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now()
	plistTime := cacheTime.Add(-time.Hour)
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.example.browser"`] = "com.example.browser"
	runner.outputs[`osascript -e POSIX path of application id "com.example.browser"`] = bundlePath
	runner.outputs["codesign -d --entitlements :- -- "+bundlePath] = `
		<plist><dict>
			<key>com.apple.security.app-sandbox</key><true/>
		</dict></plist>`
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M11") {
		t.Fatalf("expected M11 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsProviderSyncedBrowserPath(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(home, "Library", "CloudStorage", "Example.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now()
	plistTime := cacheTime.Add(-time.Hour)
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.example.browser"`] = "com.example.browser"
	runner.outputs[`osascript -e POSIX path of application id "com.example.browser"`] = bundlePath
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M15") {
		t.Fatalf("expected M15 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsBrowserProfileDeepLinkRisk(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.google.Chrome"),
	)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	localStatePath := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Local State")
	if err := os.MkdirAll(filepath.Dir(localStatePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localStatePath, []byte(`{"profile":{"last_used":"Profile 2","info_cache":{"Default":{},"Profile 2":{}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "Chrome.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now()
	plistTime := cacheTime.Add(-time.Hour)
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.google.Chrome"`] = "com.google.Chrome"
	runner.outputs[`osascript -e POSIX path of application id "com.google.Chrome"`] = bundlePath
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M25") {
		t.Fatalf("expected M25 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsSigningAndNotarizationRisk(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true, "codesign": true, "spctl": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	bundlePath := filepath.Join(t.TempDir(), "Example.app")
	infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheTime := time.Now()
	plistTime := cacheTime.Add(-time.Hour)
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	runner.outputs[`osascript -e id of application id "com.example.browser"`] = "com.example.browser"
	runner.outputs[`osascript -e POSIX path of application id "com.example.browser"`] = bundlePath
	runner.outputs["plutil -convert json -o - "+infoPath] = `{
		"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
		"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
	}`

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M28") {
		t.Fatalf("expected M28 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsConflictingUTIDeclarations(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.other.browser"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.other.browser"}`+
			`]}`,
	)
	cacheTime := time.Now()
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	bundles := map[string]string{
		"com.example.browser": `{
			"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
			"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
		}`,
		"com.other.browser": `{
			"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
			"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html"]}]
		}`,
	}
	for app, plistJSON := range bundles {
		bundlePath := filepath.Join(t.TempDir(), app+".app")
		infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
		if err := os.MkdirAll(filepath.Dir(infoPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
			t.Fatal(err)
		}
		plistTime := cacheTime.Add(-time.Hour)
		if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
			t.Fatal(err)
		}
		runner.outputs[`osascript -e id of application id "`+app+`"`] = app
		runner.outputs[`osascript -e POSIX path of application id "`+app+`"`] = bundlePath
		runner.outputs["plutil -convert json -o - "+infoPath] = plistJSON
	}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M29") {
		t.Fatalf("expected M29 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsUserSystemLaunchServicesConflict(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	runner.outputs["plutil -convert json -o - "+provider.launchServicesSystemPlistPath()] = darwinBrowserLaunchServicesJSON("com.other.browser")

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M14") {
		t.Fatalf("expected M14 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsEndpointSecurityInterception(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true, "systemextensionsctl": true},
		darwinBrowserLaunchServicesJSON("com.example.browser"),
	)
	runner.outputs["systemextensionsctl list"] = "enabled active teamID com.vendor.EndpointSecurity (EndpointSecurity)"

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M27") {
		t.Fatalf("expected M27 finding, got %#v", report.Findings)
	}
}

func TestDarwinDoctorDetectsCallbackSchemeBrowserLoop(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "com.example.callback:")
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		darwinBrowserLaunchServicesJSON(
			"com.example.browser",
			`{"LSHandlerURLScheme":"com.example.callback","LSHandlerRoleAll":"com.example.browser"}`,
		),
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M30") {
		t.Fatalf("expected M30 finding, got %#v", report.Findings)
	}
}

func TestDarwinDeclaredContentTypesFromInfoMapsExtensions(t *testing.T) {
	declared := darwinDeclaredContentTypesFromInfo(map[string]any{
		"CFBundleDocumentTypes": []any{
			map[string]any{"CFBundleTypeExtensions": []any{"html", ".xhtml"}},
		},
	})
	for _, want := range []string{"text/html", "public.html", "application/xhtml+xml", "public.xhtml", "public.xhtml+xml"} {
		if _, ok := declared[want]; !ok {
			t.Fatalf("missing declared content type %q in %#v", want, declared)
		}
	}
}

func TestDarwinSandboxEntitlementParsing(t *testing.T) {
	entitlements := `
<plist><dict>
  <key>com.apple.security.app-sandbox</key><true/>
  <key>com.apple.security.files.user-selected.read-only</key><true/>
</dict></plist>`
	if !plistHasEntitlementTrue(entitlements, "com.apple.security.app-sandbox") {
		t.Fatal("expected sandbox entitlement")
	}
	if !plistHasSandboxFileAccess(entitlements) {
		t.Fatal("expected file access entitlement")
	}
}

func TestDarwinLaunchServicesFreshnessSignal(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "Browser.app")
	contents := filepath.Join(bundlePath, "Contents")
	if err := os.MkdirAll(contents, 0o755); err != nil {
		t.Fatal(err)
	}
	plistPath := filepath.Join(contents, "Info.plist")
	if err := os.WriteFile(plistPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	plistTime := time.Now().Add(-30 * time.Minute)
	cacheTime := plistTime.Add(-5 * time.Minute)
	if err := os.Chtimes(plistPath, plistTime, plistTime); err != nil {
		t.Fatal(err)
	}
	got := darwinProvider{}.macosLaunchServicesFreshnessSignal(bundlePath, cacheTime)
	if !strings.Contains(got, "Browser.app changed") {
		t.Fatalf("freshness signal=%q", got)
	}
}

func TestDarwinRecentBundleChangeSignal(t *testing.T) {
	dir := t.TempDir()
	contents := filepath.Join(dir, "Browser.app", "Contents")
	if err := os.MkdirAll(contents, 0o755); err != nil {
		t.Fatal(err)
	}
	plistPath := filepath.Join(contents, "Info.plist")
	if err := os.WriteFile(plistPath, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := darwinProvider{}.recentBundleChangeSignal(filepath.Dir(contents), time.Hour)
	if !strings.Contains(got, "Info.plist changed recently") {
		t.Fatalf("recent bundle signal=%q", got)
	}
}

func TestDarwinUTIDeclarationConflict(t *testing.T) {
	provider := darwinProvider{}
	got := provider.macosUTIDeclarationConflict(map[string]string{
		"com.example.a": "text/html",
		"com.example.b": "application/xhtml+xml,text/html",
	})
	if !strings.Contains(got, "active web handler declaration signatures differ") {
		t.Fatalf("conflict=%q", got)
	}
}

func TestDarwinProviderPathSignal(t *testing.T) {
	provider := darwinProvider{}
	got := provider.macosProviderPathSignal("/Users/me/Library/CloudStorage/Example.app")
	if !strings.Contains(got, "cloud-synced storage") {
		t.Fatalf("provider path signal=%q", got)
	}
}

func TestDarwinAPIDriftSignal(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{
		paths: map[string]bool{"sw_vers": true},
		outputs: map[string]string{
			"sw_vers -productVersion": "16.0",
		},
	}}
	got := provider.macosAPIDriftSignal(context.Background())
	if !strings.Contains(got, "macOS 16.0 detected") {
		t.Fatalf("api drift signal=%q", got)
	}
}

func TestDarwinBrowserArchitectureSignal(t *testing.T) {
	bundlePath := filepath.Join(t.TempDir(), "Browser.app")
	executablePath := filepath.Join(bundlePath, "Contents", "MacOS", "Browser")
	provider := darwinProvider{runner: &darwinFakeRunner{
		paths: map[string]bool{"plutil": true, "lipo": true},
		outputs: map[string]string{
			"plutil -convert json -o - " + filepath.Join(bundlePath, "Contents", "Info.plist"): `{"CFBundleExecutable":"Browser"}`,
			"lipo -info " + executablePath: "Non-fat file: Browser is architecture: arm64",
		},
	}}
	got := provider.macosBrowserArchitectureSignal(context.Background(), bundlePath)
	if runtime.GOARCH == "amd64" || runtime.GOARCH == "386" {
		if !strings.Contains(got, "Apple Silicon-only") {
			t.Fatalf("architecture signal=%q", got)
		}
	}
}

func TestDarwinSignatureSignals(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{
		paths: map[string]bool{"codesign": true, "spctl": true},
	}}
	notarization, signature := provider.macosSignatureSignals(context.Background(), "/Applications/Browser.app")
	if !strings.Contains(notarization, "spctl") || !strings.Contains(signature, "codesign") {
		t.Fatalf("notarization=%q signature=%q", notarization, signature)
	}
}

func TestDarwinSetDryRunPlansBrowserTargets(t *testing.T) {
	result, err := darwinProvider{}.Set(context.Background(), Association{
		Kind:  KindBrowser,
		Value: "default",
		App:   "com.example.browser",
	}, SetOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry-run set should not report changed")
	}
	joined := strings.Join(result.Operations, "\n")
	for _, want := range []string{
		"http -> com.example.browser",
		"https -> com.example.browser",
		"text/html -> com.example.browser",
		"application/xhtml+xml -> com.example.browser",
		"duti preview: duti -s com.example.browser public.html all",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in operations:\n%s", want, joined)
		}
	}
}

func TestDarwinDoctorFixDryRunIncludesFindingRemediation(t *testing.T) {
	provider, runner := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true, "osascript": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.other.browser"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.other.browser"}`+
			`]}`,
	)
	cacheTime := time.Now()
	if err := os.Chtimes(provider.launchServicesPlistPath(), cacheTime, cacheTime); err != nil {
		t.Fatal(err)
	}
	for _, app := range []string{"com.example.browser", "com.other.browser"} {
		bundlePath := filepath.Join(t.TempDir(), app+".app")
		infoPath := filepath.Join(bundlePath, "Contents", "Info.plist")
		updaterPath := filepath.Join(bundlePath, "Contents", "Helpers", "ExampleUpdater")
		if err := os.MkdirAll(filepath.Dir(updaterPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(infoPath, []byte("plist"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(updaterPath, []byte("updater"), 0o700); err != nil {
			t.Fatal(err)
		}
		plistTime := cacheTime.Add(-time.Hour)
		if err := os.Chtimes(infoPath, plistTime, plistTime); err != nil {
			t.Fatal(err)
		}
		runner.outputs[`osascript -e id of application id "`+app+`"`] = app
		runner.outputs[`osascript -e POSIX path of application id "`+app+`"`] = bundlePath
		runner.outputs["plutil -convert json -o - "+infoPath] = `{
			"SUFeedURL":"https://updates.example.test/feed.xml",
			"CFBundleURLTypes":[{"CFBundleURLSchemes":["http","https"]}],
			"CFBundleDocumentTypes":[{"LSItemContentTypes":["public.html","public.xhtml"]}]
		}`
	}

	result, err := provider.DoctorFix(context.Background(), DoctorFixOptions{Browser: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry-run fix should not report changed")
	}
	joined := strings.Join(result.Operations, "\n")
	for _, want := range []string{
		"Open System Settings > Desktop & Dock",
		"Remediate M05: after browser updates, reapply the intended browser default across http, https, text/html, and application/xhtml+xml together",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in operations:\n%s", want, joined)
		}
	}
}

func TestDarwinTargetsForAssociation(t *testing.T) {
	targets := darwinTargetsForAssociation(Target{Kind: KindScheme, Value: "https"})
	if len(targets) != 4 {
		t.Fatalf("targets=%v", targets)
	}
	targets = darwinTargetsForAssociation(Target{Kind: KindMIME, Value: "text/plain"})
	if len(targets) != 1 || targets[0].Value != "text/plain" {
		t.Fatalf("single target=%v", targets)
	}
}

func TestDarwinBundlePathHelpers(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{
		paths: map[string]bool{"osascript": true},
		outputs: map[string]string{
			`osascript -e POSIX path of application id "com.example.browser"`: "/Applications/Example.app",
		},
	}}
	path, err := provider.bundlePathForID(context.Background(), "com.example.browser")
	if err != nil || path != "/Applications/Example.app" {
		t.Fatalf("path=%q err=%v", path, err)
	}
	plistPath, err := provider.bundleInfoPlistPath(context.Background(), "com.example.browser")
	if err != nil || !strings.HasSuffix(plistPath, "Example.app/Contents/Info.plist") {
		t.Fatalf("plist=%q err=%v", plistPath, err)
	}
}

func TestDarwinChromiumProfileSignals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Local State")
	payload := `{"profile":{"last_used":"Profile 2","info_cache":{"Default":{},"Profile 2":{}}}}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	signals := darwinProvider{}.chromiumProfileSignals("Chrome", path)
	if len(signals) != 2 {
		t.Fatalf("signals=%v", signals)
	}
}

func TestDarwinContentTypeTargetMatchesDirectUTI(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"public.html","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"public.xhtml","LSHandlerRoleAll":"com.example.browser"}`+
			`]}`,
	)

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy report, findings=%v", report.Findings)
	}
}

func TestDarwinGetMapsMIMEToContentType(t *testing.T) {
	provider := darwinProvider{runner: &darwinFakeRunner{paths: map[string]bool{"duti": true, "plutil": true},
		outputs: map[string]string{
			"duti -q uti text/html": "public.html\n",
		},
	}}
	if !provider.canReadLaunchServices() {
		t.Skip("LaunchServices cache is not readable on this runner")
	}
	got, err := provider.Get(context.Background(), Target{Kind: KindMIME, Value: "text/html"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "public.html" {
		t.Fatalf("got=%q", got)
	}
}

func TestDarwinDoctorContentType(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerContentType":"public.plain-text","LSHandlerRoleAll":"com.example.editor","LSHandlerRoleViewer":"com.other.editor"}`+
			`]}`,
	)
	report, err := provider.Doctor(context.Background(), DoctorOptions{ContentType: "public.plain-text"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M31") {
		t.Fatalf("expected M31 finding, got %#v", report.Findings)
	}
	if report.Scope != "content-type:public.plain-text" {
		t.Fatalf("scope=%q", report.Scope)
	}
}

func TestDarwinDoctorMIME(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerContentType":"text/plain","LSHandlerRoleAll":"com.example.editor"}`+
			`]}`,
	)
	if !provider.canReadLaunchServices() {
		t.Skip("LaunchServices cache is not readable on this runner")
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{MIME: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scope != "mime:text/plain" {
		t.Fatalf("scope=%q", report.Scope)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy report, findings=%v", report.Findings)
	}
}

func TestDarwinDoctorScheme(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"myapp","LSHandlerRoleAll":"com.example.app","LSHandlerRoleViewer":"com.other.app"}`+
			`]}`,
	)
	report, err := provider.Doctor(context.Background(), DoctorOptions{Scheme: "myapp"})
	if err != nil {
		t.Fatal(err)
	}
	if !hasDarwinFindingID(report.Findings, "M32") {
		t.Fatalf("expected M32 finding, got %#v", report.Findings)
	}
	if report.Scope != "scheme:myapp" {
		t.Fatalf("scope=%q", report.Scope)
	}
}

func TestDarwinDoctorAll(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerURLScheme":"http","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"https","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"text/html","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerContentType":"application/xhtml+xml","LSHandlerRoleAll":"com.example.browser"},`+
			`{"LSHandlerURLScheme":"myapp","LSHandlerRoleAll":"com.example.app"},`+
			`{"LSHandlerContentType":"public.plain-text","LSHandlerRoleAll":"com.example.editor"}`+
			`]}`,
	)
	report, err := provider.Doctor(context.Background(), DoctorOptions{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scope != "all" {
		t.Fatalf("scope=%q", report.Scope)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy all-report, findings=%v", report.Findings)
	}
	if !hasDarwinFindingID(report.Findings, "M19") {
		t.Fatalf("expected M19 finding from sub-doctors, got %#v", report.Findings)
	}
}

func TestDarwinDoctorFixContentType(t *testing.T) {
	provider, _ := darwinDoctorProviderWithHandlers(t,
		map[string]bool{"plutil": true},
		`{"LSHandlers":[`+
			`{"LSHandlerContentType":"public.plain-text","LSHandlerRoleAll":"com.example.editor"}`+
			`]}`,
	)
	result, err := provider.DoctorFix(context.Background(), DoctorFixOptions{ContentType: "public.plain-text", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry-run fix should not report changed")
	}
	joined := strings.Join(result.Operations, "\n")
	if !strings.Contains(joined, "public.plain-text") {
		t.Fatalf("missing content-type in operations:\n%s", joined)
	}
}
