//go:build windows

package defaults

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
)

type windowsFakeRunner struct {
	paths   map[string]bool
	outputs map[string]string
}

func (f windowsFakeRunner) LookPath(name string) (string, error) {
	if f.paths[name] {
		return `C:\Windows\System32\` + name, nil
	}
	return "", errors.New("not found")
}

func (f windowsFakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name
	for _, arg := range args {
		call += " " + arg
	}
	if output, ok := f.outputs[call]; ok {
		return output, nil
	}
	return "", errors.New("unexpected command: " + call)
}

func hasWindowsFindingID(findings []DoctorFinding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func TestWindowsReadRegValuesPreservesValueNamesWithSpaces(t *testing.T) {
	key := `HKLM\Software\RegisteredApplications`
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query ` + key: `HKEY_LOCAL_MACHINE\Software\RegisteredApplications
    Google Chrome    REG_SZ    Software\Clients\StartMenuInternet\Google Chrome\Capabilities
`,
		},
	}}

	values, err := provider.readRegValues(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if values["Google Chrome"] != `Software\Clients\StartMenuInternet\Google Chrome\Capabilities` {
		t.Fatalf("values=%+v", values)
	}
}

func TestWindowsResolveAppUsesRegisteredApplications(t *testing.T) {
	registeredKey := `HKLM\Software\RegisteredApplications`
	capabilityKey := `HKLM\Software\Clients\StartMenuInternet\Vivaldi\Capabilities`
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query ` + registeredKey: `HKEY_LOCAL_MACHINE\Software\RegisteredApplications
    Vivaldi    REG_SZ    Software\Clients\StartMenuInternet\Vivaldi\Capabilities
`,
			`reg query ` + capabilityKey: `HKEY_LOCAL_MACHINE\Software\Clients\StartMenuInternet\Vivaldi\Capabilities
    ApplicationName    REG_SZ    Vivaldi
`,
			`reg query ` + capabilityKey + `\URLAssociations`: `HKEY_LOCAL_MACHINE\Software\Clients\StartMenuInternet\Vivaldi\Capabilities\URLAssociations
    https    REG_SZ    VivaldiHTM
    http    REG_SZ    VivaldiHTM
`,
		},
	}}

	resolution, err := provider.ResolveApp(context.Background(), "vivaldi", Target{Kind: KindBrowser, Value: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.App != "VivaldiHTM" || resolution.Source != "Windows registered application" {
		t.Fatalf("resolution=%+v", resolution)
	}
}

func TestWindowsPolicyAssociationMetadataFromXMLSource(t *testing.T) {
	records, err := windowsPolicyAssociationMetadataFromXMLSource([]byte(`
<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".xhtml" ProgID="FirefoxHTML" Suggested="false" />
</DefaultAssociations>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%#v", records)
	}
	if records[0].identifier != "http" || records[0].progID != "ChromeHTML" || !records[0].suggestedSet || !records[0].suggested {
		t.Fatalf("first record=%#v", records[0])
	}
	if records[1].identifier != ".xhtml" || records[1].progID != "FirefoxHTML" || !records[1].suggestedSet || records[1].suggested {
		t.Fatalf("second record=%#v", records[1])
	}
}

func TestWindowsPolicyAssociationSignalsFromRecords(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "")
	provider := windowsProvider{}
	missing, issues, mandatory := provider.policyAssociationSignalsFromRecords([]windowsPolicyAssociationRecord{
		{identifier: "http", suggestedSet: true, suggested: true},
		{identifier: "https"},
		{identifier: ".html", suggestedSet: true, suggested: false},
	}, []string{"bad xml", "bad xml"})
	if !mandatory {
		t.Fatal("expected mandatory policy signal")
	}
	if strings.Join(missing, ",") != "application/xhtml+xml" {
		t.Fatalf("missing=%v", missing)
	}
	if len(issues) != 1 || issues[0] != "bad xml" {
		t.Fatalf("issues=%v", issues)
	}
}

func TestWindowsPolicyAssociationSignalsRequireConfiguredCallbackScheme(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "com.example.auth://oauth/return")
	provider := windowsProvider{}
	missing, _, _ := provider.policyAssociationSignalsFromRecords([]windowsPolicyAssociationRecord{
		{identifier: "http", suggestedSet: true, suggested: true},
		{identifier: "https", suggestedSet: true, suggested: true},
		{identifier: ".html", suggestedSet: true, suggested: true},
		{identifier: ".xhtml", suggestedSet: true, suggested: true},
	}, nil)
	if strings.Join(missing, ",") != "com.example.auth" {
		t.Fatalf("missing=%v", missing)
	}
	missing, _, _ = provider.policyAssociationSignalsFromRecords([]windowsPolicyAssociationRecord{
		{identifier: "http", suggestedSet: true, suggested: true},
		{identifier: "https", suggestedSet: true, suggested: true},
		{identifier: ".html", suggestedSet: true, suggested: true},
		{identifier: ".xhtml", suggestedSet: true, suggested: true},
		{identifier: "com.example.auth", suggestedSet: true, suggested: true},
	}, nil)
	if len(missing) != 0 {
		t.Fatalf("missing=%v", missing)
	}
}

func TestWindowsPolicyAssociationSuggested(t *testing.T) {
	set, value := windowsPolicyAssociationSuggested("yes")
	if !set || !value {
		t.Fatalf("yes: set=%t value=%t", set, value)
	}
	set, value = windowsPolicyAssociationSuggested("0")
	if !set || value {
		t.Fatalf("0: set=%t value=%t", set, value)
	}
}

func TestWindowsExpandWindowsEnvPath(t *testing.T) {
	t.Setenv("DFX_POLICY_DIR", `C:\Policy Files`)
	if got := expandWindowsEnvPath(`%DFX_POLICY_DIR%\defaults.xml`); got != `C:\Policy Files\defaults.xml` {
		t.Fatalf("expanded=%q", got)
	}
	if got := expandWindowsEnvPath(`%dfx_policy_dir%\defaults.xml`); got != `C:\Policy Files\defaults.xml` {
		t.Fatalf("case-insensitive expanded=%q", got)
	}
	t.Setenv("DFX_POLICY_FILE", "defaults.xml")
	if got := expandWindowsEnvPath(`$DFX_POLICY_FILE`); got != "defaults.xml" {
		t.Fatalf("dollar expanded=%q", got)
	}
	if got := expandWindowsEnvPath(`%DFX_UNKNOWN%\defaults.xml`); got != `%DFX_UNKNOWN%\defaults.xml` {
		t.Fatalf("unknown var expanded=%q", got)
	}
}

func TestWindowsPolicyAssociationRecordSetReadsExpandedPolicyPath(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + "defaults.xml"
	if err := os.WriteFile(path, []byte(`<DefaultAssociations><Association Identifier="https" ProgId="ChromeHTML" /></DefaultAssociations>`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DFX_POLICY_DIR", dir)
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`: `Associations    REG_SZ    %DFX_POLICY_DIR%\defaults.xml`,
		},
	}}

	records, issues := provider.windowsPolicyAssociationRecordSet(context.Background())
	if len(issues) != 0 {
		t.Fatalf("issues=%v", issues)
	}
	if len(records) != 1 || records[0].identifier != "https" || records[0].progID != "ChromeHTML" {
		t.Fatalf("records=%#v", records)
	}
}

func TestWindowsCurrentAssociationPolicySignals(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`: `Associations    REG_SZ    C:\policy\defaults.xml`,
		},
	}}
	signals := strings.Join(provider.currentAssociationPolicySignals(context.Background()), "; ")
	if !strings.Contains(signals, `Associations="C:\policy\defaults.xml"`) {
		t.Fatalf("policy signals=%q", signals)
	}
}

func TestWindowsPolicyProgIDSignals(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{paths: map[string]bool{"reg": true}}}
	signals := provider.windowsPolicyAssociationProgIDSignals(context.Background(), []windowsPolicyAssociationRecord{
		{identifier: "https", progID: "OldChromeHTML"},
	}, map[string]string{"https": "ChromeHTML"})
	if len(signals) != 1 || !strings.Contains(signals[0], "OldChromeHTML") {
		t.Fatalf("signals=%v", signals)
	}
}

func TestWindowsDoctorDetectsStalePolicyProgID(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`:    `Associations    REG_SZ    <DefaultAssociations><Association Identifier="https" ProgId="OldChromeHTML" ApplicationName="Old Chrome" /></DefaultAssociations>`,
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W10") {
		t.Fatalf("expected W10 finding, got %#v", report.Findings)
	}
}

func TestWindowsPolicyOverrideSignals(t *testing.T) {
	signals := windowsPolicyAssociationOverrideSignals([]windowsPolicyAssociationRecord{
		{identifier: "https", progID: "ChromeHTML"},
		{identifier: ".html", progID: "ChromeHTML"},
		{identifier: "com.example.auth", progID: "ExampleAuth"},
	}, map[string]string{
		"https":            "FirefoxURL",
		"text/html":        "ChromeHTML",
		"com.example.auth": "BrowserHTML",
	})
	joined := strings.Join(signals, "\n")
	if !strings.Contains(joined, `https policy ProgID(s) ChromeHTML differ from current mapping "FirefoxURL"`) {
		t.Fatalf("missing https override signal: %v", signals)
	}
	if !strings.Contains(joined, `com.example.auth policy ProgID(s) ExampleAuth differ from current mapping "BrowserHTML"`) {
		t.Fatalf("missing callback override signal: %v", signals)
	}
	if strings.Contains(joined, "text/html") {
		t.Fatalf("matching policy target should not signal: %v", signals)
	}
}

func TestWindowsPolicyIdentifierTargets(t *testing.T) {
	if got := strings.Join(mapWindowsPolicyIdentifierToTargets(".htm"), ","); got != "text/html" {
		t.Fatalf("targets=%q", got)
	}
	if got := strings.Join(mapWindowsPolicyIdentifierToTargets(".xht"), ","); got != "application/xhtml+xml" {
		t.Fatalf("targets=%q", got)
	}
	if got := strings.Join(mapWindowsPolicyIdentifierToTargets("com.example.auth"), ","); got != "com.example.auth" {
		t.Fatalf("targets=%q", got)
	}
}

func TestWindowsHandlerChannelInference(t *testing.T) {
	family, channel := inferWindowsHandlerBrowserChannel("MSEdgeHTM.Beta", "")
	if family != "msedgehtm" || channel != "beta" {
		t.Fatalf("family=%q channel=%q", family, channel)
	}
	family, channel = inferWindowsHandlerBrowserChannel("ChromeHTML", `C:\Apps\Chrome Dev\Application\chrome.exe`)
	if family != "chromehtml" || channel != "dev" {
		t.Fatalf("family=%q channel=%q", family, channel)
	}
}

func TestWindowsAssociationSelectionAndDivergence(t *testing.T) {
	value, source, hasHash, ok := bestAssociation([]associationEntry{
		{source: "HKCU", err: errors.New("skip")},
		{source: "HKCU", value: "ChromeHTML", hasHash: true},
		{source: "HKLM", value: "FirefoxHTML"},
	})
	if !ok || value != "ChromeHTML" || source != "HKCU" || !hasHash {
		t.Fatalf("best value=%q source=%q hasHash=%t ok=%t", value, source, hasHash, ok)
	}
	if !isDiverged([]associationEntry{{value: "ChromeHTML"}, {value: "FirefoxHTML"}}) {
		t.Fatal("expected divergence")
	}
	if !hasUsableAssociationFromSource([]associationEntry{{source: "HKCU", value: "ChromeHTML"}}, "hkcu") {
		t.Fatal("expected usable HKCU association")
	}
}

func TestWindowsAssociationCandidateSummary(t *testing.T) {
	got := associationCandidateSummary([]associationEntry{
		{source: "HKCU", value: "ChromeHTML"},
		{source: "HKLM", value: "FirefoxHTML"},
		{source: "HKLM", value: "FirefoxHTML"},
		{source: "broken", value: "Ignored", err: errors.New("skip")},
	})
	if len(got) != 2 {
		t.Fatalf("summary=%v", got)
	}
	if !strings.Contains(strings.Join(got, "; "), "ChromeHTML via HKCU") {
		t.Fatalf("summary=%v", got)
	}
}

func TestWindowsDoctorDetectsDuplicateHandlerCandidates(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
			`reg query HKLM\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`: "ProgId    REG_SZ    MSEdgeHTM",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W12") {
		t.Fatalf("expected W12 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsUserChoiceHashResetRisk(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`: "ProgId    REG_SZ    ChromeHTML\nHash      REG_SZ    abc123",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W13") {
		t.Fatalf("expected W13 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsLikely32BitHandler(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("32-bit handler path is not an architecture mismatch on 386")
	}
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML`:                                                   "HKEY_CURRENT_USER\\Software\\Classes\\ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\shell\open\command`:                                `(Default)    REG_SZ    "C:\Program Files (x86)\Chrome\Application\chrome.exe" "%1"`,
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W15") {
		t.Fatalf("expected W15 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsMixedBrowserChannels(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`:  "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`: "ProgId    REG_SZ    ChromeHTML.Beta",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W23") {
		t.Fatalf("expected W23 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsProtocolContentAndScopeDivergence(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`:  "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`: "ProgId    REG_SZ    FirefoxHTML",
			`reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice`:   "ProgId    REG_SZ    EdgeHTML",
			`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice`:   "ProgId    REG_SZ    ChromeHTML",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"W03", "W04", "W05"} {
		if !hasWindowsFindingID(report.Findings, want) {
			t.Fatalf("expected %s finding, got %#v", want, report.Findings)
		}
	}
}

func TestWindowsDoctorDetectsOrphanedProgID(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W11") {
		t.Fatalf("expected W11 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsMissingHandlerCommand(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML`:                                                   "HKEY_CURRENT_USER\\Software\\Classes\\ChromeHTML",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W19") {
		t.Fatalf("expected W19 finding, got %#v", report.Findings)
	}
}

func TestWindowsLegacyToolsAndSettingsVisibility(t *testing.T) {
	tools := windowsLegacyToolsAvailable(windowsProvider{runner: windowsFakeRunner{paths: map[string]bool{
		"assoc": true,
		"ftype": true,
	}}})
	if strings.Join(tools, ",") != "assoc,ftype" {
		t.Fatalf("tools=%v", tools)
	}
	if !windowsSettingsPageVisibilityRestrictsDefaultApps("hide:defaultapps;bluetooth") {
		t.Fatal("expected defaultapps restriction")
	}
	if windowsSettingsPageVisibilityRestrictsDefaultApps("hide:bluetooth") {
		t.Fatal("did not expect unrelated hidden page restriction")
	}
	if !windowsSettingsPageVisibilityRestrictsDefaultApps("showonly:bluetooth") {
		t.Fatal("expected showonly policy without defaultapps to restrict")
	}
	if !windowsSettingsPageVisibilityRestrictsDefaultApps("showonly:appsfeatures") {
		t.Fatal("expected appsfeatures-only visibility to restrict default-app remediation")
	}
	if windowsSettingsPageVisibilityRestrictsDefaultApps("showonly:defaultapps;appsfeatures") {
		t.Fatal("did not expect restriction when defaultapps is visible")
	}
}

func TestWindowsRemoteSessionSignals(t *testing.T) {
	t.Setenv("SESSIONNAME", "RDP-Tcp#12")
	t.Setenv("CLIENTNAME", "thin-client")
	signals := strings.Join(windowsRemoteSessionSignals(), "; ")
	if !strings.Contains(signals, "SESSIONNAME=RDP-Tcp#12") || !strings.Contains(signals, "CLIENTNAME=thin-client") {
		t.Fatalf("remote signals=%q", signals)
	}
}

func TestWindowsFeatureUpdateResetSignals(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`: "exists",
			`reg query HKLM\SYSTEM\Setup\State`: "ImageState    REG_SZ    IMAGE_STATE_SPECIALIZE_RESEAL_TO_OOBE",
		},
	}}
	signals := strings.Join(provider.windowsFeatureUpdateResetSignals(context.Background()), "; ")
	if !strings.Contains(signals, "RebootRequired") || !strings.Contains(signals, "image_state_specialize") {
		t.Fatalf("feature update signals=%q", signals)
	}
}

func TestWindowsDoctorDetectsFeatureUpdateResetRisk(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`: `Associations    REG_SZ    <DefaultAssociations><Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /><Association Identifier="https" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /><Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /><Association Identifier=".xhtml" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /></DefaultAssociations>`,
			`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade`:           "Pending    REG_SZ    1",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W28") {
		t.Fatalf("expected W28 finding, got %#v", report.Findings)
	}
}

func TestWindowsBrowserRepairToolSignal(t *testing.T) {
	if !(windowsProvider{}).windowsBrowserRepairToolSignal("ChromeDefaultRepair", `"chrome.exe" --set-default-browser`, "") {
		t.Fatal("expected browser repair tool signal")
	}
	if (windowsProvider{}).windowsBrowserRepairToolSignal("Updater", `"chrome.exe" --update`, "") {
		t.Fatal("did not expect update-only signal")
	}
}

func TestWindowsDoctorDetectsBrowserRepairPolicyConflict(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`: `Associations    REG_SZ    <DefaultAssociations><Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /></DefaultAssociations>`,
			`reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`:                               `ChromeDefaultRepair    REG_SZ    "chrome.exe" --set-default-browser`,
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W29") {
		t.Fatalf("expected W29 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsMachineOnlyPolicyDefault(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`:     `Associations    REG_SZ    C:\policy\defaults.xml`,
			`reg query HKLM\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`:   "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`:  "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\mailto\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice`:    "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xhtml\UserChoice`:   "ProgId    REG_SZ    ChromeHTML",
			`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.html\UserChoice`:    "ProgId    REG_SZ    ChromeHTML",
			`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.xhtml\UserChoice`:   "ProgId    REG_SZ    ChromeHTML",
			`reg query HKLM\Software\Classes\ChromeHTML`:                                                     "exists",
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\URLAssociations`:                        "http    REG_SZ    ChromeHTML\nhttps    REG_SZ    ChromeHTML\nmailto    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\FileAssociations`:                       ".html    REG_SZ    ChromeHTML\n.xhtml    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\shell\open\command`:                                  `"C:\Browser\browser.exe" "%1"`,
			`reg query HKCU\Software\Classes\ChromeHTML\DefaultIcon`:                                         `(Default)    REG_SZ    C:\Browser\browser.exe,0`,
			`reg query HKCU\Software\Classes\ChromeHTML\shell`:                                               `(Default)    REG_SZ    open`,
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W09") {
		t.Fatalf("expected W09 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsMailtoBrowserDivergence(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`:   "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`:  "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\mailto\UserChoice`: "ProgId    REG_SZ    MailClient",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W21") {
		t.Fatalf("expected W21 finding, got %#v", report.Findings)
	}
}

func TestWindowsDoctorDetectsCallbackSchemeBrowserLoop(t *testing.T) {
	t.Setenv("DFX_CALLBACK_SCHEME", "com.example.auth://oauth/return")
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice`:             "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`:            "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\mailto\UserChoice`:           "ProgId    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\com.example.auth\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
		},
	}}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasWindowsFindingID(report.Findings, "W30") {
		t.Fatalf("expected W30 finding, got %#v", report.Findings)
	}
}

func TestWindowsAssocDeclaresMissingTargetCapability(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\URLAssociations`: "https    REG_SZ    ChromeHTML",
		},
	}}

	ok, err := provider.assocDeclaresTargetCapability(context.Background(), "ChromeHTML", Target{Kind: KindScheme, Value: "http"})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("did not expect http capability declaration")
	}
}

func TestWindowsAssocDeclaresMimeCapabilityFromFileAssociations(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\FileAssociations`: ".html    REG_SZ    ChromeHTML\n.htm    REG_SZ    ChromeHTML",
		},
	}}
	ok, err := provider.assocDeclaresTargetCapability(context.Background(), "ChromeHTML", Target{Kind: KindMIME, Value: "text/html"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected file-association MIME capability declaration")
	}
}

func TestWindowsAssocDeclaresTargetCapability(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\URLAssociations`: "https    REG_SZ    ChromeHTML",
		},
	}}
	ok, err := provider.assocDeclaresTargetCapability(context.Background(), "ChromeHTML", Target{Kind: KindScheme, Value: "https"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected scheme capability declaration")
	}
}

func TestWindowsAssocCommandIconAndVerb(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Classes\ChromeHTML\shell\open\command`: `"C:\Browser\browser.exe" "%1"`,
			`reg query HKCU\Software\Classes\ChromeHTML\DefaultIcon`:        `(Default)    REG_SZ    C:\Browser\browser.exe,0`,
			`reg query HKCU\Software\Classes\ChromeHTML\shell`:              `(Default)    REG_SZ    open`,
		},
	}}
	command, err := provider.readAssocCommand(context.Background(), "ChromeHTML")
	if err != nil || !strings.Contains(command, `%1`) {
		t.Fatalf("command=%q err=%v", command, err)
	}
	icon, err := provider.readAssocDefaultIcon(context.Background(), "ChromeHTML")
	if err != nil || !strings.Contains(icon, `browser.exe`) {
		t.Fatalf("icon=%q err=%v", icon, err)
	}
	verb, err := provider.readAssocDefaultVerb(context.Background(), "ChromeHTML")
	if err != nil || verb != "open" {
		t.Fatalf("verb=%q err=%v", verb, err)
	}
}

func TestWindowsRegistrationAndTargetExpansion(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKLM\Software\Classes\ChromeHTML`: "exists",
		},
	}}
	if !provider.hasAssocRegistration(context.Background(), "ChromeHTML") {
		t.Fatal("expected association registration")
	}
	targets := windowsTargetsForAssociation(Target{Kind: KindBrowser, Value: "default"})
	if len(targets) != 4 {
		t.Fatalf("targets=%v", targets)
	}
	if strings.Join(mimeToExtensions("text/html"), ",") != ".html,.htm" {
		t.Fatalf("html extensions=%v", mimeToExtensions("text/html"))
	}
}

func TestWindowsFirstError(t *testing.T) {
	err := firstError([]associationEntry{
		{source: "HKCU", err: errors.New("missing")},
		{source: "HKLM", err: errors.New("missing")},
	})
	if err == nil || !strings.Contains(err.Error(), "HKCU") || !strings.Contains(err.Error(), "HKLM") {
		t.Fatalf("err=%v", err)
	}
}

func TestWindowsURIAndContainerSignals(t *testing.T) {
	if !supportsURIPayload(`"C:\Browser\browser.exe" -- "%1"`) {
		t.Fatal("expected URI placeholder support")
	}
	if supportsURIPayload(`"C:\Browser\browser.exe"`) {
		t.Fatal("did not expect URI placeholder support")
	}
	if !isLikelyAppContainerHandler("MSEdge.AppX123") {
		t.Fatal("expected AppX handler detection")
	}
	if !hasLikely32BitExecutableMarker(`"C:\Program Files (x86)\Browser\browser.exe" "%1"`) {
		t.Fatal("expected 32-bit executable marker")
	}
}

func TestWindowsFamilyDivergence(t *testing.T) {
	got := checkFamilyDivergence([]associationEntry{
		{extension: ".html", value: "ChromeHTML"},
		{extension: ".htm", value: "FirefoxHTML"},
	}, []string{".html", ".htm", ".shtml"})
	if !strings.Contains(got, `.shtml=missing`) || !strings.Contains(got, `mapped=2/3`) {
		t.Fatalf("divergence=%q", got)
	}
}

func TestWindowsSetDryRunPlansBrowserTargets(t *testing.T) {
	result, err := windowsProvider{}.Set(context.Background(), Association{
		Kind:  KindBrowser,
		Value: "default",
		App:   "ChromeHTML",
	}, SetOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry-run set should not report changed")
	}
	joined := strings.Join(result.Operations, "\n")
	for _, want := range []string{
		"HTTP -> ChromeHTML",
		"HTTPS -> ChromeHTML",
		".html -> ChromeHTML",
		".xhtml -> ChromeHTML",
		"<DefaultAssociations>",
		`<Association Identifier="http" ProgId="ChromeHTML" ApplicationName="ChromeHTML" />`,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in operations:\n%s", want, joined)
		}
	}
}

func TestWindowsSetRefusesDirectUserChoiceWrites(t *testing.T) {
	result, err := windowsProvider{}.Set(context.Background(), Association{
		Kind:  KindScheme,
		Value: "https",
		App:   "ChromeHTML",
	}, SetOptions{})
	if err == nil {
		t.Fatal("expected Windows set to refuse unsafe registry writes")
	}
	if !strings.Contains(err.Error(), "UserChoice") || !strings.Contains(err.Error(), "hash-protected") {
		t.Fatalf("error should explain UserChoice hash protection, got %v", err)
	}
	joined := strings.Join(result.Operations, "\n")
	for _, want := range []string{
		"Plan Default apps protocol assignment: HTTPS -> ChromeHTML",
		"Do not edit UserChoice registry keys directly",
		"Windows Settings > Apps > Default apps",
		"default-association XML/CSP policy",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in operations:\n%s", want, joined)
		}
	}
}

func TestWindowsDoctorFixDryRunIncludesPolicyRemediations(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`:    `Associations    REG_SZ    <DefaultAssociations><Association Identifier="https" ProgId="OldChromeHTML" ApplicationName="Old Chrome" Suggested="true" /><Association Identifier="http" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /><Association Identifier=".html" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /><Association Identifier=".xhtml" ProgId="ChromeHTML" ApplicationName="Chrome" Suggested="true" /></DefaultAssociations>`,
			`reg query HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice`: "ProgId    REG_SZ    ChromeHTML",
			`reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade`:              "Pending    REG_SZ    1",
			`reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run`:                                  `ChromeDefaultRepair    REG_SZ    "chrome.exe" --set-default-browser`,
		},
	}}

	result, err := provider.DoctorFix(context.Background(), DoctorFixOptions{Browser: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry-run fix should not report changed")
	}
	joined := strings.Join(result.Operations, "\n")
	for _, want := range []string{
		"Open Windows Settings > Apps > Default apps",
		"Remediate W10: refresh enterprise policy XML/CSP to match current browser registration identifiers",
		"Remediate W28: re-seed enterprise managed defaults after major Windows upgrades and verify web defaults in each affected user profile",
		"Remediate W29: disable or gate browser repair/reset tasks while policy-managed defaults are in force",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in operations:\n%s", want, joined)
		}
	}
}

func TestWindowsXMLAttributeEscape(t *testing.T) {
	got := windowsXMLAttributeEscape(`A&B "Browser" <Preview>`)
	if got != `A&amp;B &quot;Browser&quot; &lt;Preview&gt;` {
		t.Fatalf("escaped=%q", got)
	}
}

func TestWindowsCapabilityAuditHealthy(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Classes\ChromeHTML`:                               `HKEY_CURRENT_USER\Software\Classes\ChromeHTML`,
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities`:                  `ApplicationDescription    REG_SZ    Chrome`,
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\URLAssociations`:  "http    REG_SZ    ChromeHTML\nhttps    REG_SZ    ChromeHTML\nmyapp    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\MIMEAssociations`: "text/html    REG_SZ    ChromeHTML\napplication/xhtml+xml    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\shell\open\command`:            `(Default)    REG_SZ    "C:\Chrome\chrome.exe" "%1"`,
			`reg query HKCU\Software\Classes\ChromeHTML\DefaultIcon`:                   `(Default)    REG_SZ    "C:\Chrome\chrome.exe",0`,
		},
	}}

	audit, err := auditWindowsProgID(context.Background(), provider, "ChromeHTML", "myapp://oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if !audit.Healthy || !audit.HasRegistration || !audit.HasCapabilities || audit.Command == "" || audit.DefaultIcon == "" || len(audit.Targets) != 5 || len(audit.Issues) != 0 {
		t.Fatalf("audit=%+v", audit)
	}
}

func TestWindowsCapabilityAuditReportsMissingCapability(t *testing.T) {
	provider := windowsProvider{runner: windowsFakeRunner{
		paths: map[string]bool{"reg": true},
		outputs: map[string]string{
			`reg query HKCU\Software\Classes\ChromeHTML`:                               `HKEY_CURRENT_USER\Software\Classes\ChromeHTML`,
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities`:                  `ApplicationDescription    REG_SZ    Chrome`,
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\URLAssociations`:  "http    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\Capabilities\MIMEAssociations`: "text/html    REG_SZ    ChromeHTML\napplication/xhtml+xml    REG_SZ    ChromeHTML",
			`reg query HKCU\Software\Classes\ChromeHTML\shell\open\command`:            `(Default)    REG_SZ    "C:\Chrome\chrome.exe"`,
			`reg query HKCU\Software\Classes\ChromeHTML\DefaultIcon`:                   `(Default)    REG_SZ    "C:\Chrome\chrome.exe",0`,
		},
	}}

	audit, err := auditWindowsProgID(context.Background(), provider, "ChromeHTML", "")
	if err != nil {
		t.Fatal(err)
	}
	if audit.Healthy {
		t.Fatalf("expected unhealthy audit: %+v", audit)
	}
	joined := strings.Join(audit.Issues, "\n")
	for _, want := range []string{
		"scheme:https capability is not declared",
		"open command does not include a URI/file payload placeholder",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in issues:\n%s", want, joined)
		}
	}
}
