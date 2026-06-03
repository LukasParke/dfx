//go:build linux

package defaults

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeRunner struct {
	paths    map[string]bool
	runs     []string
	errors   map[string]error
	outputs  map[string]string
	outputFn func(string) (string, bool)
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.paths[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name
	for _, arg := range args {
		call += " " + arg
	}
	f.runs = append(f.runs, call)
	if err, ok := f.errors[call]; ok {
		return "", err
	}
	if f.outputFn != nil {
		if output, ok := f.outputFn(call); ok {
			return output, nil
		}
	}
	if output, ok := f.outputs[call]; ok {
		return output, nil
	}
	return "firefox.desktop", nil
}

func TestLinuxSchemeUsesXSchemeHandler(t *testing.T) {
	target := Target{Kind: KindScheme, Value: "https"}
	if got := linuxAssociationName(target); got != "x-scheme-handler/https" {
		t.Fatalf("association=%q", got)
	}
}

func TestLinuxSetSyncsBrowserScheme(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"xdg-mime": true, "xdg-settings": true}}
	provider := linuxProvider{runner: runner}

	_, err := provider.Set(context.Background(), Association{Kind: KindScheme, Value: "https", App: "firefox.desktop"}, SetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"xdg-mime default firefox.desktop x-scheme-handler/http",
		"xdg-mime default firefox.desktop x-scheme-handler/https",
		"xdg-mime default firefox.desktop text/html",
		"xdg-mime default firefox.desktop application/xhtml+xml",
		"xdg-settings set default-web-browser firefox.desktop",
	}
	if !reflect.DeepEqual(runner.runs, want) {
		t.Fatalf("runs=%v", runner.runs)
	}
}

func TestLinuxSetBrowserUpdatesOAuthRelevantDefaults(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"xdg-mime": true, "xdg-settings": true}}
	provider := linuxProvider{runner: runner}

	_, err := provider.Set(context.Background(), Association{Kind: KindBrowser, Value: "default", App: "firefox.desktop"}, SetOptions{})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"xdg-mime default firefox.desktop x-scheme-handler/http",
		"xdg-mime default firefox.desktop x-scheme-handler/https",
		"xdg-mime default firefox.desktop text/html",
		"xdg-mime default firefox.desktop application/xhtml+xml",
		"xdg-settings set default-web-browser firefox.desktop",
	}
	if !reflect.DeepEqual(runner.runs, want) {
		t.Fatalf("runs=%v", runner.runs)
	}
}

func TestLinuxDryRunDoesNotRunCommands(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{"xdg-mime": true, "xdg-settings": true}}
	provider := linuxProvider{runner: runner}

	result, err := provider.Set(context.Background(), Association{Kind: KindScheme, Value: "https", App: "firefox.desktop"}, SetOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry run should not report changed")
	}
	if len(runner.runs) != 0 {
		t.Fatalf("unexpected runs=%v", runner.runs)
	}
}

func TestLinuxDryRunDoesNotRequireXdgMime(t *testing.T) {
	runner := &fakeRunner{paths: map[string]bool{}}
	provider := linuxProvider{runner: runner}

	result, err := provider.Set(context.Background(), Association{Kind: KindMIME, Value: "text/html", App: "firefox.desktop"}, SetOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || len(result.Operations) != 1 || len(runner.runs) != 0 {
		t.Fatalf("result=%+v runs=%v", result, runner.runs)
	}
}

func TestLinuxResolveAppFindsDesktopEntryByName(t *testing.T) {
	home := t.TempDir()
	appDir := filepath.Join(home, ".local", "share", "applications")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	desktopID := "com.example.Aurora.desktop"
	if err := os.WriteFile(filepath.Join(appDir, desktopID), []byte(`[Desktop Entry]
Name=Aurora Browser
Exec=/usr/bin/aurora-browser %U
MimeType=x-scheme-handler/http;x-scheme-handler/https;text/html;application/xhtml+xml;
`), 0o600); err != nil {
		t.Fatal(err)
	}
	provider := linuxProvider{
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
		userHomeDir: func() (string, error) { return home, nil },
	}

	resolution, err := provider.ResolveApp(context.Background(), "aurora", Target{Kind: KindBrowser, Value: "default"})
	if err != nil {
		t.Fatal(err)
	}
	if resolution.App != desktopID || resolution.Source != "linux desktop entry" {
		t.Fatalf("resolution=%+v", resolution)
	}
}

func TestLinuxSetRuntimeErrorPreservesPlanAndPartialChange(t *testing.T) {
	failingCall := "xdg-mime default firefox.desktop text/html"
	runner := &fakeRunner{
		paths:  map[string]bool{"xdg-mime": true, "xdg-settings": true},
		errors: map[string]error{failingCall: errors.New("text/html failed")},
	}
	provider := linuxProvider{runner: runner}

	result, err := provider.Set(context.Background(), Association{Kind: KindBrowser, Value: "default", App: "firefox.desktop"}, SetOptions{})
	if err == nil {
		t.Fatal("expected set error")
	}
	if !result.Changed || len(result.Operations) != 5 || len(runner.runs) != 3 {
		t.Fatalf("result=%+v runs=%v", result, runner.runs)
	}
}

func TestParseDefaultFromMIMEApps(t *testing.T) {
	content := `
[Default Applications]
x-scheme-handler/https=firefox.desktop;chromium.desktop;
text/html=firefox.desktop;
`
	got, ok := parseDefaultFromMIMEApps(content, "x-scheme-handler/https")
	if !ok || got != "firefox.desktop" {
		t.Fatalf("got=%q ok=%t", got, ok)
	}
}

func TestLinuxParseDesktopEntryMetadata(t *testing.T) {
	content := `
[Desktop Entry]
Name=Firefox
Exec=firefox %u %U --foo
MimeType=text/html;application/xhtml+xml;
`
	meta, ok := parseDesktopEntryMetadata(content)
	if !ok {
		t.Fatal("expected metadata to parse")
	}
	if !meta.hasURLPlaceholder() {
		t.Fatal("expected URL placeholder")
	}
	if _, ok := meta.mimeTypes["text/html"]; !ok {
		t.Fatalf("missing text/html mime type: %#v", meta.mimeTypes)
	}
}

func TestLinuxCheckBrowserEnvFallback(t *testing.T) {
	provider := linuxProvider{
		getenv: func(key string) string {
			if key == "BROWSER" {
				return "custom-browser --incognito"
			}
			return ""
		},
	}
	findings := provider.checkBrowserEnvFallback()
	if len(findings) != 1 || findings[0].ID != "L10" {
		t.Fatalf("expected one L10 finding: %#v", findings)
	}
}

func TestLinuxCheckCurrentDesktopContext(t *testing.T) {
	provider := linuxProvider{
		getenv: func(key string) string {
			if key == "XDG_CURRENT_DESKTOP" {
				return "KDE,GNOME"
			}
			return ""
		},
	}
	findings := provider.checkCurrentDesktopContext()
	if len(findings) != 1 || findings[0].ID != "L24" {
		t.Fatalf("expected one L24 finding: %#v", findings)
	}
}

func TestLinuxCurrentDesktopsDeduplicatesAndAcceptsColons(t *testing.T) {
	desktops := currentDesktops("GNOME:KDE:GNOME:GNOME ; GNOME")
	if len(desktops) != 2 {
		t.Fatalf("expected 2 desktop tokens, got %v", desktops)
	}
	if desktops[0] != "gnome" || desktops[1] != "kde" {
		t.Fatalf("unexpected desktops: %v", desktops)
	}
}

func TestLinuxCheckMetadataMaintenanceTools(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{},
		},
	}
	findings := provider.checkMetadataMaintenanceTools()
	if len(findings) != 2 {
		t.Fatalf("expected two findings: %#v", findings)
	}
	var ids []string
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	if !(len(ids) == 2 && ((ids[0] == "L15" && ids[1] == "L16") || (ids[0] == "L16" && ids[1] == "L15"))) {
		t.Fatalf("expected L15 and L16 findings, got %v", ids)
	}
}

func TestLinuxCheckOpenPathContext(t *testing.T) {
	providerWayland := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{},
		},
		getenv: func(key string) string {
			if key == "XDG_SESSION_TYPE" {
				return "wayland"
			}
			if key == "XDG_CURRENT_DESKTOP" {
				return "GNOME"
			}
			return ""
		},
	}
	findings := providerWayland.checkOpenPathContext("firefox.desktop")
	if len(findings) != 1 || findings[0].ID != "L09" {
		t.Fatalf("expected one L09 finding: %#v", findings)
	}

	providerX11 := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{},
		},
		getenv: func(key string) string {
			if key == "XDG_SESSION_TYPE" {
				return "x11"
			}
			return ""
		},
	}
	findings = providerX11.checkOpenPathContext("firefox.desktop")
	if len(findings) != 1 || findings[0].ID != "L30" {
		t.Fatalf("expected one L30 finding: %#v", findings)
	}
}

func TestLinuxCheckCallbackScheme(t *testing.T) {
	providerUnset := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{"xdg-mime": true},
			outputs: map[string]string{
				"xdg-mime query default x-scheme-handler/callback": "None",
			},
		},
		readFile:    func(string) ([]byte, error) { return nil, errors.New("not found") },
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			if key == "DFX_CALLBACK_SCHEME" {
				return "callback://oauth/return"
			}
			if key == "XDG_CONFIG_HOME" {
				return "/home/test/.config"
			}
			return ""
		},
	}
	findings := providerUnset.checkCallbackScheme(map[string]string{"x-scheme-handler/http": "firefox.desktop"})
	if len(findings) != 1 || findings[0].ID != "L20" {
		t.Fatalf("expected one L20 finding: %#v", findings)
	}

	providerMapped := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{"xdg-mime": true},
			outputs: map[string]string{
				"xdg-mime query default x-scheme-handler/callback": "firefox.desktop",
				"xdg-mime query default x-scheme-handler/http":     "firefox.desktop",
			},
		},
		readFile:    func(string) ([]byte, error) { return nil, errors.New("not found") },
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			if key == "DFX_CALLBACK_SCHEME" {
				return "x-scheme-handler/callback"
			}
			if key == "XDG_CONFIG_HOME" {
				return "/home/test/.config"
			}
			return ""
		},
	}
	findings = providerMapped.checkCallbackScheme(map[string]string{"x-scheme-handler/http": "firefox.desktop"})
	if len(findings) != 1 || findings[0].ID != "L21" {
		t.Fatalf("expected one L21 finding: %#v", findings)
	}
}

func TestLinuxCheckToolkitDisagreement(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{
				"xdg-mime": true,
				"gio":      true,
			},
			outputs: map[string]string{
				"xdg-mime query default x-scheme-handler/http":  "firefox.desktop",
				"xdg-mime query default x-scheme-handler/https": "firefox.desktop",
				"xdg-mime query default text/html":              "firefox.desktop",
				"gio mime x-scheme-handler/http":                "Default application for x-scheme-handler/http: chromium.desktop;",
				"gio mime x-scheme-handler/https":               "Default application for x-scheme-handler/https: firefox.desktop;",
				"gio mime text/html":                            "Default application for text/html: firefox.desktop;",
			},
		},
	}
	findings := provider.checkToolkitDisagreement(context.Background())
	if len(findings) == 0 || findings[0].ID != "L02" {
		t.Fatalf("expected L02 finding: %#v", findings)
	}
}

func TestLinuxCheckToolkitDisagreementContentTypes(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{
				"xdg-mime": true,
				"gio":      true,
			},
			outputs: map[string]string{
				"xdg-mime query default x-scheme-handler/http":  "firefox.desktop",
				"xdg-mime query default x-scheme-handler/https": "firefox.desktop",
				"xdg-mime query default text/html":              "firefox.desktop",
				"xdg-mime query default application/xhtml+xml":  "firefox.desktop",
				"gio mime x-scheme-handler/http":                "firefox.desktop;",
				"gio mime x-scheme-handler/https":               "firefox.desktop;",
				"gio mime text/html":                            "chromium.desktop;",
				"gio mime application/xhtml+xml":                "firefox.desktop;",
			},
		},
	}
	findings := provider.checkToolkitDisagreement(context.Background())
	if len(findings) == 0 || findings[0].ID != "L19" {
		t.Fatalf("expected L19 finding: %#v", findings)
	}
}

func TestLinuxCheckOverrideRemovedButUISync(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{"gio": true},
			outputs: map[string]string{
				"gio mime x-scheme-handler/http":  "Default application for x-scheme-handler/http: firefox.desktop;",
				"gio mime x-scheme-handler/https": "Default application for x-scheme-handler/https: firefox.desktop;",
				"gio mime text/html":              "Default application for text/html: None;",
				"gio mime application/xhtml+xml":  "Default application for application/xhtml+xml: None;",
			},
		},
	}
	findings := provider.checkOverrideRemovedButUISync(context.Background(), map[string]string{
		"x-scheme-handler/http":  "",
		"x-scheme-handler/https": "None",
		"text/html":              "None",
		"application/xhtml+xml":  "None",
	})
	if len(findings) == 0 || findings[0].ID != "L18" {
		t.Fatalf("expected L18 finding: %#v", findings)
	}
}

func TestLinuxParseDesktopEntryMetadataAppImageRegistration(t *testing.T) {
	content := `
[Desktop Entry]
Type=Application
Name=Portable Browser
Exec=/home/test/Downloads/firefox.appimage %u
MimeType=text/html;application/xhtml+xml;
`
	meta, ok := parseDesktopEntryMetadata(content)
	if !ok {
		t.Fatal("expected metadata to parse")
	}
	if !meta.isAppImageDesktop() {
		t.Fatalf("expected AppImage desktop marker")
	}
	if meta.hasAppImageRegistration() {
		t.Fatalf("expected no persistent AppImage metadata")
	}

	content = `
[Desktop Entry]
Type=Application
Name=Portable Browser
Exec=/home/test/Downloads/firefox.appimage %u
X-AppImage-Path=/home/test/firefox.appimage
MimeType=text/html;application/xhtml+xml;
`
	meta, ok = parseDesktopEntryMetadata(content)
	if !ok || !meta.hasAppImageRegistration() {
		t.Fatalf("expected AppImage metadata to parse with path registration")
	}
}

func TestLinuxCheckAppImageRegistrationMissing(t *testing.T) {
	provider := linuxProvider{
		userHomeDir: func() (string, error) { return "/home/test", nil },
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/home/test/.local/share/applications/firefox.appimage.desktop") {
				return []byte(`[Desktop Entry]
Type=Application
Name=Portable Browser
Exec=/home/test/Downloads/firefox.appimage %u
MimeType=text/html;application/xhtml+xml;
`), nil
			}
			return nil, errors.New("not found")
		},
	}
	findings := provider.checkAppImageRegistrationMissing(map[string]string{"x-scheme-handler/http": "firefox.appimage.desktop"})
	if len(findings) == 0 || findings[0].ID != "L12" {
		t.Fatalf("expected L12 finding: %#v", findings)
	}
}

func TestLinuxCheckMIMESniffMismatch(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{"file": true, "xdg-mime": true},
			outputFn: func(call string) (string, bool) {
				switch {
				case strings.HasPrefix(call, "xdg-mime query filetype "):
					return "text/html", true
				case strings.HasPrefix(call, "file --mime-type "):
					return "text/plain", true
				default:
					return "", false
				}
			},
		},
	}
	findings := provider.checkMIMESniffMismatch(context.Background())
	if len(findings) == 0 || findings[0].ID != "L28" {
		t.Fatalf("expected L28 finding: %#v", findings)
	}
}

func TestLinuxCheckFileManagerCacheLag(t *testing.T) {
	now := time.Now()
	provider := linuxProvider{
		userHomeDir: func() (string, error) { return "/home/test", nil },
		statFile: func(path string) (os.FileInfo, error) {
			switch {
			case strings.HasSuffix(path, "/home/test/.local/share/applications/firefox.desktop"):
				return fakeFileInfo{mode: 0o644, uid: 1000, mod: now}, nil
			case strings.HasSuffix(path, "/home/test/.local/share/mime/mime.cache"):
				return fakeFileInfo{mode: 0o644, uid: 1000, mod: now.Add(-time.Hour)}, nil
			default:
				return nil, errors.New("not found")
			}
		},
	}
	findings := provider.checkFileManagerCacheLag(map[string]string{"x-scheme-handler/http": "firefox.desktop"})
	if len(findings) == 0 || findings[0].ID != "L29" {
		t.Fatalf("expected L29 finding: %#v", findings)
	}
}

func TestLinuxCheckPortalMismatch(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{
				"xdg-mime":      true,
				"flatpak":       true,
				"flatpak-spawn": true,
			},
			outputs: map[string]string{
				"xdg-mime query default x-scheme-handler/http":                       "firefox.desktop",
				"xdg-mime query default x-scheme-handler/https":                      "firefox.desktop",
				"xdg-mime query default text/html":                                   "firefox.desktop",
				"flatpak-spawn --host xdg-mime query default x-scheme-handler/http":  "chromium.desktop",
				"flatpak-spawn --host xdg-mime query default x-scheme-handler/https": "chromium.desktop",
				"flatpak-spawn --host xdg-mime query default text/html":              "chromium.desktop",
			},
		},
	}
	findings := provider.checkPortalMismatch(context.Background())
	if len(findings) == 0 || findings[0].ID != "L07" {
		t.Fatalf("expected L07 finding: %#v", findings)
	}
}

func TestLinuxCheckDuplicateDesktopIDsDetectsContainerShadowing(t *testing.T) {
	provider := linuxProvider{
		userHomeDir: func() (string, error) { return "/home/test", nil },
		statFile: func(path string) (os.FileInfo, error) {
			switch {
			case strings.HasSuffix(path, "/usr/share/applications/flatpak-browser.desktop"),
				strings.HasSuffix(path, "/var/lib/flatpak/exports/share/applications/flatpak-browser.desktop"):
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			default:
				return nil, errors.New("not found")
			}
		},
	}
	findings := provider.checkDuplicateDesktopIDs("flatpak-browser.desktop")
	if len(findings) != 2 {
		t.Fatalf("expected L13 and L14 findings, got %#v", findings)
	}
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	if ids[0] != "L13" || ids[1] != "L14" {
		t.Fatalf("expected L13 then L14 findings, got %#v", ids)
	}
}

func TestLinuxCheckCrossDesktopConfigConflicts(t *testing.T) {
	root := t.TempDir()
	configHome := filepath.Join(root, ".config")
	dataHome := filepath.Join(root, ".local", "share")
	configDir := filepath.Join(root, "xdg")
	dataDir := filepath.Join(root, "share", "data")
	if err := os.MkdirAll(filepath.Join(configHome), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(configDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataHome, "applications"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "applications"), 0o755); err != nil {
		t.Fatal(err)
	}
	currentContent := "[Default Applications]\nx-scheme-handler/http=firefox.desktop;\n"
	inactiveContent := "[Default Applications]\nx-scheme-handler/http=chromium.desktop;\n"
	if err := os.WriteFile(filepath.Join(configHome, "mimeapps.list"), []byte(currentContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configHome, "gnome-mimeapps.list"), []byte(currentContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configHome, "kde-mimeapps.list"), []byte(inactiveContent), 0o644); err != nil {
		t.Fatal(err)
	}

	provider := linuxProvider{
		runner:      &fakeRunner{paths: map[string]bool{}},
		readFile:    os.ReadFile,
		statFile:    func(string) (os.FileInfo, error) { return nil, errors.New("not found") },
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			switch key {
			case "XDG_CURRENT_DESKTOP":
				return "GNOME"
			case "XDG_CONFIG_HOME":
				return configHome
			case "XDG_DATA_HOME":
				return dataHome
			case "XDG_CONFIG_DIRS":
				return configDir
			case "XDG_DATA_DIRS":
				return dataDir
			default:
				return ""
			}
		},
	}
	findings := provider.checkCrossDesktopConfigConflicts(map[string]string{"x-scheme-handler/http": "firefox.desktop"})
	if len(findings) != 1 || findings[0].ID != "L27" {
		t.Fatalf("expected one L27 finding: %#v", findings)
	}
}

func TestLinuxGioDefaultForAssociation(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{
			paths: map[string]bool{"gio": true},
			outputs: map[string]string{
				"gio mime text/html": "Default application for text/html: firefox.desktop;",
			},
		},
	}
	got, err := provider.gioDefaultForAssociation(context.Background(), "text/html")
	if err != nil {
		t.Fatal(err)
	}
	if got != "firefox.desktop" {
		t.Fatalf("got=%q", got)
	}
}

func TestLinuxCheckBrowserEntryClaims(t *testing.T) {
	provider := linuxProvider{
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/home/test/.local/share/applications/firefox.desktop") {
				return []byte(`[Desktop Entry]
Type=Application
Name=Firefox
Exec=firefox %f --profile %F
MimeType=application/xml;
`), nil
			}
			return nil, errors.New("not found")
		},
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/home/test/.local/share/applications/firefox.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
	}
	findings := provider.checkBrowserEntryClaims(map[string]string{
		"x-scheme-handler/http": "firefox.desktop",
		"text/html":             "firefox.desktop",
	})
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	if len(ids) != 2 {
		t.Fatalf("expected two findings, got %v", ids)
	}
	if (ids[0] != "L06" && ids[1] != "L06") || (ids[0] != "L17" && ids[1] != "L17") {
		t.Fatalf("expected L06 and L17 findings, got %v", ids)
	}
}

func TestLinuxGetUsesMIMEAppsPrecedence(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{paths: map[string]bool{}},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/home/test/.config/mimeapps.list":
				return []byte("[Default Applications]\ntext/html=firefox.desktop;\n"), nil
			case "/etc/xdg/mimeapps.list":
				return []byte("[Default Applications]\ntext/html=chromium.desktop;\n"), nil
			default:
				return nil, errors.New("not found")
			}
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			switch key {
			case "XDG_CONFIG_HOME":
				return "/home/test/.config"
			case "XDG_CONFIG_DIRS":
				return "/etc/xdg"
			default:
				return ""
			}
		},
	}

	got, err := provider.Get(context.Background(), Target{Kind: KindMIME, Value: "text/html"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "firefox.desktop" {
		t.Fatalf("got=%q", got)
	}
}

func TestLinuxContentTypeNormalizesToMIME(t *testing.T) {
	provider := linuxProvider{
		runner: &fakeRunner{paths: map[string]bool{}},
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/home/test/.config/mimeapps.list":
				return []byte("[Default Applications]\ntext/html=firefox.desktop;\n"), nil
			default:
				return nil, errors.New("not found")
			}
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			if key == "XDG_CONFIG_HOME" {
				return "/home/test/.config"
			}
			return ""
		},
	}

	got, err := provider.Get(context.Background(), Target{Kind: KindContentType, Value: "text/html"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "firefox.desktop" {
		t.Fatalf("got=%q", got)
	}
}

func TestLinuxContentTypePassthroughWhenNotValidMIME(t *testing.T) {
	target := linuxNormalizeContentTypeToMIME(Target{Kind: KindContentType, Value: "public.html"})
	if target.Kind != KindContentType || target.Value != "public.html" {
		t.Fatalf("expected passthrough for non-MIME content type, got %+v", target)
	}
}

func TestLinuxDoctorBrowserHealthy(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime":                    true,
			"gio":                         true,
			"xdg-settings":                true,
			"xdg-desktop-portal":          true,
			"xdg-open":                    true,
			"xdg-desktop-portal-gtk":      true,
			"xdg-desktop-portal-kde":      false,
			"xdg-desktop-portal-wlr":      false,
			"xdg-desktop-portal-hyprland": false,
		},
		outputs: map[string]string{
			"xdg-settings get default-web-browser":          "firefox.desktop",
			"xdg-mime query default x-scheme-handler/http":  "firefox.desktop",
			"xdg-mime query default x-scheme-handler/https": "firefox.desktop",
			"xdg-mime query default text/html":              "firefox.desktop",
			"xdg-mime query default application/xhtml+xml":  "firefox.desktop",
		},
	}
	provider := linuxProvider{
		runner:      runner,
		readFile:    func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile:    os.Stat,
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy report, findings=%v", report.Findings)
	}
}

func TestLinuxDoctorBrowserFindings(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime":           true,
			"gio":                false,
			"xdg-settings":       true,
			"xdg-desktop-portal": false,
		},
		outputs: map[string]string{
			"xdg-settings get default-web-browser":          "chromium.desktop",
			"xdg-mime query default x-scheme-handler/http":  "firefox.desktop",
			"xdg-mime query default x-scheme-handler/https": "firefox.desktop",
			"xdg-mime query default text/html":              "firefox.desktop",
			"xdg-mime query default application/xhtml+xml":  "chromium.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected findings")
	}
	var ids []string
	for _, finding := range report.Findings {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"L26", "L11", "L15", "L16", "L03", "L05", "L25", "L08"}) {
		t.Fatalf("unexpected finding ids: %v", ids)
	}
}

func TestLinuxDoctorBrowserAdditionalIssueFindings(t *testing.T) {
	mimeUser := "[Default Applications]\ntext/html=firefox.desktop;\ninvalid-line\n"
	mimeSys := "[Default Applications]\ntext/html=chromium.desktop;\n"
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime": true,
		},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/http":  "missing.desktop",
			"xdg-mime query default x-scheme-handler/https": "missing.desktop",
			"xdg-mime query default text/html":              "missing.desktop",
			"xdg-mime query default application/xhtml+xml":  "missing.desktop",
		},
	}
	provider := linuxProvider{
		runner: runner,
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/home/test/.config/mimeapps.list":
				return []byte(mimeUser), nil
			case "/etc/xdg/mimeapps.list":
				return []byte(mimeSys), nil
			default:
				return nil, errors.New("not found")
			}
		},
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/home/test/.config/mimeapps.list") {
				return fakeFileInfo{mode: 0o644, uid: 0}, nil
			}
			if strings.HasSuffix(path, "/usr/share/applications/firefox.desktop") || strings.HasSuffix(path, "/var/lib/flatpak/exports/share/applications/firefox.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			switch key {
			case "XDG_CONFIG_HOME":
				return "/home/test/.config"
			case "XDG_CONFIG_DIRS":
				return "/etc/xdg"
			default:
				return ""
			}
		},
	}

	report, err := provider.Doctor(context.Background(), DoctorOptions{Browser: true})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]bool = map[string]bool{}
	for _, finding := range report.Findings {
		got[finding.ID] = true
	}
	for _, want := range []string{"L22", "L23", "L04", "L05", "L13", "L14"} {
		if !got[want] {
			t.Fatalf("missing finding %s in %+v", want, report.Findings)
		}
	}
}

func TestLinuxDoctorFixUsesInstalledBrowserAndDryRun(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime":     true,
			"xdg-settings": true,
		},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/https": "firefox.desktop",
		},
	}
	provider := linuxProvider{
		runner: runner,
		readFile: func(string) ([]byte, error) {
			return nil, errors.New("not found")
		},
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/firefox.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}

	result, err := provider.DoctorFix(context.Background(), DoctorFixOptions{Browser: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("dry-run fix should not report changed")
	}
	if len(result.Operations) == 0 {
		t.Fatal("expected planned operations")
	}
}

func TestLinuxDoctorFixErrorPreservesSetPlan(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime":     true,
			"xdg-settings": true,
		},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/https": "firefox.desktop",
		},
		errors: map[string]error{
			"xdg-mime default firefox.desktop text/html": errors.New("text/html failed"),
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/firefox.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}

	result, err := provider.DoctorFix(context.Background(), DoctorFixOptions{Browser: true})
	if err == nil {
		t.Fatal("expected doctor fix error")
	}
	if !result.Changed || len(result.Operations) != 5 {
		t.Fatalf("result=%+v", result)
	}
}

func TestLinuxDoctorFixFailsWithoutInstalledBrowser(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime": true,
		},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/https": "missing.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(string) (os.FileInfo, error) { return nil, errors.New("not found") },
		userHomeDir: func() (string, error) {
			return "/home/test", nil
		},
		getenv: func(string) string { return "" },
	}
	if _, err := provider.DoctorFix(context.Background(), DoctorFixOptions{Browser: true}); err == nil {
		t.Fatal("expected error")
	}
}

type fakeFileInfo struct {
	mode os.FileMode
	uid  uint32
	mod  time.Time
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }


func TestLinuxDoctorMIME(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default text/plain": "gedit.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/gedit.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{MIME: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy MIME report, findings=%v", report.Findings)
	}
	if report.Scope != "mime:text/plain" {
		t.Fatalf("unexpected scope: %s", report.Scope)
	}
}

func TestLinuxDoctorScheme(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/mailto": "thunderbird.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/thunderbird.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{Scheme: "mailto"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy scheme report, findings=%v", report.Findings)
	}
	if report.Scope != "scheme:mailto" {
		t.Fatalf("unexpected scope: %s", report.Scope)
	}
}

func TestLinuxDoctorContentTypeDelegatesToMIME(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default text/html": "firefox.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/firefox.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{ContentType: "text/html"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy report, findings=%v", report.Findings)
	}
	if report.Scope != "mime:text/html" {
		t.Fatalf("unexpected scope: %s", report.Scope)
	}
}

func TestLinuxDoctorContentTypeRejectsNonMIME(t *testing.T) {
	provider := linuxProvider{runner: &fakeRunner{}}
	_, err := provider.Doctor(context.Background(), DoctorOptions{ContentType: "public.html"})
	if err == nil {
		t.Fatal("expected error for non-MIME content type")
	}
	if !strings.Contains(err.Error(), "Linux has no separate content-type namespace") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxDoctorAll(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime":     true,
			"xdg-settings": true,
		},
		outputs: map[string]string{
			"xdg-settings get default-web-browser":            "firefox.desktop",
			"xdg-mime query default x-scheme-handler/http":    "firefox.desktop",
			"xdg-mime query default x-scheme-handler/https":   "firefox.desktop",
			"xdg-mime query default text/html":                "firefox.desktop",
			"xdg-mime query default application/xhtml+xml":    "firefox.desktop",
			"xdg-mime query default x-scheme-handler/mailto":  "thunderbird.desktop",
		},
	}
	provider := linuxProvider{
		runner: runner,
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/home/test/.config/mimeapps.list") {
				return []byte("[Default Applications]\nx-scheme-handler/mailto=thunderbird.desktop;\n"), nil
			}
			return nil, errors.New("not found")
		},
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/firefox.desktop") ||
				strings.HasSuffix(path, "/usr/share/applications/thunderbird.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv: func(key string) string {
			if key == "XDG_CONFIG_HOME" {
				return "/home/test/.config"
			}
			return ""
		},
	}
	report, err := provider.Doctor(context.Background(), DoctorOptions{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Healthy {
		t.Fatalf("expected healthy all report, findings=%v", report.Findings)
	}
	if report.Scope != "all" {
		t.Fatalf("unexpected scope: %s", report.Scope)
	}
}

func TestLinuxDoctorFixMIME(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default text/plain": "missing.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/gedit.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	_, err := provider.DoctorFix(context.Background(), DoctorFixOptions{MIME: "text/plain"})
	if err == nil {
		t.Fatal("expected error when no installed handler found")
	}

	runner2 := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default text/plain": "gedit.desktop",
		},
	}
	provider2 := linuxProvider{
		runner:   runner2,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/gedit.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	result, err := provider2.DoctorFix(context.Background(), DoctorFixOptions{MIME: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("expected no change when handler is already installed")
	}
}

func TestLinuxDoctorFixScheme(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/mailto": "missing.desktop",
		},
	}
	provider := linuxProvider{
		runner:   runner,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/thunderbird.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	_, err := provider.DoctorFix(context.Background(), DoctorFixOptions{Scheme: "mailto"})
	if err == nil {
		t.Fatal("expected error when no installed handler found")
	}

	runner2 := &fakeRunner{
		paths: map[string]bool{"xdg-mime": true},
		outputs: map[string]string{
			"xdg-mime query default x-scheme-handler/mailto": "thunderbird.desktop",
		},
	}
	provider2 := linuxProvider{
		runner:   runner2,
		readFile: func(string) ([]byte, error) { return nil, errors.New("not found") },
		statFile: func(path string) (os.FileInfo, error) {
			if strings.HasSuffix(path, "/usr/share/applications/thunderbird.desktop") {
				return fakeFileInfo{mode: 0o644, uid: 1000}, nil
			}
			return nil, errors.New("not found")
		},
		userHomeDir: func() (string, error) { return "/home/test", nil },
		getenv:      func(string) string { return "" },
	}
	result, err := provider2.DoctorFix(context.Background(), DoctorFixOptions{Scheme: "mailto"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatal("expected no change when handler is already installed")
	}
}
