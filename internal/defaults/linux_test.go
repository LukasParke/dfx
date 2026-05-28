package defaults

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fakeRunner struct {
	paths   map[string]bool
	runs    []string
	outputs map[string]string
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

func TestLinuxDoctorBrowserHealthy(t *testing.T) {
	runner := &fakeRunner{
		paths: map[string]bool{
			"xdg-mime":                    true,
			"gio":                         true,
			"xdg-settings":                true,
			"xdg-desktop-portal":          true,
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
	if !reflect.DeepEqual(ids, []string{"L26", "L03", "L05", "L25", "L08"}) {
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
	for _, want := range []string{"L22", "L23", "L04", "L05", "L13"} {
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
}

func (f fakeFileInfo) Name() string       { return "fake" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }
