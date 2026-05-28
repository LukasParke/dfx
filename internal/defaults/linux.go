package defaults

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type linuxProvider struct {
	runner      commandRunner
	readFile    func(string) ([]byte, error)
	statFile    func(string) (os.FileInfo, error)
	userHomeDir func() (string, error)
	getenv      func(string) string
}

func newLinuxProvider() Provider {
	return linuxProvider{
		runner:      execRunner{},
		readFile:    os.ReadFile,
		statFile:    os.Stat,
		userHomeDir: os.UserHomeDir,
		getenv:      os.Getenv,
	}
}

func (p linuxProvider) Inspect(context.Context) InspectReport {
	report := InspectReport{
		Platform: "linux",
		Provider: "xdg",
		CanRead:  true,
		CanWrite: true,
		Capabilities: Capabilities{
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
	if _, err := p.runner.LookPath("xdg-mime"); err != nil {
		report.CanRead = false
		report.CanWrite = false
		report.Capabilities.CanReadCurrent = false
		report.Capabilities.CanWriteUserDefault = false
		report.Notes = append(report.Notes, "xdg-mime was not found")
	}
	if _, err := p.runner.LookPath("xdg-settings"); err != nil {
		report.Notes = append(report.Notes, "xdg-settings was not found; browser defaults will only use xdg-mime")
	}
	return report
}

func (p linuxProvider) Get(ctx context.Context, target Target) (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	if app, ok := p.resolveFromMIMEApps(target); ok {
		return app, nil
	}
	if target.Kind == KindBrowser && hasCommand(p.runner, "xdg-settings") {
		return p.runner.Run(ctx, "xdg-settings", "get", "default-web-browser")
	}
	if _, err := p.runner.LookPath("xdg-mime"); err != nil {
		return "", errors.New("xdg-mime is required on Linux")
	}
	return p.runner.Run(ctx, "xdg-mime", "query", "default", linuxAssociationName(target))
}

func (p linuxProvider) Doctor(ctx context.Context, options DoctorOptions) (DoctorReport, error) {
	if !options.Browser {
		return DoctorReport{}, errors.New("linux doctor currently requires --browser")
	}
	report := DoctorReport{
		Platform: "linux",
		Scope:    "browser",
		Healthy:  true,
	}

	if !hasCommand(p.runner, "xdg-mime") {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L26",
			Severity:    "error",
			Summary:     "Required command missing: xdg-mime",
			Remediation: "Install xdg-utils package for your distribution.",
		})
		return report, nil
	}
	if !hasCommand(p.runner, "gio") {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L26",
			Severity:    "warning",
			Summary:     "Optional command missing: gio",
			Remediation: "Install GLib tools to compare GIO behavior against XDG defaults.",
		})
	}
	if !hasCommand(p.runner, "xdg-settings") {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L26",
			Severity:    "warning",
			Summary:     "Optional command missing: xdg-settings",
			Remediation: "Install xdg-settings to sync desktop browser preference with MIME defaults.",
		})
	}
	report.Findings = append(report.Findings, p.checkRootOwnedUserMIMEApps()...)

	httpApp, _ := p.Get(ctx, Target{Kind: KindScheme, Value: "http"})
	httpsApp, _ := p.Get(ctx, Target{Kind: KindScheme, Value: "https"})
	htmlApp, _ := p.Get(ctx, Target{Kind: KindMIME, Value: "text/html"})
	xhtmlApp, _ := p.Get(ctx, Target{Kind: KindMIME, Value: "application/xhtml+xml"})
	report.Findings = append(report.Findings, p.checkMalformedMIMEApps()...)
	report.Findings = append(report.Findings, p.checkPrecedenceConflicts()...)

	if httpApp == "" || httpsApp == "" || htmlApp == "" {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L01",
			Severity:    "error",
			Summary:     "One or more browser associations are unset",
			Details:     fmt.Sprintf("http=%q https=%q text/html=%q", httpApp, httpsApp, htmlApp),
			Remediation: "Run dfx set --browser --app <desktop-id> to set all browser associations.",
		})
	} else if !(httpApp == httpsApp && httpsApp == htmlApp) {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L01",
			Severity:    "error",
			Summary:     "Browser defaults are inconsistent across core associations",
			Details:     fmt.Sprintf("http=%q https=%q text/html=%q", httpApp, httpsApp, htmlApp),
			Remediation: "Run dfx set --browser --app <desktop-id> to make browser defaults consistent.",
		})
	}

	if xhtmlApp == "" {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L03",
			Severity:    "warning",
			Summary:     "application/xhtml+xml is unset",
			Remediation: "Run dfx set --browser --app <desktop-id> to include XHTML association.",
		})
	} else if httpsApp != "" && xhtmlApp != httpsApp {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L03",
			Severity:    "warning",
			Summary:     "XHTML association differs from browser scheme defaults",
			Details:     fmt.Sprintf("application/xhtml+xml=%q https=%q", xhtmlApp, httpsApp),
			Remediation: "Run dfx set --browser --app <desktop-id> to align XHTML with browser scheme defaults.",
		})
	}
	report.Findings = append(report.Findings, p.checkMissingDesktopEntries(httpApp, httpsApp, htmlApp, xhtmlApp)...)
	report.Findings = append(report.Findings, p.checkDuplicateDesktopIDs()...)

	if hasCommand(p.runner, "xdg-settings") {
		desktopBrowser, err := p.runner.Run(ctx, "xdg-settings", "get", "default-web-browser")
		if err == nil && desktopBrowser != "" && httpsApp != "" && desktopBrowser != httpsApp {
			report.Findings = append(report.Findings, DoctorFinding{
				ID:          "L25",
				Severity:    "warning",
				Summary:     "Desktop browser setting differs from MIME browser default",
				Details:     fmt.Sprintf("xdg-settings=%q https=%q", desktopBrowser, httpsApp),
				Remediation: "Run dfx set --browser --app <desktop-id> to synchronize xdg-settings and MIME defaults.",
			})
		}
	}

	hasPortal := hasCommand(p.runner, "xdg-desktop-portal")
	hasBackend := hasCommand(p.runner, "xdg-desktop-portal-gtk") ||
		hasCommand(p.runner, "xdg-desktop-portal-kde") ||
		hasCommand(p.runner, "xdg-desktop-portal-wlr") ||
		hasCommand(p.runner, "xdg-desktop-portal-hyprland")
	if !hasPortal || !hasBackend {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:       "L08",
			Severity: "warning",
			Summary:  "Portal stack appears incomplete for sandboxed app OpenURI flows",
			Details:  fmt.Sprintf("xdg-desktop-portal=%t backend=%t", hasPortal, hasBackend),
			Remediation: "Install xdg-desktop-portal and a desktop backend " +
				"(gtk/kde/wlr/hyprland) used by your session.",
		})
	}

	if len(report.Findings) != 0 {
		for _, finding := range report.Findings {
			if finding.Severity == "error" {
				report.Healthy = false
				return report, nil
			}
		}
		report.Healthy = true
	}
	return report, nil
}

func (p linuxProvider) DoctorFix(ctx context.Context, options DoctorFixOptions) (DoctorFixResult, error) {
	if !options.Browser {
		return DoctorFixResult{}, errors.New("linux doctor fix currently requires --browser")
	}
	candidates := []Target{
		{Kind: KindScheme, Value: "https"},
		{Kind: KindScheme, Value: "http"},
		{Kind: KindMIME, Value: "text/html"},
		{Kind: KindMIME, Value: "application/xhtml+xml"},
	}
	var app string
	for _, target := range candidates {
		current, _ := p.Get(ctx, target)
		current = strings.TrimSpace(current)
		if current != "" && current != "None" && desktopExists(p, current) {
			app = current
			break
		}
	}
	if app == "" && hasCommand(p.runner, "xdg-settings") {
		current, err := p.runner.Run(ctx, "xdg-settings", "get", "default-web-browser")
		if err == nil {
			current = strings.TrimSpace(current)
			if current != "" && current != "None" && desktopExists(p, current) {
				app = current
			}
		}
	}
	if app == "" {
		return DoctorFixResult{}, errors.New("unable to select a valid installed browser desktop id to repair defaults")
	}

	result, err := p.Set(ctx, Association{Kind: KindBrowser, Value: "default", App: app}, SetOptions{DryRun: options.DryRun})
	if err != nil {
		return DoctorFixResult{}, err
	}
	return DoctorFixResult{Changed: result.Changed, Operations: result.Operations}, nil
}

func (p linuxProvider) Set(ctx context.Context, association Association, options SetOptions) (SetResult, error) {
	if err := association.Validate(); err != nil {
		return SetResult{}, err
	}
	if _, err := p.runner.LookPath("xdg-mime"); err != nil {
		return SetResult{}, errors.New("xdg-mime is required on Linux")
	}

	targets := linuxTargetsForAssociation(association.Target())
	ops := make([]string, 0, len(targets)+1)
	for _, target := range targets {
		ops = append(ops, fmt.Sprintf("xdg-mime default %s %s", association.App, linuxAssociationName(target)))
	}
	if isBrowserTarget(association.Target()) && hasCommand(p.runner, "xdg-settings") {
		ops = append(ops, fmt.Sprintf("xdg-settings set default-web-browser %s", association.App))
	}
	if options.DryRun {
		return SetResult{Changed: false, Operations: ops}, nil
	}

	for _, target := range targets {
		if _, err := p.runner.Run(ctx, "xdg-mime", "default", association.App, linuxAssociationName(target)); err != nil {
			return SetResult{}, err
		}
	}
	if isBrowserTarget(association.Target()) && hasCommand(p.runner, "xdg-settings") {
		if _, err := p.runner.Run(ctx, "xdg-settings", "set", "default-web-browser", association.App); err != nil {
			return SetResult{}, err
		}
	}
	return SetResult{Changed: true, Operations: ops}, nil
}

func linuxAssociationName(target Target) string {
	if target.Kind == KindBrowser {
		return "x-scheme-handler/https"
	}
	if target.Kind == KindScheme {
		return "x-scheme-handler/" + target.Value
	}
	return target.Value
}

func isBrowserTarget(target Target) bool {
	return target.Kind == KindBrowser || isBrowserScheme(target)
}

func isBrowserScheme(target Target) bool {
	return target.Kind == KindScheme && (target.Value == "http" || target.Value == "https")
}

func linuxTargetsForAssociation(target Target) []Target {
	if target.Kind != KindBrowser && !isBrowserScheme(target) {
		return []Target{target}
	}
	return []Target{
		{Kind: KindScheme, Value: "http"},
		{Kind: KindScheme, Value: "https"},
		{Kind: KindMIME, Value: "text/html"},
		{Kind: KindMIME, Value: "application/xhtml+xml"},
	}
}

func hasCommand(runner commandRunner, name string) bool {
	_, err := runner.LookPath(name)
	return err == nil
}

func (p linuxProvider) resolveFromMIMEApps(target Target) (string, bool) {
	key := linuxAssociationName(target)
	for _, path := range p.mimeappsLookupPaths() {
		content, err := p.readFile(path)
		if err != nil {
			continue
		}
		if app, ok := parseDefaultFromMIMEApps(string(content), key); ok {
			return app, true
		}
	}
	return "", false
}

func (p linuxProvider) mimeappsLookupPaths() []string {
	home, err := p.userHomeDir()
	if err != nil {
		return nil
	}
	xdgConfigHome := p.getenv("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	xdgDataHome := p.getenv("XDG_DATA_HOME")
	if xdgDataHome == "" {
		xdgDataHome = filepath.Join(home, ".local", "share")
	}
	xdgConfigDirs := splitOrDefault(p.getenv("XDG_CONFIG_DIRS"), []string{"/etc/xdg"})
	xdgDataDirs := splitOrDefault(p.getenv("XDG_DATA_DIRS"), []string{"/usr/local/share", "/usr/share"})
	desktops := currentDesktops(p.getenv("XDG_CURRENT_DESKTOP"))

	paths := make([]string, 0, 24)
	for _, desktop := range desktops {
		paths = append(paths, filepath.Join(xdgConfigHome, desktop+"-mimeapps.list"))
	}
	paths = append(paths, filepath.Join(xdgConfigHome, "mimeapps.list"))
	for _, dir := range xdgConfigDirs {
		for _, desktop := range desktops {
			paths = append(paths, filepath.Join(dir, desktop+"-mimeapps.list"))
		}
		paths = append(paths, filepath.Join(dir, "mimeapps.list"))
	}
	for _, desktop := range desktops {
		paths = append(paths, filepath.Join(xdgDataHome, "applications", desktop+"-mimeapps.list"))
	}
	paths = append(paths, filepath.Join(xdgDataHome, "applications", "mimeapps.list"))
	for _, dir := range xdgDataDirs {
		for _, desktop := range desktops {
			paths = append(paths, filepath.Join(dir, "applications", desktop+"-mimeapps.list"))
		}
		paths = append(paths, filepath.Join(dir, "applications", "mimeapps.list"))
	}
	return dedupePaths(paths)
}

func parseDefaultFromMIMEApps(content, key string) (string, bool) {
	inDefaults := false
	lines := strings.Split(content, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDefaults = strings.EqualFold(line, "[Default Applications]")
			continue
		}
		if !inDefaults {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(left) != key {
			continue
		}
		for _, candidate := range strings.Split(right, ";") {
			app := strings.TrimSpace(candidate)
			if app != "" {
				return app, true
			}
		}
	}
	return "", false
}

func splitOrDefault(value string, fallback []string) []string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	parts := strings.Split(value, ":")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func currentDesktops(value string) []string {
	parts := strings.Split(strings.ToLower(value), ":")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return []string{"generic"}
	}
	return out
}

func dedupePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func (p linuxProvider) checkRootOwnedUserMIMEApps() []DoctorFinding {
	home, err := p.userHomeDir()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".config", "mimeapps.list")
	info, err := p.statFile(path)
	if err != nil {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L22",
		Severity:    "warning",
		Summary:     "User mimeapps.list is owned by root",
		Details:     path,
		Remediation: "Fix ownership with chown to allow user-level default-app updates.",
	}}
}

func (p linuxProvider) checkMalformedMIMEApps() []DoctorFinding {
	for _, path := range p.mimeappsLookupPaths() {
		content, err := p.readFile(path)
		if err != nil {
			continue
		}
		if malformed := malformedDefaultLines(string(content)); len(malformed) > 0 {
			return []DoctorFinding{{
				ID:          "L23",
				Severity:    "warning",
				Summary:     "Malformed lines detected in [Default Applications]",
				Details:     fmt.Sprintf("%s: %s", path, strings.Join(malformed, ", ")),
				Remediation: "Fix malformed key=value lines in mimeapps.list and rerun doctor.",
			}}
		}
	}
	return nil
}

func malformedDefaultLines(content string) []string {
	inDefaults := false
	var malformed []string
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inDefaults = strings.EqualFold(line, "[Default Applications]")
			continue
		}
		if !inDefaults {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
			malformed = append(malformed, line)
		}
	}
	return malformed
}

func (p linuxProvider) checkPrecedenceConflicts() []DoctorFinding {
	keys := []string{"x-scheme-handler/http", "x-scheme-handler/https", "text/html", "application/xhtml+xml"}
	seen := map[string]map[string]struct{}{}
	for _, key := range keys {
		seen[key] = map[string]struct{}{}
	}
	for _, path := range p.mimeappsLookupPaths() {
		content, err := p.readFile(path)
		if err != nil {
			continue
		}
		for _, key := range keys {
			if app, ok := parseDefaultFromMIMEApps(string(content), key); ok && app != "" {
				seen[key][app] = struct{}{}
			}
		}
	}
	for _, key := range keys {
		if len(seen[key]) > 1 {
			return []DoctorFinding{{
				ID:          "L04",
				Severity:    "warning",
				Summary:     "Conflicting defaults found across mimeapps precedence layers",
				Details:     fmt.Sprintf("%s has %d competing defaults", key, len(seen[key])),
				Remediation: "Consolidate browser defaults in highest-precedence user mimeapps.list.",
			}}
		}
	}
	return nil
}

func (p linuxProvider) checkMissingDesktopEntries(apps ...string) []DoctorFinding {
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app == "" || app == "None" {
			continue
		}
		if desktopExists(p, app) {
			continue
		}
		return []DoctorFinding{{
			ID:          "L05",
			Severity:    "warning",
			Summary:     "Default association points to missing desktop file",
			Details:     app,
			Remediation: "Set browser defaults to an installed desktop id or reinstall the missing app.",
		}}
	}
	return nil
}

func desktopExists(p linuxProvider, desktop string) bool {
	for _, path := range desktopSearchPaths(p, desktop) {
		if _, err := p.statFile(path); err == nil {
			return true
		}
	}
	return false
}

func (p linuxProvider) checkDuplicateDesktopIDs() []DoctorFinding {
	ids := []string{"firefox.desktop", "chromium.desktop", "google-chrome.desktop", "brave-browser.desktop", "vivaldi-stable.desktop", "zen.desktop"}
	for _, id := range ids {
		count := 0
		for _, path := range desktopSearchPaths(p, id) {
			if _, err := p.statFile(path); err == nil {
				count++
			}
		}
		if count > 1 {
			return []DoctorFinding{{
				ID:          "L13",
				Severity:    "warning",
				Summary:     "Duplicate desktop IDs found in multiple application paths",
				Details:     fmt.Sprintf("%s present in %d locations", id, count),
				Remediation: "Remove/disable duplicate desktop entries to avoid nondeterministic handler selection.",
			}}
		}
	}
	return nil
}

func desktopSearchPaths(p linuxProvider, desktop string) []string {
	home, err := p.userHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".local", "share", "applications", desktop),
		filepath.Join("/usr/share/applications", desktop),
		filepath.Join("/usr/local/share/applications", desktop),
		filepath.Join("/var/lib/flatpak/exports/share/applications", desktop),
		filepath.Join(home, ".local/share/flatpak/exports/share/applications", desktop),
		filepath.Join("/var/lib/snapd/desktop/applications", desktop),
	}
}
