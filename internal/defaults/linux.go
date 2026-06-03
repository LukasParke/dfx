//go:build linux

package defaults

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type desktopEntryMetadata struct {
	name           string
	genericName    string
	execLine       string
	mimeTypes      map[string]struct{}
	appImagePath   string
	hasAppImageKey bool
}

type linuxProvider struct {
	runner      commandRunner
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	statFile    func(string) (os.FileInfo, error)
	userHomeDir func() (string, error)
	getenv      func(string) string
}

func newLinuxProvider() Provider {
	return linuxProvider{
		runner:      execRunner{},
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
		userHomeDir: os.UserHomeDir,
		getenv:      os.Getenv,
	}
}

func (p linuxProvider) readFileOrDefault(path string) ([]byte, error) {
	if p.readFile != nil {
		return p.readFile(path)
	}
	return nil, os.ErrNotExist
}

func (p linuxProvider) readDirOrDefault(path string) ([]os.DirEntry, error) {
	if p.readDir != nil {
		return p.readDir(path)
	}
	return nil, os.ErrNotExist
}

func (p linuxProvider) statFileOrDefault(path string) (os.FileInfo, error) {
	if p.statFile != nil {
		return p.statFile(path)
	}
	return nil, os.ErrNotExist
}

func (p linuxProvider) userHomeDirOrDefault() (string, error) {
	if p.userHomeDir != nil {
		return p.userHomeDir()
	}
	return "", os.ErrNotExist
}

func (p linuxProvider) getenvOrDefault(key string) string {
	if p.getenv != nil {
		return p.getenv(key)
	}
	return ""
}

func (p linuxProvider) Inspect(context.Context) InspectReport {
	canWriteSystem := os.Geteuid() == 0
	report := InspectReport{
		Platform: "linux",
		Provider: "xdg",
		CanRead:  true,
		CanWrite: true,
		Capabilities: Capabilities{
			CanReadCurrent:        true,
			CanWriteUserDefault:   true,
			CanWriteSystemDefault: canWriteSystem,
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
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return "", err
	}
	target = linuxNormalizeContentTypeToMIME(target)
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
	switch {
	case options.Browser:
		return p.doctorBrowser(ctx)
	case options.MIME != "":
		if !validMIMEType(options.MIME) {
			return DoctorReport{}, fmt.Errorf("invalid MIME type: %s", options.MIME)
		}
		return p.doctorMIME(ctx, options.MIME)
	case options.Scheme != "":
		return p.doctorScheme(ctx, options.Scheme)
	case options.ContentType != "":
		if validMIMEType(options.ContentType) {
			return p.doctorMIME(ctx, options.ContentType)
		}
		return DoctorReport{}, errors.New("Linux has no separate content-type namespace; use --mime or a valid MIME type")
	case options.All:
		return p.doctorAll(ctx)
	default:
		return DoctorReport{}, errors.New("no scope specified for linux doctor")
	}
}

func (p linuxProvider) DoctorFix(ctx context.Context, options DoctorFixOptions) (DoctorFixResult, error) {
	switch {
	case options.Browser:
		return p.doctorFixBrowser(ctx, options.DryRun)
	case options.MIME != "":
		if !validMIMEType(options.MIME) {
			return DoctorFixResult{}, fmt.Errorf("invalid MIME type: %s", options.MIME)
		}
		return p.doctorFixMIME(ctx, options.MIME, options.DryRun)
	case options.Scheme != "":
		return p.doctorFixScheme(ctx, options.Scheme, options.DryRun)
	case options.ContentType != "":
		if validMIMEType(options.ContentType) {
			return p.doctorFixMIME(ctx, options.ContentType, options.DryRun)
		}
		return DoctorFixResult{}, errors.New("Linux has no separate content-type namespace; use --mime or a valid MIME type")
	case options.All:
		return p.doctorFixAll(ctx, options.DryRun)
	default:
		return DoctorFixResult{}, errors.New("no scope specified for linux doctor fix")
	}
}

func (p linuxProvider) Set(ctx context.Context, association Association, options SetOptions) (SetResult, error) {
	association = association.Normalized()
	if err := association.Validate(); err != nil {
		return SetResult{}, err
	}
	association.Kind = linuxNormalizeContentTypeToMIME(association.Target()).Kind

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
	if options.System {
		return p.setSystem(ctx, association, targets, ops)
	}
	if _, err := p.runner.LookPath("xdg-mime"); err != nil {
		return SetResult{Changed: false, Operations: ops}, errors.New("xdg-mime is required on Linux")
	}

	changed := false
	for _, target := range targets {
		if _, err := p.runner.Run(ctx, "xdg-mime", "default", association.App, linuxAssociationName(target)); err != nil {
			return SetResult{Changed: changed, Operations: ops}, err
		}
		changed = true
	}
	if isBrowserTarget(association.Target()) && hasCommand(p.runner, "xdg-settings") {
		if _, err := p.runner.Run(ctx, "xdg-settings", "set", "default-web-browser", association.App); err != nil {
			return SetResult{Changed: changed, Operations: ops}, err
		}
		changed = true
	}
	return SetResult{Changed: changed, Operations: ops}, nil
}

func (p linuxProvider) setSystem(ctx context.Context, association Association, targets []Target, ops []string) (SetResult, error) {
	if os.Geteuid() != 0 {
		return SetResult{Changed: false, Operations: ops}, errors.New("system-level writes on Linux require root privileges")
	}
	systemPath := "/etc/xdg/mimeapps.list"
	if err := os.MkdirAll(filepath.Dir(systemPath), 0o755); err != nil {
		return SetResult{Changed: false, Operations: ops}, fmt.Errorf("create system config dir: %w", err)
	}
	content, _ := os.ReadFile(systemPath)
	updated := linuxUpdateMIMEAppsList(string(content), association)
	if err := os.WriteFile(systemPath, []byte(updated), 0o644); err != nil {
		return SetResult{Changed: false, Operations: ops}, fmt.Errorf("write system mimeapps.list: %w", err)
	}
	if hasCommand(p.runner, "update-desktop-database") {
		p.runner.Run(ctx, "update-desktop-database")
	}
	if hasCommand(p.runner, "update-mime-database") {
		p.runner.Run(ctx, "update-mime-database", "/usr/share/mime")
	}
	return SetResult{Changed: true, Operations: append(ops, "Wrote system /etc/xdg/mimeapps.list")}, nil
}

func linuxUpdateMIMEAppsList(content string, association Association) string {
	key := linuxAssociationName(association.Target())
	value := association.App
	lines := strings.Split(content, "\n")
	var out []string
	inDefaults := false
	found := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[Default Applications]" {
			inDefaults = true
			out = append(out, line)
			continue
		}
		if inDefaults && strings.HasPrefix(trimmed, "[") {
			if !found {
				out = append(out, key+"="+value+";")
				found = true
			}
			inDefaults = false
		}
		if inDefaults {
			if eq := strings.Index(line, "="); eq > 0 {
				k := strings.TrimSpace(line[:eq])
				if k == key {
					out = append(out, key+"="+value+";")
					found = true
					continue
				}
			}
		}
		out = append(out, line)
	}
	if !found {
		if !inDefaults {
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
				out = append(out, "")
			}
			out = append(out, "[Default Applications]")
		}
		out = append(out, key+"="+value+";")
	}
	return strings.Join(out, "\n")
}

func (p linuxProvider) ResolveApp(_ context.Context, query string, target Target) (AppResolution, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return AppResolution{}, errors.New("app is required")
	}
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return AppResolution{}, err
	}
	target = linuxNormalizeContentTypeToMIME(target)

	for _, id := range linuxDesktopIDGuesses(query) {
		if desktopExists(p, id) {
			return AppResolution{App: id, Source: "linux desktop entry", Candidates: []string{id}}, nil
		}
	}

	candidates := p.linuxDesktopCandidates(query, target)
	if len(candidates) == 0 {
		if strings.HasSuffix(strings.ToLower(query), ".desktop") {
			return AppResolution{App: query, Source: "literal desktop id"}, nil
		}
		return AppResolution{}, fmt.Errorf("could not resolve app query %q to an installed Linux desktop entry; use --app with an exact .desktop id", query)
	}
	if len(candidates) > 1 && candidates[0].score == candidates[1].score {
		return AppResolution{}, fmt.Errorf("app query %q is ambiguous on Linux; use an exact .desktop id: %s", query, strings.Join(linuxDesktopCandidateIDs(candidates), ", "))
	}
	return AppResolution{
		App:        candidates[0].id,
		Source:     "linux desktop entry",
		Candidates: linuxDesktopCandidateIDs(candidates),
	}, nil
}

type linuxDesktopCandidate struct {
	id    string
	score int
}

func (p linuxProvider) linuxDesktopCandidates(query string, target Target) []linuxDesktopCandidate {
	queryToken := linuxNormalizeAppToken(query)
	if queryToken == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var candidates []linuxDesktopCandidate
	for _, dir := range linuxApplicationDirs(p) {
		entries, err := p.readDirOrDefault(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			id := entry.Name()
			if !strings.HasSuffix(strings.ToLower(id), ".desktop") {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			raw, err := p.readFileOrDefault(filepath.Join(dir, id))
			if err != nil {
				continue
			}
			metadata, ok := parseDesktopEntryMetadata(string(raw))
			if !ok {
				continue
			}
			score := linuxDesktopMatchScore(queryToken, query, id, metadata, target)
			if score == 0 {
				continue
			}
			seen[id] = struct{}{}
			candidates = append(candidates, linuxDesktopCandidate{id: id, score: score})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].id < candidates[j].id
	})
	return candidates
}

func linuxDesktopIDGuesses(query string) []string {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	guesses := []string{query}
	if !strings.HasSuffix(strings.ToLower(query), ".desktop") {
		guesses = append(guesses, query+".desktop")
	}
	switch linuxNormalizeAppToken(query) {
	case "brave", "bravebrowser":
		guesses = append(guesses, "brave-browser.desktop")
	case "chrome", "googlechrome":
		guesses = append(guesses, "google-chrome.desktop")
	case "chromium":
		guesses = append(guesses, "chromium.desktop")
	case "edge", "microsoftedge":
		guesses = append(guesses, "microsoft-edge.desktop")
	case "firefox":
		guesses = append(guesses, "firefox.desktop")
	case "vivaldi":
		guesses = append(guesses, "vivaldi-stable.desktop")
	case "zen", "zenbrowser":
		guesses = append(guesses, "zen.desktop")
	}

	seen := map[string]struct{}{}
	unique := guesses[:0]
	for _, guess := range guesses {
		guess = strings.TrimSpace(guess)
		if guess == "" {
			continue
		}
		key := strings.ToLower(guess)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, guess)
	}
	return unique
}

func linuxDesktopMatchScore(queryToken, query, id string, metadata desktopEntryMetadata, target Target) int {
	idLower := strings.ToLower(id)
	queryLower := strings.ToLower(strings.TrimSpace(query))
	idBase := strings.TrimSuffix(idLower, ".desktop")
	fields := []string{idLower, idBase, metadata.name, metadata.genericName, linuxDesktopExecName(metadata.execLine)}

	score := 0
	for _, field := range fields {
		fieldToken := linuxNormalizeAppToken(field)
		if fieldToken == "" {
			continue
		}
		switch {
		case strings.EqualFold(field, queryLower), fieldToken == queryToken:
			if score < 900 {
				score = 900
			}
		case strings.HasPrefix(fieldToken, queryToken):
			if score < 700 {
				score = 700
			}
		case strings.Contains(fieldToken, queryToken):
			if score < 500 {
				score = 500
			}
		}
	}
	if score == 0 {
		return 0
	}
	if metadata.supportsTarget(target) {
		score += 100
	}
	return score
}

func linuxNormalizeAppToken(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func linuxDesktopExecName(execLine string) string {
	fields := strings.Fields(execLine)
	if len(fields) == 0 {
		return ""
	}
	return filepath.Base(strings.Trim(fields[0], `"'`))
}

func linuxDesktopCandidateIDs(candidates []linuxDesktopCandidate) []string {
	limit := len(candidates)
	if limit > 5 {
		limit = 5
	}
	ids := make([]string, 0, limit)
	for _, candidate := range candidates[:limit] {
		ids = append(ids, candidate.id)
	}
	return ids
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

func linuxNormalizeContentTypeToMIME(target Target) Target {
	if target.Kind == KindContentType {
		if validMIMEType(target.Value) {
			return Target{Kind: KindMIME, Value: target.Value}
		}
	}
	return target
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
		content, err := p.readFileOrDefault(path)
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
	home, err := p.userHomeDirOrDefault()
	if err != nil {
		return nil
	}
	xdgConfigHome := p.getenvOrDefault("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	xdgDataHome := p.getenvOrDefault("XDG_DATA_HOME")
	if xdgDataHome == "" {
		xdgDataHome = filepath.Join(home, ".local", "share")
	}
	xdgConfigDirs := splitOrDefault(p.getenvOrDefault("XDG_CONFIG_DIRS"), []string{"/etc/xdg"})
	xdgDataDirs := splitOrDefault(p.getenvOrDefault("XDG_DATA_DIRS"), []string{"/usr/local/share", "/usr/share"})
	desktops := currentDesktops(p.getenvOrDefault("XDG_CURRENT_DESKTOP"))

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
	parts := strings.FieldsFunc(strings.TrimSpace(strings.ToLower(value)), func(r rune) bool {
		return r == ':' || r == ';' || r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			if _, exists := seen[part]; exists {
				continue
			}
			seen[part] = struct{}{}
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

func (p linuxProvider) checkCurrentDesktopContext() []DoctorFinding {
	current := strings.TrimSpace(p.getenvOrDefault("XDG_CURRENT_DESKTOP"))
	if current == "" {
		return nil
	}
	if strings.ContainsAny(current, ",;") || strings.Contains(current, " ") {
		return []DoctorFinding{{
			ID:          "L24",
			Severity:    "warning",
			Summary:     "XDG_CURRENT_DESKTOP looks malformed",
			Details:     current,
			Remediation: "Use colon-separated desktop identifiers, such as KDE:GNOME, or keep unset for WM-only sessions.",
		}}
	}
	return nil
}

func (p linuxProvider) checkMetadataMaintenanceTools() []DoctorFinding {
	findings := []DoctorFinding{}
	if !hasCommand(p.runner, "update-desktop-database") {
		findings = append(findings, DoctorFinding{
			ID:          "L15",
			Severity:    "warning",
			Summary:     "Optional metadata maintenance command missing: update-desktop-database",
			Remediation: "Install desktop-file-utils and run update-desktop-database to refresh cached desktop metadata.",
		})
	}
	if !hasCommand(p.runner, "update-mime-database") {
		findings = append(findings, DoctorFinding{
			ID:          "L16",
			Severity:    "warning",
			Summary:     "Optional MIME cache update command missing: update-mime-database",
			Remediation: "Install shared-mime-info and refresh MIME cache after changing MIME declarations.",
		})
	}
	return findings
}

func (p linuxProvider) checkOpenPathContext(browserApp string) []DoctorFinding {
	sessionType := strings.ToLower(strings.TrimSpace(p.getenvOrDefault("XDG_SESSION_TYPE")))
	desktop := strings.ToLower(strings.TrimSpace(p.getenvOrDefault("XDG_CURRENT_DESKTOP")))
	hasBackend := hasCommand(p.runner, "xdg-desktop-portal-gtk") ||
		hasCommand(p.runner, "xdg-desktop-portal-kde") ||
		hasCommand(p.runner, "xdg-desktop-portal-wlr") ||
		hasCommand(p.runner, "xdg-desktop-portal-hyprland")
	findings := []DoctorFinding{}
	if (strings.EqualFold(sessionType, "wayland") || strings.Contains(desktop, "gnome") || strings.Contains(desktop, "kde")) && !hasBackend {
		findings = append(findings, DoctorFinding{
			ID:          "L09",
			Severity:    "warning",
			Summary:     "Session type may prefer portal open paths not fully backed by desktop portal",
			Details:     sessionType,
			Remediation: "Install a matching xdg-desktop-portal backend for this session and re-run doctor.",
		})
	}
	if strings.EqualFold(sessionType, "x11") && browserApp != "" && !hasCommand(p.runner, "xdg-open") {
		findings = append(findings, DoctorFinding{
			ID:          "L30",
			Severity:    "warning",
			Summary:     "xdg-open is missing on an X11 session",
			Details:     "fallback open paths may differ for local vs portal-based URIs",
			Remediation: "Install xdg-utils and verify dfx open behavior in your target context.",
		})
	}
	return findings
}

func (p linuxProvider) checkCallbackScheme(currentDefaults map[string]string) []DoctorFinding {
	scheme := normalizeCallbackScheme(p.getenvOrDefault("DFX_CALLBACK_SCHEME"))
	if scheme == "" {
		return nil
	}
	app, err := p.Get(context.Background(), Target{Kind: KindScheme, Value: scheme})
	if err != nil || app == "" || strings.EqualFold(strings.TrimSpace(app), "None") {
		return []DoctorFinding{{
			ID:          "L20",
			Severity:    "warning",
			Summary:     "Configured callback scheme is unset",
			Details:     scheme,
			Remediation: "Set DFX_CALLBACK_SCHEME to a URI scheme mapped to an installed native app.",
		}}
	}
	browserApp := strings.TrimSpace(currentDefaults["x-scheme-handler/http"])
	if browserApp != "" && strings.EqualFold(app, browserApp) {
		return []DoctorFinding{{
			ID:          "L21",
			Severity:    "warning",
			Summary:     "Callback scheme points to the current browser default",
			Details:     scheme + "=" + app,
			Remediation: "Point the callback scheme to a native app handler to avoid browser-only deep link loops.",
		}}
	}
	return nil
}

func (p linuxProvider) checkCrossDesktopConfigConflicts(active map[string]string) []DoctorFinding {
	keys := []string{"x-scheme-handler/http", "x-scheme-handler/https", "text/html", "application/xhtml+xml"}
	conflicts := make(map[string]struct{}, len(keys)*2)
	current := currentDesktops(p.getenvOrDefault("XDG_CURRENT_DESKTOP"))
	currentSet := make(map[string]struct{}, len(current)+1)
	currentSet["generic"] = struct{}{}
	for _, desktop := range current {
		currentSet[desktop] = struct{}{}
	}

	for _, path := range p.crossDesktopMIMEAppsLookupPaths() {
		desktop := strings.ToLower(mimeappsDesktopToken(path))
		if desktop == "" {
			continue
		}
		if desktop != "generic" {
			if _, isCurrent := currentSet[desktop]; isCurrent {
				continue
			}
		}
		content, err := p.readFileOrDefault(path)
		if err != nil {
			continue
		}
		for _, key := range keys {
			want := strings.TrimSpace(active[key])
			if want == "" || strings.EqualFold(want, "None") {
				continue
			}
			if app, ok := parseDefaultFromMIMEApps(string(content), key); ok {
				if !strings.EqualFold(app, want) {
					conflicts[fmt.Sprintf("%s=%s in %s (current=%s)", key, app, path, want)] = struct{}{}
				}
			}
		}
	}
	if len(conflicts) == 0 {
		return nil
	}
	details := make([]string, 0, len(conflicts))
	for conflict := range conflicts {
		details = append(details, conflict)
	}
	return []DoctorFinding{{
		ID:          "L27",
		Severity:    "warning",
		Summary:     "Cross-desktop mimeapps files contain conflicting values",
		Details:     strings.Join(details, "; "),
		Remediation: "Remove stale desktop-specific mimeapps entries after switching desktop environments.",
	}}
}

func (p linuxProvider) crossDesktopMIMEAppsLookupPaths() []string {
	paths := p.mimeappsLookupPaths()
	home, err := p.userHomeDirOrDefault()
	if err != nil {
		return dedupePaths(paths)
	}

	xdgConfigHome := p.getenvOrDefault("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	xdgDataHome := p.getenvOrDefault("XDG_DATA_HOME")
	if xdgDataHome == "" {
		xdgDataHome = filepath.Join(home, ".local", "share")
	}
	xdgConfigDirs := splitOrDefault(p.getenvOrDefault("XDG_CONFIG_DIRS"), []string{"/etc/xdg"})
	xdgDataDirs := splitOrDefault(p.getenvOrDefault("XDG_DATA_DIRS"), []string{"/usr/local/share", "/usr/share"})

	paths = append(paths, wildcardMIMEApps(filepath.Join(xdgConfigHome, "*-mimeapps.list"))...)
	paths = append(paths, wildcardMIMEApps(filepath.Join(xdgDataHome, "applications", "*-mimeapps.list"))...)
	for _, dir := range xdgConfigDirs {
		paths = append(paths, wildcardMIMEApps(filepath.Join(dir, "*-mimeapps.list"))...)
	}
	for _, dir := range xdgDataDirs {
		paths = append(paths, wildcardMIMEApps(filepath.Join(dir, "applications", "*-mimeapps.list"))...)
	}
	return dedupePaths(paths)
}

func wildcardMIMEApps(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	return matches
}

func mimeappsDesktopToken(path string) string {
	base := filepath.Base(path)
	if base == "mimeapps.list" {
		return "generic"
	}
	if !strings.HasSuffix(base, "-mimeapps.list") {
		return ""
	}
	return strings.TrimSuffix(base, "-mimeapps.list")
}

func (p linuxProvider) checkBrowserEnvFallback() []DoctorFinding {
	browser := strings.TrimSpace(p.getenvOrDefault("BROWSER"))
	if browser == "" || strings.HasPrefix(browser, "xdg-open") {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L10",
		Severity:    "warning",
		Summary:     "BROWSER environment variable may override CLI-driven opens",
		Details:     browser,
		Remediation: "Unset BROWSER while validating defaults, or ensure it points to your selected browser command.",
	}}
}

func (p linuxProvider) checkToolkitDisagreement(ctx context.Context) []DoctorFinding {
	if !hasCommand(p.runner, "gio") {
		return nil
	}

	keys := []string{"x-scheme-handler/http", "x-scheme-handler/https", "text/html", "application/xhtml+xml"}
	conflicts := map[string][]string{
		"L02": nil,
		"L19": nil,
	}
	for _, key := range keys {
		target := Target{Kind: KindMIME, Value: key}
		if strings.HasPrefix(key, "x-scheme-handler/") {
			target = Target{Kind: KindScheme, Value: strings.TrimPrefix(key, "x-scheme-handler/")}
		}
		xdgApp, err := p.Get(ctx, target)
		if err != nil {
			continue
		}
		xdgApp = strings.TrimSpace(xdgApp)
		if xdgApp == "" || strings.EqualFold(xdgApp, "None") {
			continue
		}
		gioApp, err := p.gioDefaultForAssociation(ctx, key)
		if err != nil {
			continue
		}
		gioApp = strings.TrimSpace(gioApp)
		if gioApp == "" || strings.EqualFold(gioApp, "None") {
			continue
		}
		issueID := "L02"
		if !strings.HasPrefix(key, "x-scheme-handler/") {
			issueID = "L19"
		}
		if xdgApp != gioApp {
			conflicts[issueID] = append(conflicts[issueID], fmt.Sprintf("%s: xdg-mime=%q gio=%q", key, xdgApp, gioApp))
		}
	}

	findings := make([]DoctorFinding, 0, 2)
	for _, issueID := range []string{"L02", "L19"} {
		if len(conflicts[issueID]) == 0 {
			continue
		}
		summary := "xdg-mime and GIO report different defaults"
		remediation := "Use desktop-specific tools to align xdg and GIO defaults."
		if issueID == "L19" {
			summary = "xdg-mime defaults and GIO content defaults disagree"
			remediation = "Verify toolkit open-path defaults after desktop updates and launch registration refresh."
		}
		findings = append(findings, DoctorFinding{
			ID:          issueID,
			Severity:    "warning",
			Summary:     summary,
			Details:     strings.Join(conflicts[issueID], "; "),
			Remediation: remediation,
		})
	}
	return findings
}

func (p linuxProvider) checkOverrideRemovedButUISync(ctx context.Context, currentDefaults map[string]string) []DoctorFinding {
	if !hasCommand(p.runner, "gio") {
		return nil
	}
	keys := []string{"x-scheme-handler/http", "x-scheme-handler/https", "text/html", "application/xhtml+xml"}
	var stale []string
	for _, key := range keys {
		current := strings.TrimSpace(currentDefaults[key])
		if current != "" && !strings.EqualFold(current, "None") {
			continue
		}
		toolkit, err := p.gioDefaultForAssociation(ctx, key)
		if err != nil {
			continue
		}
		toolkit = strings.TrimSpace(toolkit)
		if toolkit == "" || strings.EqualFold(toolkit, "None") {
			continue
		}
		stale = append(stale, fmt.Sprintf("%s: toolkit=%q", key, toolkit))
	}
	if len(stale) == 0 {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L18",
		Severity:    "warning",
		Summary:     "Toolkit still reports a handler after user override was removed",
		Details:     strings.Join(stale, "; "),
		Remediation: "Clear stale defaults cache and re-run desktop association sync for affected types.",
	}}
}

func (p linuxProvider) checkAppImageRegistrationMissing(associations map[string]string) []DoctorFinding {
	if len(associations) == 0 {
		return nil
	}
	checked := make(map[string]struct{}, len(associations))
	var missing []string
	for _, app := range associations {
		app = strings.TrimSpace(app)
		if app == "" || app == "None" {
			continue
		}
		if _, ok := checked[app]; ok {
			continue
		}
		checked[app] = struct{}{}

		meta, ok := p.desktopMetadata(app)
		if !ok || !meta.isAppImageDesktop() {
			continue
		}
		if meta.hasAppImageRegistration() {
			continue
		}
		missing = append(missing, app)
	}
	if len(missing) == 0 {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L12",
		Severity:    "warning",
		Summary:     "AppImage desktop entry appears unregistered for persistent defaults",
		Details:     strings.Join(missing, ", "),
		Remediation: "Use AppImage registration tooling to generate a stable desktop entry with AppImage metadata and re-run doctor.",
	}}
}

func (p linuxProvider) checkMIMESniffMismatch(ctx context.Context) []DoctorFinding {
	if !hasCommand(p.runner, "file") || !hasCommand(p.runner, "xdg-mime") {
		return nil
	}
	tmpDir, err := os.MkdirTemp("", "dfx-mime-sniff-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tmpDir)

	probes := []struct {
		suffix   string
		expected string
		content  string
	}{
		{suffix: ".html", expected: "text/html", content: "%PDF-1.4\n%Fake pdf header\n"},
	}

	var mismatches []string
	for _, probe := range probes {
		path := filepath.Join(tmpDir, "dfx-sniff"+probe.suffix)
		if err := os.WriteFile(path, []byte(probe.content), 0o644); err != nil {
			continue
		}

		extMime, err := p.runner.Run(ctx, "xdg-mime", "query", "filetype", path)
		if err != nil {
			continue
		}
		fileMime, err := p.runner.Run(ctx, "file", "--mime-type", path)
		if err != nil {
			continue
		}

		extMime = parseMimeTypeFromOutput(extMime)
		fileMime = parseMimeTypeFromOutput(fileMime)
		if extMime == "" || fileMime == "" {
			continue
		}
		if extMime == probe.expected && fileMime != probe.expected {
			mismatches = append(mismatches, fmt.Sprintf("%s: xdg-mime=%q file=%q", probe.suffix, extMime, fileMime))
		}
	}

	if len(mismatches) == 0 {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L28",
		Severity:    "warning",
		Summary:     "MIME sniff result does not match extension-backed defaulting behavior",
		Details:     strings.Join(mismatches, "; "),
		Remediation: "Verify file association registration for the content type and avoid content/extension hybrid handlers.",
	}}
}

func parseMimeTypeFromOutput(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if idx := strings.Index(raw, ":"); idx >= 0 {
		raw = strings.TrimSpace(raw[idx+1:])
	}
	if idx := strings.Index(raw, ";"); idx >= 0 {
		raw = strings.TrimSpace(raw[:idx])
	}
	return raw
}

func (p linuxProvider) checkFileManagerCacheLag(associations map[string]string) []DoctorFinding {
	if len(associations) == 0 {
		return nil
	}
	home, err := p.userHomeDirOrDefault()
	if err != nil {
		return nil
	}

	checked := make(map[string]struct{}, len(associations))
	var latestDesktopApp time.Time
	for _, app := range associations {
		app = strings.TrimSpace(app)
		if app == "" || app == "None" {
			continue
		}
		if _, ok := checked[app]; ok {
			continue
		}
		checked[app] = struct{}{}

		for _, path := range desktopSearchPaths(p, app) {
			info, err := p.statFileOrDefault(path)
			if err != nil {
				continue
			}
			if info.ModTime().After(latestDesktopApp) {
				latestDesktopApp = info.ModTime()
			}
		}
	}
	if latestDesktopApp.IsZero() {
		return nil
	}

	cachePaths := dedupePaths([]string{
		filepath.Join(home, ".local", "share", "mime", "mime.cache"),
		filepath.Join(home, ".cache", "mimeinfo.cache"),
		filepath.Join(home, ".local", "share", "applications", "mimeinfo.cache"),
		"/usr/share/mime/mime.cache",
		"/usr/local/share/mime/mime.cache",
		"/var/cache/mime/mime.cache",
	})
	var stale []string
	for _, path := range cachePaths {
		info, err := p.statFileOrDefault(path)
		if err != nil {
			continue
		}
		if info.ModTime().Before(latestDesktopApp) {
			stale = append(stale, path)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L29",
		Severity:    "warning",
		Summary:     "File manager and MIME caches appear stale relative to updated desktop files",
		Details:     strings.Join(stale, "; "),
		Remediation: "Run cache refresh steps (update-mime-database and update-desktop-database) and restart file manager sessions.",
	}}
}

func (p linuxProvider) checkPortalMismatch(ctx context.Context) []DoctorFinding {
	if !hasCommand(p.runner, "flatpak") || !hasCommand(p.runner, "flatpak-spawn") {
		return nil
	}

	keys := []string{"x-scheme-handler/http", "x-scheme-handler/https", "text/html"}
	var mismatches []string
	for _, key := range keys {
		host, err := p.runner.Run(ctx, "flatpak-spawn", "--host", "xdg-mime", "query", "default", key)
		if err != nil {
			return nil
		}
		local, err := p.runner.Run(ctx, "xdg-mime", "query", "default", key)
		if err != nil {
			continue
		}
		host = strings.TrimSpace(host)
		local = strings.TrimSpace(local)
		if host == "" || local == "" {
			continue
		}
		if host != local {
			mismatches = append(mismatches, fmt.Sprintf("%s: host=%q local=%q", key, host, local))
		}
	}
	if len(mismatches) == 0 {
		return nil
	}
	return []DoctorFinding{{
		ID:          "L07",
		Severity:    "warning",
		Summary:     "Flatpak portal and host defaults are misaligned",
		Details:     strings.Join(mismatches, "; "),
		Remediation: "Align host and Flatpak-context registration for the same browser identifiers.",
	}}
}

func (p linuxProvider) gioDefaultForAssociation(ctx context.Context, key string) (string, error) {
	raw, err := p.runner.Run(ctx, "gio", "mime", key)
	if err != nil {
		return "", err
	}
	prefix := "Default application for " + key + ":"
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		for _, candidate := range strings.Split(value, ";") {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" {
				return candidate, nil
			}
		}
		return "", nil
	}
	for _, candidate := range strings.Split(strings.TrimSpace(raw), ";") {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("unable to parse gio output for %q", key)
}

func (p linuxProvider) checkBrowserEntryClaims(associations map[string]string) []DoctorFinding {
	type appTargets map[string][]string
	byApp := make(appTargets)
	for key, app := range associations {
		app = strings.TrimSpace(app)
		if app == "" || app == "None" {
			continue
		}
		byApp[app] = append(byApp[app], key)
	}

	findings := make([]DoctorFinding, 0, len(byApp))
	for app, targets := range byApp {
		meta, ok := p.desktopMetadata(app)
		if !ok {
			continue
		}
		var missing []string
		needsURL := false
		for _, key := range targets {
			if strings.HasPrefix(key, "x-scheme-handler/") {
				needsURL = true
			}
			if _, has := meta.mimeTypes[key]; !has {
				missing = append(missing, key)
			}
		}
		if needsURL && !meta.hasURLPlaceholder() {
			findings = append(findings, DoctorFinding{
				ID:          "L06",
				Severity:    "warning",
				Summary:     "Desktop entry for browser handler lacks URL placeholder",
				Details:     app,
				Remediation: "Ensure Exec includes %u or %U for URL handler compatibility.",
			})
		}
		if len(missing) > 0 {
			findings = append(findings, DoctorFinding{
				ID:          "L17",
				Severity:    "warning",
				Summary:     "Browser default targets are not declared in the desktop file",
				Details:     fmt.Sprintf("%s missing: %s", app, strings.Join(missing, ", ")),
				Remediation: "Add the missing MimeType entries to the desktop file and refresh desktop metadata.",
			})
		}
	}
	return findings
}

func (p linuxProvider) checkRootOwnedUserMIMEApps() []DoctorFinding {
	home, err := p.userHomeDirOrDefault()
	if err != nil {
		return nil
	}
	path := filepath.Join(home, ".config", "mimeapps.list")
	info, err := p.statFileOrDefault(path)
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
		content, err := p.readFileOrDefault(path)
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
		content, err := p.readFileOrDefault(path)
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
		if _, err := p.statFileOrDefault(path); err == nil {
			return true
		}
	}
	return false
}

func (p linuxProvider) desktopMetadata(app string) (desktopEntryMetadata, bool) {
	for _, path := range desktopSearchPaths(p, app) {
		raw, err := p.readFileOrDefault(path)
		if err != nil {
			continue
		}
		meta, ok := parseDesktopEntryMetadata(string(raw))
		if !ok {
			continue
		}
		return meta, true
	}
	return desktopEntryMetadata{}, false
}

func parseDesktopEntryMetadata(content string) (desktopEntryMetadata, bool) {
	metadata := desktopEntryMetadata{
		mimeTypes: make(map[string]struct{}),
	}
	inSection := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = strings.EqualFold(line, "[Desktop Entry]")
			continue
		}
		if !inSection {
			continue
		}
		left, right, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		left = strings.TrimSpace(left)
		right = strings.TrimSpace(right)
		switch {
		case strings.EqualFold(left, "Name") || (metadata.name == "" && strings.HasPrefix(strings.ToLower(left), "name[")):
			metadata.name = right
		case strings.EqualFold(left, "GenericName") || (metadata.genericName == "" && strings.HasPrefix(strings.ToLower(left), "genericname[")):
			metadata.genericName = right
		case strings.EqualFold(left, "Exec"):
			metadata.execLine = right
		case strings.EqualFold(left, "X-AppImage-Path") || strings.HasPrefix(strings.ToLower(left), "x-appimage-"):
			metadata.hasAppImageKey = true
			if strings.EqualFold(left, "X-AppImage-Path") {
				metadata.appImagePath = right
			}
		case strings.EqualFold(left, "MimeType"):
			for _, mime := range strings.Split(right, ";") {
				mime = strings.TrimSpace(mime)
				if mime != "" {
					metadata.mimeTypes[mime] = struct{}{}
				}
			}
		}
	}
	if metadata.name == "" && metadata.execLine == "" && len(metadata.mimeTypes) == 0 {
		return desktopEntryMetadata{}, false
	}
	return metadata, true
}

func (metadata desktopEntryMetadata) supportsTarget(target Target) bool {
	for _, candidate := range linuxTargetsForAssociation(target) {
		if _, ok := metadata.mimeTypes[linuxAssociationName(candidate)]; ok {
			return true
		}
	}
	return false
}

func (metadata desktopEntryMetadata) hasURLPlaceholder() bool {
	return strings.Contains(metadata.execLine, "%u") || strings.Contains(metadata.execLine, "%U")
}

func (metadata desktopEntryMetadata) isAppImageDesktop() bool {
	return strings.Contains(strings.ToLower(metadata.execLine), ".appimage")
}

func (metadata desktopEntryMetadata) hasAppImageRegistration() bool {
	return metadata.hasAppImageKey && metadata.appImagePath != ""
}

func (p linuxProvider) checkDuplicateDesktopIDs(apps ...string) []DoctorFinding {
	ids := []string{"firefox.desktop", "chromium.desktop", "google-chrome.desktop", "brave-browser.desktop", "vivaldi-stable.desktop", "zen.desktop"}
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app == "" || app == "None" {
			continue
		}
		ids = append(ids, app)
	}
	seen := make(map[string]struct{}, len(ids))
	uniq := ids[:0]
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	ids = uniq

	for _, id := range ids {
		count := 0
		var pathsFound []string
		for _, path := range desktopSearchPaths(p, id) {
			if _, err := p.statFileOrDefault(path); err == nil {
				count++
				pathsFound = append(pathsFound, path)
			}
		}
		if count > 1 {
			findings := []DoctorFinding{{
				ID:          "L13",
				Severity:    "warning",
				Summary:     "Duplicate desktop IDs found in multiple application paths",
				Details:     fmt.Sprintf("%s present in %d locations", id, count),
				Remediation: "Remove/disable duplicate desktop entries to avoid nondeterministic handler selection.",
			}}
			if hasContainerShadowing(pathsFound) {
				findings = append(findings, DoctorFinding{
					ID:          "L14",
					Severity:    "warning",
					Summary:     "Snap/Flatpak desktop entries shadow native package entries",
					Details:     fmt.Sprintf("%s present in native and container-provided paths", id),
					Remediation: "Prefer one app family (native or container) for the browser default IDs.",
				})
			}
			return findings
		}
	}
	return nil
}

func hasContainerShadowing(paths []string) bool {
	hasNative := false
	hasFlatpak := false
	hasSnap := false
	for _, path := range paths {
		switch {
		case strings.Contains(path, filepath.Join(string(filepath.Separator), "var", "lib", "flatpak", string(filepath.Separator))) ||
			strings.Contains(path, filepath.Join(string(filepath.Separator), ".local", "share", "flatpak", string(filepath.Separator))):
			hasFlatpak = true
		case strings.Contains(path, filepath.Join(string(filepath.Separator), "var", "lib", "snapd", string(filepath.Separator))):
			hasSnap = true
		default:
			hasNative = true
		}
	}
	return (hasFlatpak && (hasNative || hasSnap)) || (hasSnap && hasNative)
}

func desktopSearchPaths(p linuxProvider, desktop string) []string {
	dirs := linuxApplicationDirs(p)
	if len(dirs) == 0 {
		return nil
	}
	paths := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		paths = append(paths, filepath.Join(dir, desktop))
	}
	return paths
}

func linuxApplicationDirs(p linuxProvider) []string {
	home, err := p.userHomeDirOrDefault()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".local", "share", "applications"),
		"/usr/share/applications",
		"/usr/local/share/applications",
		"/var/lib/flatpak/exports/share/applications",
		filepath.Join(home, ".local/share/flatpak/exports/share/applications"),
		"/var/lib/snapd/desktop/applications",
	}
}


func (p linuxProvider) doctorBrowser(ctx context.Context) (DoctorReport, error) {
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
	if !hasCommand(p.runner, "xdg-open") {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L11",
			Severity:    "warning",
			Summary:     "Optional command missing: xdg-open",
			Remediation: "Install xdg-utils package support for non-DE open flows.",
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
	currentDefaults := map[string]string{
		"x-scheme-handler/http":  httpApp,
		"x-scheme-handler/https": httpsApp,
		"text/html":              htmlApp,
		"application/xhtml+xml":  xhtmlApp,
	}
	report.Findings = append(report.Findings, p.checkMalformedMIMEApps()...)
	report.Findings = append(report.Findings, p.checkCurrentDesktopContext()...)
	report.Findings = append(report.Findings, p.checkBrowserEnvFallback()...)
	report.Findings = append(report.Findings, p.checkPrecedenceConflicts()...)
	report.Findings = append(report.Findings, p.checkCrossDesktopConfigConflicts(currentDefaults)...)
	report.Findings = append(report.Findings, p.checkMetadataMaintenanceTools()...)
	report.Findings = append(report.Findings, p.checkOpenPathContext(httpApp)...)
	report.Findings = append(report.Findings, p.checkMIMESniffMismatch(ctx)...)
	report.Findings = append(report.Findings, p.checkCallbackScheme(currentDefaults)...)
	report.Findings = append(report.Findings, p.checkPortalMismatch(ctx)...)
	report.Findings = append(report.Findings, p.checkToolkitDisagreement(ctx)...)
	report.Findings = append(report.Findings, p.checkOverrideRemovedButUISync(ctx, currentDefaults)...)

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
	report.Findings = append(report.Findings, p.checkBrowserEntryClaims(currentDefaults)...)
	report.Findings = append(report.Findings, p.checkDuplicateDesktopIDs(httpApp, httpsApp, htmlApp, xhtmlApp)...)
	report.Findings = append(report.Findings, p.checkAppImageRegistrationMissing(currentDefaults)...)
	report.Findings = append(report.Findings, p.checkFileManagerCacheLag(currentDefaults)...)

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

func (p linuxProvider) doctorFixBrowser(ctx context.Context, dryRun bool) (DoctorFixResult, error) {
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

	result, err := p.Set(ctx, Association{Kind: KindBrowser, Value: "default", App: app}, SetOptions{DryRun: dryRun})
	if err != nil {
		return DoctorFixResult{Changed: result.Changed, Operations: result.Operations}, err
	}
	return DoctorFixResult{Changed: result.Changed, Operations: result.Operations}, nil
}

func (p linuxProvider) doctorMIME(ctx context.Context, mimeType string) (DoctorReport, error) {
	report := DoctorReport{
		Platform: "linux",
		Scope:    fmt.Sprintf("mime:%s", mimeType),
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

	app, err := p.Get(ctx, Target{Kind: KindMIME, Value: mimeType})
	if err != nil {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L31",
			Severity:    "error",
			Summary:     fmt.Sprintf("Unable to query default handler for %s", mimeType),
			Details:     err.Error(),
			Remediation: "Ensure xdg-mime is installed and MIME database is valid.",
		})
		return report, nil
	}

	app = strings.TrimSpace(app)
	if app == "" || strings.EqualFold(app, "None") {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L31",
			Severity:    "error",
			Summary:     fmt.Sprintf("No default handler set for %s", mimeType),
			Remediation: fmt.Sprintf("Run dfx set --mime %s --app <desktop-id> to set a default handler.", mimeType),
		})
	} else {
		if !desktopExists(p, app) {
			report.Healthy = false
			report.Findings = append(report.Findings, DoctorFinding{
				ID:          "L31",
				Severity:    "error",
				Summary:     fmt.Sprintf("Default handler for %s points to missing desktop file", mimeType),
				Details:     app,
				Remediation: "Set the default to an installed desktop id or reinstall the missing app.",
			})
		}

		meta, ok := p.desktopMetadata(app)
		if ok {
			if _, has := meta.mimeTypes[mimeType]; !has {
				report.Findings = append(report.Findings, DoctorFinding{
					ID:          "L31",
					Severity:    "warning",
					Summary:     fmt.Sprintf("Desktop entry for %s handler does not declare the MIME type", mimeType),
					Details:     app,
					Remediation: "Add the missing MimeType entry to the desktop file and refresh desktop metadata.",
				})
			}
		}

		report.Findings = append(report.Findings, p.checkPrecedenceConflictsForKey(mimeType)...)
		report.Findings = append(report.Findings, p.checkToolkitDisagreementForKey(ctx, mimeType)...)
	}

	if len(report.Findings) != 0 {
		for _, finding := range report.Findings {
			if finding.Severity == "error" {
				report.Healthy = false
				return report, nil
			}
		}
	}
	return report, nil
}

func (p linuxProvider) doctorScheme(ctx context.Context, scheme string) (DoctorReport, error) {
	report := DoctorReport{
		Platform: "linux",
		Scope:    fmt.Sprintf("scheme:%s", scheme),
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

	key := "x-scheme-handler/" + scheme
	app, err := p.Get(ctx, Target{Kind: KindScheme, Value: scheme})
	if err != nil {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L32",
			Severity:    "error",
			Summary:     fmt.Sprintf("Unable to query default handler for %s", scheme),
			Details:     err.Error(),
			Remediation: "Ensure xdg-mime is installed and scheme database is valid.",
		})
		return report, nil
	}

	app = strings.TrimSpace(app)
	if app == "" || strings.EqualFold(app, "None") {
		report.Healthy = false
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L32",
			Severity:    "error",
			Summary:     fmt.Sprintf("No default handler set for %s", scheme),
			Remediation: fmt.Sprintf("Run dfx set --scheme %s --app <desktop-id> to set a default handler.", scheme),
		})
	} else {
		if !desktopExists(p, app) {
			report.Healthy = false
			report.Findings = append(report.Findings, DoctorFinding{
				ID:          "L32",
				Severity:    "error",
				Summary:     fmt.Sprintf("Default handler for %s points to missing desktop file", scheme),
				Details:     app,
				Remediation: "Set the default to an installed desktop id or reinstall the missing app.",
			})
		}

		meta, ok := p.desktopMetadata(app)
		if ok {
			if !meta.hasURLPlaceholder() {
				report.Findings = append(report.Findings, DoctorFinding{
					ID:          "L32",
					Severity:    "warning",
					Summary:     fmt.Sprintf("Desktop entry for %s handler lacks URL placeholder", scheme),
					Details:     app,
					Remediation: "Ensure Exec includes %u or %U for URL handler compatibility.",
				})
			}
		}

		report.Findings = append(report.Findings, p.checkPrecedenceConflictsForKey(key)...)
		report.Findings = append(report.Findings, p.checkToolkitDisagreementForKey(ctx, key)...)

		if scheme == "http" || scheme == "https" {
			report.Findings = append(report.Findings, p.checkPortalMismatchForKey(ctx, key)...)
		}
	}

	if len(report.Findings) != 0 {
		for _, finding := range report.Findings {
			if finding.Severity == "error" {
				report.Healthy = false
				return report, nil
			}
		}
	}
	return report, nil
}

func (p linuxProvider) doctorAll(ctx context.Context) (DoctorReport, error) {
	report := DoctorReport{
		Platform: "linux",
		Scope:    "all",
		Healthy:  true,
	}

	browserReport, err := p.doctorBrowser(ctx)
	if err != nil {
		return report, err
	}
	if !browserReport.Healthy {
		report.Healthy = false
	}
	report.Findings = append(report.Findings, browserReport.Findings...)

	const maxAssociations = 50
	count := 0
	capped := false

	home, err := p.userHomeDirOrDefault()
	if err == nil {
		xdgConfigHome := p.getenvOrDefault("XDG_CONFIG_HOME")
		if xdgConfigHome == "" {
			xdgConfigHome = filepath.Join(home, ".config")
		}
		userMIMEApps := filepath.Join(xdgConfigHome, "mimeapps.list")
		content, err := p.readFileOrDefault(userMIMEApps)
		if err == nil {
			schemes, mimes := parseMIMEAppsSections(string(content))
			for _, scheme := range schemes {
				if count >= maxAssociations {
					capped = true
					break
				}
				subReport, err := p.doctorScheme(ctx, scheme)
				if err != nil {
					continue
				}
				if !subReport.Healthy {
					report.Healthy = false
				}
				report.Findings = append(report.Findings, subReport.Findings...)
				count++
			}
			for _, mime := range mimes {
				if count >= maxAssociations {
					capped = true
					break
				}
				subReport, err := p.doctorMIME(ctx, mime)
				if err != nil {
					continue
				}
				if !subReport.Healthy {
					report.Healthy = false
				}
				report.Findings = append(report.Findings, subReport.Findings...)
				count++
			}
		}
	}

	if capped {
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          "L33",
			Severity:    "warning",
			Summary:     "Doctor --all capped associations at 50",
			Details:     "Some associations were not checked to avoid spam.",
			Remediation: "Run doctor with --mime or --scheme for specific associations.",
		})
	}

	return report, nil
}

func (p linuxProvider) doctorFixMIME(ctx context.Context, mimeType string, dryRun bool) (DoctorFixResult, error) {
	app, err := p.Get(ctx, Target{Kind: KindMIME, Value: mimeType})
	if err != nil {
		return DoctorFixResult{}, err
	}
	app = strings.TrimSpace(app)
	if app != "" && app != "None" && desktopExists(p, app) {
		return DoctorFixResult{Changed: false}, nil
	}

	for _, path := range p.mimeappsLookupPaths() {
		content, err := p.readFileOrDefault(path)
		if err != nil {
			continue
		}
		if candidate, ok := parseDefaultFromMIMEApps(string(content), mimeType); ok && candidate != "" {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" && candidate != "None" && candidate != app && desktopExists(p, candidate) {
				result, err := p.Set(ctx, Association{Kind: KindMIME, Value: mimeType, App: candidate}, SetOptions{DryRun: dryRun})
				return DoctorFixResult{Changed: result.Changed, Operations: result.Operations}, err
			}
		}
	}

	return DoctorFixResult{}, fmt.Errorf("no installed handler found for MIME type %s", mimeType)
}

func (p linuxProvider) doctorFixScheme(ctx context.Context, scheme string, dryRun bool) (DoctorFixResult, error) {
	key := "x-scheme-handler/" + scheme
	app, err := p.Get(ctx, Target{Kind: KindScheme, Value: scheme})
	if err != nil {
		return DoctorFixResult{}, err
	}
	app = strings.TrimSpace(app)
	if app != "" && app != "None" && desktopExists(p, app) {
		return DoctorFixResult{Changed: false}, nil
	}

	for _, path := range p.mimeappsLookupPaths() {
		content, err := p.readFileOrDefault(path)
		if err != nil {
			continue
		}
		if candidate, ok := parseDefaultFromMIMEApps(string(content), key); ok && candidate != "" {
			candidate = strings.TrimSpace(candidate)
			if candidate != "" && candidate != "None" && candidate != app && desktopExists(p, candidate) {
				result, err := p.Set(ctx, Association{Kind: KindScheme, Value: scheme, App: candidate}, SetOptions{DryRun: dryRun})
				return DoctorFixResult{Changed: result.Changed, Operations: result.Operations}, err
			}
		}
	}

	return DoctorFixResult{}, fmt.Errorf("no installed handler found for scheme %s", scheme)
}

func (p linuxProvider) doctorFixAll(ctx context.Context, dryRun bool) (DoctorFixResult, error) {
	result := DoctorFixResult{Changed: false}

	browserResult, err := p.doctorFixBrowser(ctx, dryRun)
	if err != nil {
		return result, err
	}
	result.Changed = result.Changed || browserResult.Changed
	result.Operations = append(result.Operations, browserResult.Operations...)

	home, err := p.userHomeDirOrDefault()
	if err != nil {
		return result, nil
	}

	xdgConfigHome := p.getenvOrDefault("XDG_CONFIG_HOME")
	if xdgConfigHome == "" {
		xdgConfigHome = filepath.Join(home, ".config")
	}
	userMIMEApps := filepath.Join(xdgConfigHome, "mimeapps.list")
	content, err := p.readFileOrDefault(userMIMEApps)
	if err != nil {
		return result, nil
	}

	schemes, mimes := parseMIMEAppsSections(string(content))
	seen := make(map[string]struct{})

	for _, scheme := range schemes {
		if _, ok := seen["scheme:"+scheme]; ok {
			continue
		}
		seen["scheme:"+scheme] = struct{}{}
		subResult, err := p.doctorFixScheme(ctx, scheme, dryRun)
		if err != nil {
			continue
		}
		result.Changed = result.Changed || subResult.Changed
		result.Operations = append(result.Operations, subResult.Operations...)
	}

	for _, mime := range mimes {
		if _, ok := seen["mime:"+mime]; ok {
			continue
		}
		seen["mime:"+mime] = struct{}{}
		subResult, err := p.doctorFixMIME(ctx, mime, dryRun)
		if err != nil {
			continue
		}
		result.Changed = result.Changed || subResult.Changed
		result.Operations = append(result.Operations, subResult.Operations...)
	}

	return result, nil
}

func (p linuxProvider) checkPrecedenceConflictsForKey(key string) []DoctorFinding {
	seen := map[string]struct{}{}
	for _, path := range p.mimeappsLookupPaths() {
		content, err := p.readFileOrDefault(path)
		if err != nil {
			continue
		}
		if app, ok := parseDefaultFromMIMEApps(string(content), key); ok && app != "" {
			seen[app] = struct{}{}
		}
	}
	if len(seen) > 1 {
		return []DoctorFinding{{
			ID:          "L04",
			Severity:    "warning",
			Summary:     "Conflicting defaults found across mimeapps precedence layers",
			Details:     fmt.Sprintf("%s has %d competing defaults", key, len(seen)),
			Remediation: "Consolidate defaults in highest-precedence user mimeapps.list.",
		}}
	}
	return nil
}

func (p linuxProvider) checkToolkitDisagreementForKey(ctx context.Context, key string) []DoctorFinding {
	if !hasCommand(p.runner, "gio") {
		return nil
	}
	target := Target{Kind: KindMIME, Value: key}
	if strings.HasPrefix(key, "x-scheme-handler/") {
		target = Target{Kind: KindScheme, Value: strings.TrimPrefix(key, "x-scheme-handler/")}
	}
	xdgApp, err := p.Get(ctx, target)
	if err != nil {
		return nil
	}
	xdgApp = strings.TrimSpace(xdgApp)
	if xdgApp == "" || strings.EqualFold(xdgApp, "None") {
		return nil
	}
	gioApp, err := p.gioDefaultForAssociation(ctx, key)
	if err != nil {
		return nil
	}
	gioApp = strings.TrimSpace(gioApp)
	if gioApp == "" || strings.EqualFold(gioApp, "None") {
		return nil
	}
	if xdgApp != gioApp {
		issueID := "L19"
		if strings.HasPrefix(key, "x-scheme-handler/") {
			issueID = "L02"
		}
		return []DoctorFinding{{
			ID:          issueID,
			Severity:    "warning",
			Summary:     "xdg-mime and GIO report different defaults",
			Details:     fmt.Sprintf("%s: xdg-mime=%q gio=%q", key, xdgApp, gioApp),
			Remediation: "Use desktop-specific tools to align xdg and GIO defaults.",
		}}
	}
	return nil
}

func (p linuxProvider) checkPortalMismatchForKey(ctx context.Context, key string) []DoctorFinding {
	if !hasCommand(p.runner, "flatpak") || !hasCommand(p.runner, "flatpak-spawn") {
		return nil
	}
	host, err := p.runner.Run(ctx, "flatpak-spawn", "--host", "xdg-mime", "query", "default", key)
	if err != nil {
		return nil
	}
	local, err := p.runner.Run(ctx, "xdg-mime", "query", "default", key)
	if err != nil {
		return nil
	}
	host = strings.TrimSpace(host)
	local = strings.TrimSpace(local)
	if host == "" || local == "" {
		return nil
	}
	if host != local {
		return []DoctorFinding{{
			ID:          "L07",
			Severity:    "warning",
			Summary:     "Flatpak portal and host defaults are misaligned",
			Details:     fmt.Sprintf("%s: host=%q local=%q", key, host, local),
			Remediation: "Align host and Flatpak-context registration for the same identifiers.",
		}}
	}
	return nil
}

func parseMIMEAppsSections(content string) (schemes []string, mimes []string) {
	inDefaults := false
	seen := make(map[string]struct{})
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
		left, _, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(left)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if strings.HasPrefix(key, "x-scheme-handler/") {
			scheme := strings.TrimPrefix(key, "x-scheme-handler/")
			if scheme != "" {
				schemes = append(schemes, scheme)
			}
		} else if strings.Contains(key, "/") {
			mimes = append(mimes, key)
		}
	}
	return schemes, mimes
}
