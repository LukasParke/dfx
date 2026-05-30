//go:build darwin

package defaults

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type darwinProvider struct {
	runner commandRunner
}

type darwinAppManifestRequirement struct {
	schemes map[string]struct{}
	mimes   map[string]struct{}
}

func newDarwinProvider() Provider {
	return darwinProvider{runner: execRunner{}}
}

func (p darwinProvider) Inspect(context.Context) InspectReport {
	canRead := p.canReadLaunchServices()
	report := InspectReport{
		Platform: "darwin",
		Provider: "launchservices",
		CanRead:  canRead,
		CanWrite: false,
		Capabilities: Capabilities{
			CanReadCurrent:        canRead,
			CanWriteUserDefault:   false,
			CanWriteSystemDefault: false,
			PolicyRestricted:      false,
			SupportsBrowser:       true,
			SupportsScheme:        true,
			SupportsMIME:          canRead,
			SupportsContentType:   true,
		},
		Notes: []string{
			"LaunchServices values are read from the user cache in com.apple.launchservices.secure.plist",
			"see docs/wiki/macos-default-apps.md for handler model, constraints, and caveats",
		},
	}

	if canRead {
		report.Notes = append(report.Notes, "defaults read is cache-backed; run registration paths or cache reset flows after fresh installs")
	} else {
		report.Notes = append(report.Notes, "install macOS command line tools (`plutil`) and ensure LaunchServices cache file exists")
	}
	if p.dutiAvailable() {
		report.Provider = "duti"
		report.Notes = append(report.Notes, "duti detected; dfx can emit dry-run LaunchServices guidance, but native writes remain disabled until safe workflows are implemented")
	} else {
		report.Notes = append(report.Notes, "install duti (`brew install duti`) for CLI-oriented write workflows")
	}
	if !p.runnerOrDefaultHas("osascript") {
		report.Notes = append(report.Notes, "osascript not found; bundle-id validation checks are limited")
	}
	return report
}

func (p darwinProvider) Get(ctx context.Context, target Target) (string, error) {
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return "", err
	}
	if !p.canReadLaunchServices() {
		return "", p.darwinUnsupportedOperation("get")
	}

	query := target
	if target.Kind == KindBrowser {
		query = Target{Kind: KindScheme, Value: "http"}
	}
	return p.getFromLaunchServices(ctx, query)
}

func (p darwinProvider) Doctor(ctx context.Context, options DoctorOptions) (DoctorReport, error) {
	if !options.Browser {
		return DoctorReport{}, fmt.Errorf("doctor currently requires --browser")
	}
	return p.doctorForBrowserDefaults(ctx)
}

func (p darwinProvider) DoctorFix(ctx context.Context, options DoctorFixOptions) (DoctorFixResult, error) {
	if !options.Browser {
		return DoctorFixResult{}, fmt.Errorf("macOS doctor fix currently requires --browser")
	}
	operations := []string{
		"Open System Settings > Desktop & Dock and set the intended default web browser",
		"Verify http and https scheme handlers match the selected browser bundle identifier",
		"Verify text/html and application/xhtml+xml LaunchServices role handlers match the selected browser",
		"Re-run dfx doctor --browser after browser updates or LaunchServices cache rebuilds",
	}
	operations = appendFindingRemediationOperations(ctx, p, operations)
	if options.DryRun {
		return DoctorFixResult{Changed: false, Operations: operations}, nil
	}
	return DoctorFixResult{Operations: operations}, p.darwinUnsupportedOperation("doctor fix")
}

func (p darwinProvider) Set(_ context.Context, association Association, options SetOptions) (SetResult, error) {
	association = association.Normalized()
	if err := association.Validate(); err != nil {
		return SetResult{}, err
	}
	operations := p.darwinSetGuidanceOperations(association)
	if options.DryRun {
		return SetResult{Changed: false, Operations: operations}, nil
	}
	return SetResult{Operations: operations}, p.darwinUnsupportedOperation("set")
}

func (p darwinProvider) ResolveApp(ctx context.Context, query string, target Target) (AppResolution, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return AppResolution{}, fmt.Errorf("app is required")
	}
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return AppResolution{}, err
	}

	if strings.Contains(query, ".") {
		return AppResolution{App: query, Source: "bundle id"}, nil
	}

	if p.runnerOrDefaultHas("osascript") {
		for _, name := range darwinAppNameCandidates(query) {
			escaped := strings.ReplaceAll(name, `"`, `\"`)
			output, err := p.runnerOrDefault().Run(ctx, "osascript", "-e", `id of application "`+escaped+`"`)
			if err != nil {
				continue
			}
			bundleID := strings.TrimSpace(output)
			if bundleID != "" {
				return AppResolution{App: bundleID, Source: "macOS application name", Candidates: []string{name}}, nil
			}
		}
	}

	if bundleID := knownDarwinBundleID(query); bundleID != "" {
		return AppResolution{App: bundleID, Source: "known macOS browser alias", Candidates: darwinAppNameCandidates(query)}, nil
	}
	return AppResolution{}, fmt.Errorf("could not resolve app query %q to a macOS bundle identifier; use --app with an exact bundle id", query)
}

func (p darwinProvider) doctorForBrowserDefaults(ctx context.Context) (DoctorReport, error) {
	if !p.canReadLaunchServices() {
		return DoctorReport{}, p.darwinUnsupportedOperation("doctor")
	}

	handlers, handlersErr := p.loadLaunchServicesHandlers(ctx)
	report := DoctorReport{
		Platform: "darwin",
		Scope:    "browser",
		Healthy:  true,
		Notes: []string{
			"checks are read-only and validate cache state only; use doctor --browser --fix --dry-run for guided remediation because direct LaunchServices writes are disabled",
		},
	}

	addFinding := func(id, severity, summary, details, remediation string) {
		if !strings.EqualFold(severity, "info") && !strings.EqualFold(severity, "warning") {
			report.Healthy = false
		}
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          id,
			Severity:    severity,
			Summary:     summary,
			Details:     details,
			Remediation: remediation,
		})
	}
	if handlersErr != nil {
		addFinding("M23", "error", "LaunchServices cache is unreadable or malformed", handlersErr.Error(), "rebuild LaunchServices cache and rerun dfx")
		return report, nil
	}

	httpRoles, httpErr := p.targetRoleHandlersFromHandlers(Target{Kind: KindScheme, Value: "http"}, handlers)
	httpsRoles, httpsErr := p.targetRoleHandlersFromHandlers(Target{Kind: KindScheme, Value: "https"}, handlers)
	htmlRoles, htmlErr := p.targetRoleHandlersFromHandlers(Target{Kind: KindMIME, Value: "text/html"}, handlers)
	xhtmlRoles, xhtmlErr := p.targetRoleHandlersFromHandlers(Target{Kind: KindMIME, Value: "application/xhtml+xml"}, handlers)
	httpApp := p.selectRoleHandler(httpRoles)
	httpsApp := p.selectRoleHandler(httpsRoles)
	htmlApp := p.selectRoleHandler(htmlRoles)
	xhtmlApp := p.selectRoleHandler(xhtmlRoles)
	requirementsByApp := map[string]*darwinAppManifestRequirement{}
	addRequirement := func(app, scheme, mime string) {
		if app == "" {
			return
		}
		req, ok := requirementsByApp[app]
		if !ok {
			req = &darwinAppManifestRequirement{
				schemes: map[string]struct{}{},
				mimes:   map[string]struct{}{},
			}
			requirementsByApp[app] = req
		}
		if scheme != "" {
			req.schemes[strings.ToLower(strings.TrimSpace(scheme))] = struct{}{}
		}
		if mime != "" {
			req.mimes[strings.ToLower(strings.TrimSpace(mime))] = struct{}{}
		}
	}
	addRequirement(httpApp, "http", "")
	addRequirement(httpsApp, "https", "")
	addRequirement(htmlApp, "", "text/html")
	addRequirement(xhtmlApp, "", "application/xhtml+xml")

	if httpErr != nil {
		addFinding("M01", "error", "required HTTP scheme handler missing", httpErr.Error(), "reset HTTP handler in macOS settings or a native Launch Services flow")
	}
	if httpsErr != nil {
		addFinding("M01", "error", "required HTTPS scheme handler missing", httpsErr.Error(), "reset HTTPS handler in macOS settings or a native Launch Services flow")
	}
	if htmlErr != nil {
		addFinding("M01", "error", "required text/html content mapping missing", htmlErr.Error(), "validate Info.plist document-type declarations for the browser and re-register")
	}
	if xhtmlErr != nil {
		addFinding("M06", "warning", "application/xhtml+xml mapping not currently resolved", xhtmlErr.Error(), "review UTI inheritance and extension-to-UTI coverage for the selected browser")
	}

	if httpApp != "" && htmlApp != "" && !strings.EqualFold(httpApp, htmlApp) {
		addFinding("M01", "warning", "scheme and file defaults diverge", fmt.Sprintf(`http -> %q, text/html -> %q`, httpApp, htmlApp), "set both scheme and text/html handlers to the same application where possible")
	}
	if httpsApp != "" && htmlApp != "" && !strings.EqualFold(httpsApp, htmlApp) {
		addFinding("M01", "warning", "scheme and file defaults diverge", fmt.Sprintf(`https -> %q, text/html -> %q`, httpsApp, htmlApp), "align scheme and file handler assignments for URL and web content")
	}
	if issue := macContentTypeAliasDrift(handlers, []string{"text/html", "public.html"}); issue != "" {
		addFinding("M08", "warning", "extension-to-UTI handler drift for html-like content", issue, "verify public.html/text/html declarations and re-register handlers through the active browser installer")
	}
	if issue := macContentTypeAliasDrift(handlers, []string{"application/xhtml+xml", "public.xhtml", "public.xhtml+xml"}); issue != "" {
		addFinding("M08", "warning", "extension-to-UTI handler drift for xhtml-like content", issue, "verify xhtml/public.xhtml declarations and re-sync Launch Services registration for browser handlers")
	}
	if hasRoleMismatch(httpRoles) {
		addFinding("M07", "warning", "scheme role handlers differ", roleSummary(httpRoles), "verify role handler declarations in app LaunchServices metadata for scheme and content handling")
	}
	if hasRoleMismatch(httpsRoles) {
		addFinding("M07", "warning", "scheme role handlers differ", roleSummary(httpsRoles), "verify role handler declarations in app LaunchServices metadata for scheme and content handling")
	}
	if hasRoleMismatch(htmlRoles) {
		addFinding("M07", "warning", "content role handlers differ", roleSummary(htmlRoles), "verify role handler declarations in app LaunchServices metadata for scheme and content handling")
	}
	if hasRoleMismatch(xhtmlRoles) {
		addFinding("M07", "warning", "content role handlers differ", roleSummary(xhtmlRoles), "verify role handler declarations in app LaunchServices metadata for scheme and content handling")
	}
	if issue, err := p.getTargetRoleCollisionFromHandlers(Target{Kind: KindScheme, Value: "http"}, handlers); err == nil && issue != "" {
		addFinding("M24", "warning", "duplicate role handlers for http scheme", issue, "remove duplicate LaunchServices entries and ensure one authoritative web-scheme assignment path")
	}
	if issue, err := p.getTargetRoleCollisionFromHandlers(Target{Kind: KindScheme, Value: "https"}, handlers); err == nil && issue != "" {
		addFinding("M24", "warning", "duplicate role handlers for https scheme", issue, "remove duplicate LaunchServices entries and ensure one authoritative web-scheme assignment path")
	}
	if issue, err := p.getTargetRoleCollisionFromHandlers(Target{Kind: KindMIME, Value: "text/html"}, handlers); err == nil && issue != "" {
		addFinding("M24", "warning", "duplicate role handlers for text/html content", issue, "remove duplicate LaunchServices entries and ensure one authoritative content-type handler mapping")
	}
	if xhtmlApp != "" && httpsApp != "" && !strings.EqualFold(xhtmlApp, httpsApp) {
		addFinding("M06", "warning", "UTI inheritance mismatch risk", fmt.Sprintf(`application/xhtml+xml -> %q, https -> %q`, xhtmlApp, httpsApp), "re-check declared UTIs in the browser Info.plist for compatibility")
	}
	if issue := macosBrowserPromptPartialCoverageSignal(httpApp, httpsApp, htmlApp, xhtmlApp, htmlErr, xhtmlErr); issue != "" {
		addFinding("M13", "warning", "browser prompt appears to have applied only part of web defaults", issue, "set browser defaults through a flow that updates both URL schemes and web content UTIs, then re-run doctor")
	}
	canInspectBundles := p.runnerOrDefaultHas("osascript")
	if !canInspectBundles {
		addFinding("M19", "warning", "undocumented/undetected environment tooling limits manifest checks", "osascript is missing, so bundle ID validation and Info.plist inspection are unavailable", "install or run from macOS scripting environment to enable full manifest verification")
		report.Notes = append(report.Notes, "bundle-id existence checks are limited because osascript is not available")
	}

	channelSignals := map[string]map[string][]string{}
	recordChannelSignal := func(target string, app string) {
		family, channel := inferDarwinBrowserChannel(app)
		if family == "" {
			return
		}
		channels, ok := channelSignals[family]
		if !ok {
			channels = map[string][]string{}
			channelSignals[family] = channels
		}
		channels[channel] = append(channels[channel], target)
	}
	recordChannelSignal("http", httpApp)
	recordChannelSignal("https", httpsApp)
	recordChannelSignal("text/html", htmlApp)
	recordChannelSignal("application/xhtml+xml", xhtmlApp)
	for family, channels := range channelSignals {
		if len(channels) <= 1 {
			continue
		}
		parts := make([]string, 0, len(channels))
		for channel, targets := range channels {
			sort.Strings(targets)
			parts = append(parts, fmt.Sprintf("%s=%s", channel, strings.Join(targets, ", ")))
		}
		sort.Strings(parts)
		addFinding("M04", "warning", "multiple channel variants are active for one browser family", fmt.Sprintf("family=%q coverage=%s", family, strings.Join(parts, "; ")), "select a single macOS browser channel variant and clear stale default entries for competing variants")
	}
	launchServicesCachePath := p.launchServicesPlistPath()
	launchServicesCacheModTime, launchServicesCacheHasModTime := p.pathModTime(launchServicesCachePath)

	systemHandlers, err := p.loadLaunchServicesHandlersFromPath(ctx, p.launchServicesSystemPlistPath())
	if err == nil {
		systemTargets := []struct {
			name      string
			target    Target
			userValue string
		}{
			{"http", Target{Kind: KindScheme, Value: "http"}, httpApp},
			{"https", Target{Kind: KindScheme, Value: "https"}, httpsApp},
			{"text/html", Target{Kind: KindMIME, Value: "text/html"}, htmlApp},
			{"application/xhtml+xml", Target{Kind: KindMIME, Value: "application/xhtml+xml"}, xhtmlApp},
		}
		for _, item := range systemTargets {
			systemApps, err := p.targetRoleHandlersFromHandlers(item.target, systemHandlers)
			if err != nil || len(systemApps) == 0 {
				continue
			}
			systemApp := p.selectRoleHandler(systemApps)
			if systemApp == "" || item.userValue == "" {
				continue
			}
			if !strings.EqualFold(systemApp, item.userValue) {
				addFinding("M14", "warning", "per-user/system default handler domains differ", fmt.Sprintf("%s: user=%q, system=%q", item.name, item.userValue, systemApp), "align user and system Launch Services registrations by rebuilding defaults for the active browser family")
			}
		}
	}

	if callbackScheme := normalizeCallbackScheme(os.Getenv("DFX_CALLBACK_SCHEME")); callbackScheme != "" {
		callbackRoles, err := p.targetRoleHandlersFromHandlers(Target{Kind: KindScheme, Value: callbackScheme}, handlers)
		if err != nil {
			addFinding("M30", "warning", "configured callback scheme is unset", callbackScheme, "set DFX_CALLBACK_SCHEME to a URI scheme mapped to your native callback handler")
		} else if callbackApp := p.selectRoleHandler(callbackRoles); callbackApp != "" {
			if (httpApp != "" && strings.EqualFold(callbackApp, httpApp)) || (httpsApp != "" && strings.EqualFold(callbackApp, httpsApp)) {
				addFinding("M30", "warning", "callback scheme maps to browser default", fmt.Sprintf("%s -> %q", callbackScheme, callbackApp), "point the callback scheme to native app handler to avoid browser redirection loop")
			}
		}
	}

	if mdmSignals := p.macosMDMLaunchServicesSignals(ctx); len(mdmSignals) > 0 {
		addFinding("M12", "warning", "MDM-managed LaunchServices policy may constrain browser defaults", strings.Join(mdmSignals, "; "), "review managed configuration policy for allowed default-app changes and expected routing")
	}
	if signals := p.macosEndpointSecuritySignals(ctx); len(signals) > 0 {
		addFinding("M27", "warning", "endpoint security policy may intercept URL/file open paths", strings.Join(signals, "; "), "identify interception points (browser launch proxies, network filters, endpoint policy) and validate allow-list behavior for browser defaults")
	}
	if signal := p.macosAPIDriftSignal(ctx); signal != "" {
		addFinding("M20", "info", "macOS LaunchServices behavior may vary across release/API levels", signal, "compare doctor results against native macOS Default Browser settings after OS upgrades or LaunchServices cache format changes")
	}

	if signals := p.macosEnvironmentSignals(); len(signals) > 0 {
		addFinding("M21", "warning", "doctor inspection appears to be running in non-Finder context", strings.Join(signals, "; "), "perform end-to-end default validation from the same runtime context where users invoke links")
	}
	if signals := p.macosSessionSignals(); len(signals) > 0 {
		addFinding("M22", "warning", "headless/remote session context may differ from interactive user defaults", strings.Join(signals, "; "), "run this diagnostic inside the target user session to confirm cache ownership")
	}

	webTypeSignatures := map[string]string{}
	activeWebDefaultsDiverged := len(uniqueNonEmptyValues([]string{httpApp, httpsApp, htmlApp, xhtmlApp})) > 1 || httpErr != nil || httpsErr != nil || htmlErr != nil || xhtmlErr != nil
	updateReclaimSignals := []string{}
	for app, req := range requirementsByApp {
		if app == "" || req == nil {
			continue
		}
		if !canInspectBundles {
			continue
		}
		if !p.bundleIDLooksInstalled(ctx, app) {
			addFinding("M02", "warning", "bundle ID may not resolve to an installed app", fmt.Sprintf("%s is not resolvable through osascript", app), "correct stale/default bundle identifiers and re-run dfx")
			addFinding("M26", "warning", "browser default is set to an uninstalled or stale bundle ID", fmt.Sprintf("%s is not resolvable through osascript", app), "clear stale defaults and re-register a currently installed browser")
			addFinding("M09", "warning", "stale LaunchServices reference remains after uninstall", fmt.Sprintf("%s is no longer resolvable", app), "clear stale launch service entries and reassign defaults for this target set")
			continue
		}
		bundlePath, err := p.bundlePathForID(ctx, app)
		if err != nil {
			addFinding("M17", "warning", "unable to resolve selected browser bundle path", fmt.Sprintf("%s path resolution failed: %v", app, err), "correct browser registration and rerun dfx")
			continue
		}
		if securitySignal := p.macosSandboxPathSignal(ctx, bundlePath); securitySignal != "" {
			addFinding("M11", "warning", "app sandbox constraints can alter file-path handling", securitySignal, "verify sandboxed app file-scope settings for URL/file handoff flows and avoid restricted working directories when possible")
		}
		if launchServicesCacheHasModTime {
			if freshnessSignal := p.macosLaunchServicesFreshnessSignal(bundlePath, launchServicesCacheModTime); freshnessSignal != "" {
				addFinding("M10", "warning", "browser install/update registration may lag in LaunchServices cache", freshnessSignal, "re-run LaunchServices registration flows after browser update or reinstall and then retry")
			}
		}
		if providerPathSignal := p.macosProviderPathSignal(bundlePath); providerPathSignal != "" {
			addFinding("M15", "warning", "selected browser path may use provider-synced filesystem location", providerPathSignal, "prefer a local, non-synced install path for browser defaults to minimize handoff variation")
		}
		if archSignal := p.macosBrowserArchitectureSignal(ctx, bundlePath); archSignal != "" {
			addFinding("M16", "warning", "browser binary architecture may differ from host expectations", archSignal, "install a browser binary matching host architecture or ensure compatibility path works for your deployment")
		}
		plist, err := p.readAppInfoPlistFromPath(ctx, app, bundlePath)
		if err != nil {
			addFinding("M17", "warning", "unable to read app manifest claims", fmt.Sprintf("%s manifest inspection failed: %v", app, err), "validate app registration and re-run dfx")
			continue
		}
		if activeWebDefaultsDiverged {
			updateReclaimSignals = append(updateReclaimSignals, p.macosUpdateReclaimSignals(app, bundlePath, plist)...)
		}
		if signals := p.macosBrowserProfileSignals(app); len(signals) > 0 {
			addFinding("M25", "warning", "browser profile state may affect deep-link result", strings.Join(signals, "; "), "validate default-browser deep links with the target profile and reset browser profile routing if OAuth/callback behavior differs")
		}
		if securitySignal, signatureSignal := p.macosSignatureSignals(ctx, bundlePath); securitySignal != "" || signatureSignal != "" {
			if securitySignal != "" {
				addFinding("M28", "warning", "notarization/signing status may affect launch path", securitySignal, "re-install or repair the app signature/notarization path through the app vendor")
			}
			if signatureSignal != "" {
				addFinding("M28", "warning", "code-signature verification failed for selected browser", signatureSignal, "reinstall the browser from a trusted source so secure verification can succeed")
			}
		}
		malformedURLTypes, malformedDocumentTypes := darwinMalformedManifestDeclarationIssues(plist)
		if len(malformedURLTypes) != 0 {
			addFinding("M17", "warning", "app manifest has malformed URL-type declarations", fmt.Sprintf("%s: %s", app, strings.Join(malformedURLTypes, "; ")), "repair CFBundleURLTypes so each entry has valid CFBundleURLSchemes values, then re-register the app")
		}
		if len(malformedDocumentTypes) != 0 {
			addFinding("M18", "warning", "app manifest has malformed document-type declarations", fmt.Sprintf("%s: %s", app, strings.Join(malformedDocumentTypes, "; ")), "repair CFBundleDocumentTypes so each entry declares LSItemContentTypes or valid file extensions, then re-register the app")
		}
		missingSchemes, missingMimes := p.missingBrowserManifestClaimsFromInfo(plist, req)
		if signature := darwinWebContentTypeDeclarationSignature(darwinDeclaredContentTypesFromInfo(plist)); signature != "" {
			webTypeSignatures[app] = signature
		}
		if len(missingSchemes) != 0 {
			addFinding("M03", "warning", "default handler may not declare callback-relevant schemes", fmt.Sprintf("%s missing URL schemes: %s", app, strings.Join(missingSchemes, ", ")), "verify CFBundleURLTypes and re-register app for this target")
			addFinding("M17", "warning", "app manifest lacks matching URL scheme declarations", fmt.Sprintf("%s missing URL scheme coverage for %s", app, strings.Join(missingSchemes, ", ")), "verify CFBundleURLTypes for URLScheme declarations in Info.plist")
		}
		if len(missingMimes) != 0 {
			addFinding("M18", "warning", "app manifest lacks matching document-type declarations", fmt.Sprintf("%s missing document types: %s", app, strings.Join(missingMimes, ", ")), "verify CFBundleDocumentTypes and re-register browser after updates")
		}
	}
	if activeWebDefaultsDiverged {
		if updateReclaimSignals = uniqueNonEmptyValues(updateReclaimSignals); len(updateReclaimSignals) > 0 {
			sort.Strings(updateReclaimSignals)
			addFinding("M05", "warning", "browser update machinery may have reclaimed a subset of defaults", strings.Join(updateReclaimSignals, "; "), "after browser updates, reapply the intended browser default across http, https, text/html, and application/xhtml+xml together")
		}
	}
	if conflict := p.macosUTIDeclarationConflict(webTypeSignatures); conflict != "" {
		addFinding("M29", "warning", "conflicting UTI declarations across selected web handlers", conflict, "standardize declaration expectations for text/html and application/xhtml+xml among active browser handlers")
	}

	return report, nil
}

func (p darwinProvider) getFromLaunchServices(ctx context.Context, target Target) (string, error) {
	roleHandlers, err := p.getTargetRoleHandlers(ctx, target)
	if err != nil {
		return "", err
	}
	if app := p.selectRoleHandler(roleHandlers); app != "" {
		return app, nil
	}
	return "", fmt.Errorf("no handler found for %s %q", target.Kind, target.Value)
}

func (p darwinProvider) missingBrowserManifestClaims(ctx context.Context, app string, req *darwinAppManifestRequirement) ([]string, []string, error) {
	bundlePath, err := p.bundlePathForID(ctx, app)
	if err != nil {
		return nil, nil, err
	}
	return p.missingBrowserManifestClaimsFromPath(ctx, app, bundlePath, req)
}

func (p darwinProvider) missingBrowserManifestClaimsFromPath(ctx context.Context, app string, bundlePath string, req *darwinAppManifestRequirement) ([]string, []string, error) {
	plist, err := p.readAppInfoPlistFromPath(ctx, app, bundlePath)
	if err != nil {
		return nil, nil, err
	}
	missingSchemes, missingMimes := p.missingBrowserManifestClaimsFromInfo(plist, req)
	return missingSchemes, missingMimes, nil
}

func (p darwinProvider) missingBrowserManifestClaimsFromInfo(plist map[string]any, req *darwinAppManifestRequirement) ([]string, []string) {
	declaredSchemes := darwinDeclaredSchemesFromInfo(plist)
	declaredMimes := darwinDeclaredContentTypesFromInfo(plist)

	missingSchemes := []string{}
	for scheme := range req.schemes {
		scheme = strings.TrimSpace(strings.ToLower(scheme))
		if scheme == "" {
			continue
		}
		if _, ok := declaredSchemes[scheme]; ok {
			continue
		}
		missingSchemes = append(missingSchemes, scheme)
	}

	missingMimes := []string{}
	for mime := range req.mimes {
		mime = strings.ToLower(strings.TrimSpace(mime))
		if mime == "" {
			continue
		}
		requiredAliases := normalizeMacContentType(mime)
		if len(requiredAliases) == 0 {
			requiredAliases = []string{mime}
		}
		found := false
		for _, alias := range requiredAliases {
			if _, ok := declaredMimes[strings.ToLower(alias)]; ok {
				found = true
				break
			}
		}
		if !found {
			missingMimes = append(missingMimes, mime)
		}
	}

	sort.Strings(missingSchemes)
	sort.Strings(missingMimes)
	return missingSchemes, missingMimes
}

func (p darwinProvider) webContentTypeDeclarationSignatureFromPath(ctx context.Context, app string, bundlePath string) string {
	plist, err := p.readAppInfoPlistFromPath(ctx, app, bundlePath)
	if err != nil {
		return ""
	}
	return darwinWebContentTypeDeclarationSignature(darwinDeclaredContentTypesFromInfo(plist))
}

func darwinWebContentTypeDeclarationSignature(mimes map[string]struct{}) string {
	parts := []string{}
	if _, ok := mimes["text/html"]; ok {
		parts = append(parts, "text/html")
	} else if _, ok := mimes["public.html"]; ok {
		parts = append(parts, "text/html")
	}
	if mtypes := []string{"application/xhtml+xml", "public.xhtml", "public.xhtml+xml"}; mtypes != nil {
		for _, mtype := range mtypes {
			if _, ok := mimes[mtype]; ok {
				parts = append(parts, "application/xhtml+xml")
				break
			}
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

func (p darwinProvider) macosUTIDeclarationConflict(signaturesByApp map[string]string) string {
	if len(signaturesByApp) <= 1 {
		return ""
	}
	unique := map[string]struct{}{}
	for _, signature := range signaturesByApp {
		unique[signature] = struct{}{}
	}
	if len(unique) <= 1 {
		return ""
	}
	items := make([]string, 0, len(signaturesByApp))
	for app, signature := range signaturesByApp {
		items = append(items, fmt.Sprintf("%s=%s", app, signature))
	}
	sort.Strings(items)
	return fmt.Sprintf("active web handler declaration signatures differ: %s", strings.Join(items, "; "))
}

func (p darwinProvider) readAppInfoPlist(ctx context.Context, app string) (map[string]any, error) {
	plistPath, err := p.bundleInfoPlistPath(ctx, app)
	if err != nil {
		return nil, err
	}
	return p.readAppInfoPlistFromPath(ctx, app, filepath.Dir(filepath.Dir(plistPath)))
}

func (p darwinProvider) readAppInfoPlistFromPath(ctx context.Context, app string, bundlePath string) (map[string]any, error) {
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	output, err := p.runnerOrDefault().Run(ctx, "plutil", "-convert", "json", "-o", "-", plistPath)
	if err != nil {
		return nil, fmt.Errorf("%s: read %s: %w", app, plistPath, err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return nil, fmt.Errorf("%s: parse plist json: %w", app, err)
	}
	return payload, nil
}

func (p darwinProvider) bundleInfoPlistPath(ctx context.Context, app string) (string, error) {
	bundlePath, err := p.bundlePathForID(ctx, app)
	if err != nil {
		return "", err
	}
	return filepath.Join(bundlePath, "Contents", "Info.plist"), nil
}

func (p darwinProvider) bundlePathForID(ctx context.Context, app string) (string, error) {
	escaped := strings.ReplaceAll(app, `"`, `\"`)
	output, err := p.runnerOrDefault().Run(ctx, "osascript", "-e", `POSIX path of application id "`+escaped+`"`)
	if err != nil {
		return "", err
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return "", fmt.Errorf("empty application path for %q", app)
	}
	return output, nil
}

func (p darwinProvider) getTargetRoleHandlers(ctx context.Context, target Target) (map[string]string, error) {
	handlers, err := p.loadLaunchServicesHandlers(ctx)
	if err != nil {
		return nil, err
	}
	return p.targetRoleHandlersFromHandlers(target, handlers)
}

func (p darwinProvider) targetRoleHandlersFromHandlers(target Target, handlers []map[string]any) (map[string]string, error) {
	for _, handler := range handlers {
		if p.matchesTarget(target, handler) {
			if roleApps := p.roleValuesFromMap(handler); len(roleApps) != 0 {
				return roleApps, nil
			}
		}
	}
	return nil, fmt.Errorf("no handler found for %s %q", target.Kind, target.Value)
}

func darwinDeclaredSchemesFromInfo(plist map[string]any) map[string]struct{} {
	declared := map[string]struct{}{}
	raw, ok := plist["CFBundleURLTypes"]
	if !ok {
		return declared
	}
	for _, itemAny := range plistValueToSlice(raw) {
		item, ok := itemAny.(map[string]any)
		if !ok {
			continue
		}
		for _, scheme := range plistValueToStringSlice(item["CFBundleURLSchemes"]) {
			scheme = strings.TrimSpace(strings.ToLower(scheme))
			if scheme == "" {
				continue
			}
			declared[scheme] = struct{}{}
		}
	}
	return declared
}

func darwinDeclaredContentTypesFromInfo(plist map[string]any) map[string]struct{} {
	declared := map[string]struct{}{}
	raw, ok := plist["CFBundleDocumentTypes"]
	if !ok {
		return declared
	}
	for _, itemAny := range plistValueToSlice(raw) {
		item, ok := itemAny.(map[string]any)
		if !ok {
			continue
		}
		for _, contentType := range plistValueToStringSlice(item["LSItemContentTypes"]) {
			contentType = strings.TrimSpace(strings.ToLower(contentType))
			if contentType != "" {
				declared[contentType] = struct{}{}
			}
		}
		for _, ext := range plistValueToStringSlice(item["CFBundleTypeExtensions"]) {
			ext = strings.TrimSpace(strings.ToLower(ext))
			switch strings.TrimPrefix(ext, ".") {
			case "htm", "html":
				declared["text/html"] = struct{}{}
				declared["public.html"] = struct{}{}
			case "xhtml", "xht":
				declared["application/xhtml+xml"] = struct{}{}
				declared["public.xhtml"] = struct{}{}
				declared["public.xhtml+xml"] = struct{}{}
			}
		}
	}
	return declared
}

func darwinMalformedManifestDeclarationIssues(plist map[string]any) (urlIssues []string, documentIssues []string) {
	if raw, ok := plist["CFBundleURLTypes"]; ok {
		if _, ok := raw.([]any); !ok {
			urlIssues = append(urlIssues, "CFBundleURLTypes is not an array")
		}
		for index, itemAny := range plistValueToSlice(raw) {
			item, ok := itemAny.(map[string]any)
			if !ok {
				urlIssues = append(urlIssues, fmt.Sprintf("CFBundleURLTypes[%d] is not a dictionary", index))
				continue
			}
			values := plistValueToStringSlice(item["CFBundleURLSchemes"])
			if len(values) == 0 {
				urlIssues = append(urlIssues, fmt.Sprintf("CFBundleURLTypes[%d] has no CFBundleURLSchemes", index))
				continue
			}
			for _, scheme := range values {
				if !validURLScheme(strings.ToLower(strings.TrimSpace(scheme))) {
					urlIssues = append(urlIssues, fmt.Sprintf("CFBundleURLTypes[%d] has invalid scheme %q", index, scheme))
				}
			}
		}
	}

	if raw, ok := plist["CFBundleDocumentTypes"]; ok {
		if _, ok := raw.([]any); !ok {
			documentIssues = append(documentIssues, "CFBundleDocumentTypes is not an array")
		}
		for index, itemAny := range plistValueToSlice(raw) {
			item, ok := itemAny.(map[string]any)
			if !ok {
				documentIssues = append(documentIssues, fmt.Sprintf("CFBundleDocumentTypes[%d] is not a dictionary", index))
				continue
			}
			contentTypes := plistValueToStringSlice(item["LSItemContentTypes"])
			extensions := plistValueToStringSlice(item["CFBundleTypeExtensions"])
			if len(contentTypes) == 0 && len(extensions) == 0 {
				documentIssues = append(documentIssues, fmt.Sprintf("CFBundleDocumentTypes[%d] has no LSItemContentTypes or CFBundleTypeExtensions", index))
				continue
			}
			for _, contentType := range contentTypes {
				if !darwinValidContentTypeDeclaration(contentType) {
					documentIssues = append(documentIssues, fmt.Sprintf("CFBundleDocumentTypes[%d] has invalid content type %q", index, contentType))
				}
			}
			for _, extension := range extensions {
				if !darwinValidFileExtensionDeclaration(extension) {
					documentIssues = append(documentIssues, fmt.Sprintf("CFBundleDocumentTypes[%d] has invalid file extension %q", index, extension))
				}
			}
		}
	}

	return urlIssues, documentIssues
}

func darwinValidContentTypeDeclaration(value string) bool {
	value = strings.TrimSpace(value)
	if validMIMEType(value) {
		return true
	}
	if value == "" || strings.ContainsAny(value, " /:") {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r >= 'a' && r <= 'z' {
				continue
			}
			if r >= 'A' && r <= 'Z' {
				continue
			}
			if r >= '0' && r <= '9' {
				continue
			}
			if r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

func darwinValidFileExtensionDeclaration(value string) bool {
	value = strings.TrimPrefix(strings.TrimSpace(value), ".")
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func plistValueToSlice(value any) []any {
	if value == nil {
		return nil
	}
	if items, ok := value.([]any); ok {
		return items
	}
	return []any{value}
}

func plistValueToStringSlice(value any) []string {
	var values []string
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			s := strings.TrimSpace(stringValue(item))
			if s == "" {
				continue
			}
			values = append(values, s)
		}
	case []string:
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			values = append(values, item)
		}
	case string:
		if typed = strings.TrimSpace(typed); typed != "" {
			values = append(values, typed)
		}
	}
	return values
}

func (p darwinProvider) matchesTarget(target Target, handler map[string]any) bool {
	switch target.Kind {
	case KindScheme:
		return strings.EqualFold(stringValue(handler["LSHandlerURLScheme"]), target.Value)
	case KindMIME, KindBrowser:
		actual := stringValue(handler["LSHandlerContentType"])
		for _, expected := range normalizeMacContentType(target.Value) {
			if strings.EqualFold(actual, expected) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (p darwinProvider) roleHandler(handler map[string]any) string {
	return p.selectRoleHandler(p.roleValuesFromMap(handler))
}

func (p darwinProvider) roleValuesFromMap(handler map[string]any) map[string]string {
	roleApps := map[string]string{}
	for _, role := range []string{
		"LSHandlerRoleAll",
		"LSHandlerRoleViewer",
		"LSHandlerRoleEditor",
		"LSHandlerRoleShell",
	} {
		if app := strings.TrimSpace(stringValue(handler[role])); app != "" {
			roleApps[role] = app
		}
	}
	return roleApps
}

func (p darwinProvider) selectRoleHandler(roleApps map[string]string) string {
	for _, role := range []string{
		"LSHandlerRoleAll",
		"LSHandlerRoleViewer",
		"LSHandlerRoleEditor",
		"LSHandlerRoleShell",
	} {
		if app, ok := roleApps[role]; ok && strings.TrimSpace(app) != "" {
			return strings.TrimSpace(app)
		}
	}
	return ""
}

func hasRoleMismatch(roleApps map[string]string) bool {
	return len(uniqueNonEmptyValues(valuesFromMap(roleApps))) > 1
}

func (p darwinProvider) getTargetRoleCollision(ctx context.Context, target Target) (string, error) {
	handlers, err := p.loadLaunchServicesHandlers(ctx)
	if err != nil {
		return "", err
	}
	return p.getTargetRoleCollisionFromHandlers(target, handlers)
}

func (p darwinProvider) getTargetRoleCollisionFromHandlers(target Target, handlers []map[string]any) (string, error) {
	candidates := []string{}
	for _, handler := range handlers {
		if !p.matchesTarget(target, handler) {
			continue
		}
		roleApps := p.roleValuesFromMap(handler)
		if len(roleApps) == 0 {
			continue
		}
		for _, value := range valuesFromMap(roleApps) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			candidates = append(candidates, value)
		}
	}
	distinct := uniqueNonEmptyValues(candidates)
	if len(distinct) <= 1 {
		return "", nil
	}
	return fmt.Sprintf("detected %d unique handlers: %s", len(distinct), strings.Join(distinct, ", ")), nil
}

func (p darwinProvider) macosEnvironmentSignals() []string {
	signals := []string{}
	if term := strings.TrimSpace(os.Getenv("TERM")); term != "" {
		signals = append(signals, "TERM="+term)
	}
	if termApp := strings.TrimSpace(os.Getenv("TERM_PROGRAM")); termApp != "" {
		signals = append(signals, "TERM_PROGRAM="+termApp)
	}
	if parent := strings.TrimSpace(os.Getenv("PARENT")); parent != "" {
		signals = append(signals, "PARENT="+parent)
	}
	return signals
}

func (p darwinProvider) macosSessionSignals() []string {
	signals := []string{}
	if sshConn := strings.TrimSpace(os.Getenv("SSH_CONNECTION")); sshConn != "" {
		signals = append(signals, "SSH_CONNECTION set")
	}
	if sshClient := strings.TrimSpace(os.Getenv("SSH_CLIENT")); sshClient != "" {
		signals = append(signals, "SSH_CLIENT set")
	}
	if user := strings.TrimSpace(os.Getenv("LOGNAME")); user != "" {
		signals = append(signals, "LOGNAME="+user)
	}
	return signals
}

func macosBrowserPromptPartialCoverageSignal(httpApp string, httpsApp string, htmlApp string, xhtmlApp string, htmlErr error, xhtmlErr error) string {
	if httpApp == "" || httpsApp == "" || !strings.EqualFold(httpApp, httpsApp) {
		return ""
	}
	issues := []string{}
	if htmlErr != nil {
		issues = append(issues, "text/html missing")
	} else if htmlApp != "" && !strings.EqualFold(httpApp, htmlApp) {
		issues = append(issues, fmt.Sprintf("text/html=%q", htmlApp))
	}
	if xhtmlErr != nil {
		issues = append(issues, "application/xhtml+xml missing")
	} else if xhtmlApp != "" && !strings.EqualFold(httpApp, xhtmlApp) {
		issues = append(issues, fmt.Sprintf("application/xhtml+xml=%q", xhtmlApp))
	}
	if len(issues) == 0 {
		return ""
	}
	sort.Strings(issues)
	return fmt.Sprintf("http/https point to %q while content defaults are partial: %s", httpApp, strings.Join(issues, ", "))
}

func (p darwinProvider) macosAPIDriftSignal(ctx context.Context) string {
	if !p.runnerOrDefaultHas("sw_vers") {
		return "sw_vers is unavailable; LaunchServices behavior cannot be pinned to a macOS release"
	}
	version, err := p.runnerOrDefault().Run(ctx, "sw_vers", "-productVersion")
	if err != nil {
		return fmt.Sprintf("sw_vers failed: %v", err)
	}
	version = strings.TrimSpace(version)
	parts := strings.Split(version, ".")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		return fmt.Sprintf("macOS version %q could not be parsed for LaunchServices compatibility checks", version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Sprintf("macOS version %q could not be parsed for LaunchServices compatibility checks", version)
	}
	if major >= 16 {
		return fmt.Sprintf("macOS %s detected; dfx is reading LaunchServices cache state and should be rechecked after OS-level default-app behavior changes", version)
	}
	return ""
}

func (p darwinProvider) macosUpdateReclaimSignals(app string, bundlePath string, plist map[string]any) []string {
	signals := []string{}
	if _, ok := plist["SUFeedURL"]; ok {
		signals = append(signals, fmt.Sprintf("%s declares Sparkle updater feed", app))
	}
	if _, ok := plist["KSVersion"]; ok {
		signals = append(signals, fmt.Sprintf("%s declares Keystone updater metadata", app))
	}
	if recentlyModified := p.recentBundleChangeSignal(bundlePath, 14*24*time.Hour); recentlyModified != "" {
		signals = append(signals, recentlyModified)
	}
	for _, relative := range []string{
		filepath.Join("Contents", "Frameworks", "Sparkle.framework"),
		filepath.Join("Contents", "Frameworks", "Squirrel.framework"),
		filepath.Join("Contents", "Frameworks", "GoogleSoftwareUpdate.framework"),
		filepath.Join("Contents", "Helpers"),
		filepath.Join("Contents", "Library", "LaunchServices"),
	} {
		candidate := filepath.Join(bundlePath, relative)
		if _, err := os.Stat(candidate); err == nil {
			signals = append(signals, fmt.Sprintf("%s contains updater/helper path %s", app, relative))
		}
	}
	for _, pattern := range []string{
		filepath.Join(bundlePath, "Contents", "MacOS", "*[Uu]pdat*"),
		filepath.Join(bundlePath, "Contents", "Helpers", "*[Uu]pdat*"),
		filepath.Join(bundlePath, "Contents", "Library", "LaunchServices", "*[Uu]pdat*"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			signals = append(signals, fmt.Sprintf("%s contains updater component %s", app, strings.TrimPrefix(filepath.Clean(match), filepath.Clean(bundlePath)+string(filepath.Separator))))
		}
	}
	for _, signal := range p.browserUpdaterAgentSignals(app) {
		signals = append(signals, signal)
	}
	sort.Strings(signals)
	return uniqueNonEmptyValues(signals)
}

func (p darwinProvider) recentBundleChangeSignal(bundlePath string, window time.Duration) string {
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	info, err := os.Stat(plistPath)
	if err != nil {
		return ""
	}
	age := time.Since(info.ModTime())
	if age < 0 || age > window {
		return ""
	}
	return fmt.Sprintf("%s Info.plist changed recently at %s", filepath.Base(bundlePath), info.ModTime().Format(time.RFC3339))
}

func (p darwinProvider) browserUpdaterAgentSignals(app string) []string {
	home, _ := os.UserHomeDir()
	patterns := []string{}
	lowerApp := strings.ToLower(strings.TrimSpace(app))
	addPatterns := func(names ...string) {
		for _, name := range names {
			patterns = append(patterns, filepath.Join(string(filepath.Separator), "Library", "LaunchAgents", name))
			patterns = append(patterns, filepath.Join(string(filepath.Separator), "Library", "LaunchDaemons", name))
			if home != "" {
				patterns = append(patterns, filepath.Join(home, "Library", "LaunchAgents", name))
			}
		}
	}
	switch {
	case strings.Contains(lowerApp, "google.chrome"):
		addPatterns("com.google.keystone*.plist")
	case strings.Contains(lowerApp, "microsoft.edgemac"):
		addPatterns("com.microsoft.EdgeUpdater*.plist", "com.microsoft.autoupdate*.plist")
	case strings.Contains(lowerApp, "brave"):
		addPatterns("com.brave.Browser*.plist")
	case strings.Contains(lowerApp, "firefox") || strings.Contains(lowerApp, "mozilla"):
		addPatterns("org.mozilla.*updat*.plist")
	}

	signals := []string{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			signals = append(signals, fmt.Sprintf("%s updater agent present: %s", app, match))
		}
	}
	sort.Strings(signals)
	return uniqueNonEmptyValues(signals)
}

func (p darwinProvider) macosBrowserProfileSignals(app string) []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	lowerApp := strings.ToLower(strings.TrimSpace(app))
	switch {
	case strings.Contains(lowerApp, "google.chrome"):
		return p.chromiumProfileSignals("Google Chrome", filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Local State"))
	case strings.Contains(lowerApp, "microsoft.edgemac"):
		return p.chromiumProfileSignals("Microsoft Edge", filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "Local State"))
	case strings.Contains(lowerApp, "brave"):
		return p.chromiumProfileSignals("Brave", filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Local State"))
	case strings.Contains(lowerApp, "vivaldi"):
		return p.chromiumProfileSignals("Vivaldi", filepath.Join(home, "Library", "Application Support", "Vivaldi", "Local State"))
	case strings.Contains(lowerApp, "firefox") || strings.Contains(lowerApp, "mozilla"):
		return p.firefoxProfileSignals(filepath.Join(home, "Library", "Application Support", "Firefox", "profiles.ini"))
	default:
		return nil
	}
}

func (p darwinProvider) chromiumProfileSignals(label string, localStatePath string) []string {
	payload, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		return nil
	}
	profile, ok := root["profile"].(map[string]any)
	if !ok {
		return nil
	}
	infoCache, _ := profile["info_cache"].(map[string]any)
	signals := []string{}
	if len(infoCache) > 1 {
		signals = append(signals, fmt.Sprintf("%s has %d browser profiles in Local State", label, len(infoCache)))
	}
	if lastUsed := strings.TrimSpace(stringValue(profile["last_used"])); lastUsed != "" && len(infoCache) > 1 {
		signals = append(signals, fmt.Sprintf("%s last used profile is %q", label, lastUsed))
	}
	sort.Strings(signals)
	return uniqueNonEmptyValues(signals)
}

func (p darwinProvider) firefoxProfileSignals(profilePath string) []string {
	payload, err := os.ReadFile(profilePath)
	if err != nil {
		return nil
	}
	profileCount := 0
	defaultProfiles := []string{}
	currentProfile := ""
	for _, rawLine := range strings.Split(string(payload), "\n") {
		line := strings.TrimSpace(rawLine)
		if strings.HasPrefix(line, "[Profile") && strings.HasSuffix(line, "]") {
			profileCount++
			currentProfile = ""
			continue
		}
		if strings.HasPrefix(line, "Name=") {
			currentProfile = strings.TrimSpace(strings.TrimPrefix(line, "Name="))
			continue
		}
		if line == "Default=1" && currentProfile != "" {
			defaultProfiles = append(defaultProfiles, currentProfile)
		}
	}
	signals := []string{}
	if profileCount > 1 {
		signals = append(signals, fmt.Sprintf("Firefox has %d configured profiles", profileCount))
	}
	if len(defaultProfiles) > 0 && profileCount > 1 {
		sort.Strings(defaultProfiles)
		signals = append(signals, fmt.Sprintf("Firefox default profile candidates: %s", strings.Join(defaultProfiles, ", ")))
	}
	sort.Strings(signals)
	return uniqueNonEmptyValues(signals)
}

func (p darwinProvider) macosSignatureSignals(ctx context.Context, bundlePath string) (notarizationSignal string, signatureSignal string) {
	if !p.runnerOrDefaultHas("codesign") {
		return "", ""
	}
	if _, err := p.runnerOrDefault().Run(ctx, "codesign", "-v", "--strict", "--verbose=1", bundlePath); err != nil {
		signatureSignal = strings.TrimSpace(err.Error())
	}
	if p.runnerOrDefaultHas("spctl") {
		if _, err := p.runnerOrDefault().Run(ctx, "spctl", "--assess", "--verbose", "2", "--type", "execute", bundlePath); err != nil {
			notarizationSignal = strings.TrimSpace(err.Error())
		}
	}
	return notarizationSignal, signatureSignal
}

func (p darwinProvider) pathModTime(path string) (time.Time, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return info.ModTime(), true
}

func (p darwinProvider) macosLaunchServicesFreshnessSignal(bundlePath string, cacheModTime time.Time) string {
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	plistInfo, err := os.Stat(plistPath)
	if err != nil {
		return ""
	}
	plistModTime := plistInfo.ModTime()
	if !plistModTime.After(cacheModTime) {
		return ""
	}
	delay := plistModTime.Sub(cacheModTime)
	if delay < 2*time.Minute || time.Since(plistModTime) > 3*time.Hour {
		return ""
	}
	return fmt.Sprintf("%s changed at %s after LaunchServices cache write at %s", filepath.Base(bundlePath), plistModTime.Format(time.RFC3339), cacheModTime.Format(time.RFC3339))
}

func (p darwinProvider) macosProviderPathSignal(bundlePath string) string {
	path := strings.ToLower(filepath.Clean(filepath.ToSlash(bundlePath)))
	providerMarkers := []string{
		"/library/mobile documents/",
		"/library/cloudstorage/",
		"/icloud drive/",
		"/google drive/",
		"/onedrive/",
		"/dropbox/",
		"/box/",
	}
	for _, marker := range providerMarkers {
		if strings.Contains(path, marker) {
			return fmt.Sprintf("%s path indicates provider or cloud-synced storage: %s", filepath.Base(bundlePath), marker)
		}
	}
	return ""
}

func (p darwinProvider) macosBrowserArchitectureSignal(ctx context.Context, bundlePath string) string {
	plist, err := p.readAppInfoPlistFromPath(ctx, filepath.Base(bundlePath), bundlePath)
	if err != nil {
		return ""
	}
	executableName, ok := plist["CFBundleExecutable"].(string)
	if !ok || strings.TrimSpace(executableName) == "" {
		return ""
	}
	executablePath := filepath.Join(bundlePath, "Contents", "MacOS", executableName)
	if !p.runnerOrDefaultHas("lipo") {
		return ""
	}
	output, err := p.runnerOrDefault().Run(ctx, "lipo", "-info", executablePath)
	if err != nil || strings.TrimSpace(output) == "" {
		return ""
	}
	outputText := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(output), "\n", " "))
	hasArm := strings.Contains(outputText, "arm64") || strings.Contains(outputText, "armv7") || strings.Contains(outputText, "armv8") || strings.Contains(outputText, "arm64e")
	hasIntel := strings.Contains(outputText, "x86_64")
	hostArm := runtime.GOARCH == "arm64"
	hostIntel := runtime.GOARCH == "amd64" || runtime.GOARCH == "386"
	if hostArm && hasIntel && !hasArm {
		return fmt.Sprintf("%s reports Intel-only binary architecture (`%s`)", filepath.Base(bundlePath), outputText)
	}
	if hostIntel && hasArm && !hasIntel {
		return fmt.Sprintf("%s reports Apple Silicon-only binary architecture (`%s`)", filepath.Base(bundlePath), outputText)
	}
	return ""
}

func (p darwinProvider) macosSandboxPathSignal(ctx context.Context, bundlePath string) string {
	entitlements, err := p.macosBundleEntitlementsXML(ctx, bundlePath)
	if err != nil || strings.TrimSpace(entitlements) == "" {
		return ""
	}
	if !plistHasEntitlementTrue(entitlements, "com.apple.security.app-sandbox") {
		return ""
	}
	if plistHasSandboxFileAccess(entitlements) {
		return ""
	}
	return fmt.Sprintf("%s appears sandboxed without direct file-access entitlements; file-path open behavior may differ from Finder for URL/file handoff", filepath.Base(bundlePath))
}

func (p darwinProvider) macosBundleEntitlementsXML(ctx context.Context, bundlePath string) (string, error) {
	output, err := p.runnerOrDefault().Run(ctx, "codesign", "-d", "--entitlements", ":-", "--", bundlePath)
	if err == nil && strings.TrimSpace(output) != "" {
		return output, nil
	}
	if !p.runnerOrDefaultHas("sh") {
		return "", err
	}
	output, shErr := p.runnerOrDefault().Run(ctx, "sh", "-lc", fmt.Sprintf("codesign -d --entitlements :- -- %s 2>&1", strconv.Quote(bundlePath)))
	if shErr != nil {
		if strings.TrimSpace(output) == "" {
			return "", err
		}
		return output, nil
	}
	if strings.TrimSpace(output) == "" {
		return "", err
	}
	return output, nil
}

func plistHasEntitlementTrue(payload string, key string) bool {
	marker := "<key>" + key + "</key>"
	idx := strings.Index(payload, marker)
	if idx == -1 {
		return false
	}
	rest := payload[idx+len(marker):]
	if next := strings.Index(rest, "<key>"); next > 0 {
		rest = rest[:next]
	}
	return strings.Contains(rest, "<true/>") || strings.Contains(rest, "<true />")
}

func plistHasSandboxFileAccess(payload string) bool {
	fileEntitlements := []string{
		"com.apple.security.files.user-selected.read-only",
		"com.apple.security.files.user-selected.read-write",
		"com.apple.security.files.downloads.read-only",
		"com.apple.security.files.downloads.read-write",
		"com.apple.security.files.pictures.read-only",
		"com.apple.security.files.pictures.read-write",
		"com.apple.security.files.movies.read-only",
		"com.apple.security.files.movies.read-write",
		"com.apple.security.files.music.read-only",
		"com.apple.security.files.music.read-write",
		"com.apple.security.files.documents.read-only",
		"com.apple.security.files.documents.read-write",
	}
	for _, entitlement := range fileEntitlements {
		if plistHasEntitlementTrue(payload, entitlement) {
			return true
		}
	}
	return false
}

func (p darwinProvider) macosMDMLaunchServicesSignals(ctx context.Context) []string {
	managedSignals := []string{}
	candidatePaths := map[string]struct{}{}

	addCandidatePath := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		candidatePaths[filepath.Clean(path)] = struct{}{}
	}
	appendPatterns := func(patterns ...string) {
		for _, pattern := range patterns {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}
			for _, match := range matches {
				addCandidatePath(match)
			}
		}
	}

	systemPolicyRoot := filepath.Join(string(filepath.Separator), "Library", "Managed Preferences")
	home, err := os.UserHomeDir()
	appendPatterns(filepath.Join(systemPolicyRoot, "*LaunchServices*.plist"))
	addCandidatePath(filepath.Join(systemPolicyRoot, "com.apple.LaunchServices.plist"))
	addCandidatePath(filepath.Join(systemPolicyRoot, "com.apple.LaunchServices"))

	if err == nil {
		appendPatterns(filepath.Join(home, "Library", "Managed Preferences", "*LaunchServices*.plist"))
		addCandidatePath(filepath.Join(home, "Library", "Managed Preferences", "com.apple.LaunchServices.plist"))
		addCandidatePath(filepath.Join(home, "Library", "Managed Preferences", "com.apple.LaunchServices"))
	}

	for path := range candidatePaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".plist") {
					continue
				}
				if candidate := filepath.Join(path, entry.Name()); p.hasLaunchServicesManagedPayload(ctx, candidate) {
					managedSignals = append(managedSignals, candidate)
				}
			}
			continue
		}
		if p.hasLaunchServicesManagedPayload(ctx, path) {
			managedSignals = append(managedSignals, path)
		}
	}

	sort.Strings(managedSignals)
	return managedSignals
}

func (p darwinProvider) macosEndpointSecuritySignals(ctx context.Context) []string {
	signals := []string{}
	if p.runnerOrDefaultHas("systemextensionsctl") {
		output, err := p.runnerOrDefault().Run(ctx, "systemextensionsctl", "list")
		if err == nil {
			interesting := []string{
				"contentfilter",
				"networkextension",
				"endpointsecurity",
				"content filter",
			}
			for _, line := range strings.Split(output, "\n") {
				normalized := strings.ToLower(strings.TrimSpace(line))
				if normalized == "" {
					continue
				}
				for _, marker := range interesting {
					if strings.Contains(normalized, marker) {
						signals = append(signals, fmt.Sprintf("systemextensionsctl: %s", strings.TrimSpace(line)))
						break
					}
				}
			}
		}
	}
	extRoot := filepath.Join(string(filepath.Separator), "Library", "SystemExtensions")
	entries, err := os.ReadDir(extRoot)
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() {
				continue
			}
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".systemextension") {
				signals = append(signals, fmt.Sprintf("system extension installed: %s", name))
				continue
			}
			if strings.Contains(lower, "filter") || strings.Contains(lower, "security") {
				signals = append(signals, fmt.Sprintf("system extension candidate: %s", name))
			}
		}
	}
	sort.Strings(signals)
	signals = uniqueNonEmptyValues(signals)
	return signals
}

func (p darwinProvider) hasLaunchServicesManagedPayload(ctx context.Context, path string) bool {
	if !p.runnerOrDefaultHas("plutil") {
		return false
	}
	output, err := p.runnerOrDefault().Run(ctx, "plutil", "-convert", "json", "-o", "-", path)
	if err != nil || strings.TrimSpace(output) == "" {
		return false
	}
	var payload any
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return false
	}
	return hasLaunchServicesPolicySignal(payload)
}

func hasLaunchServicesPolicySignal(value any) bool {
	switch root := value.(type) {
	case map[string]any:
		for key, child := range root {
			lowerKey := strings.ToLower(strings.TrimSpace(key))
			if lowerKey == "lshandlers" || lowerKey == "com.apple.launchservices" || strings.Contains(lowerKey, "launchservices") {
				return true
			}
			if hasLaunchServicesPolicySignal(child) {
				return true
			}
		}
	case []any:
		for _, child := range root {
			if hasLaunchServicesPolicySignal(child) {
				return true
			}
		}
	}
	return false
}

func roleSummary(roleApps map[string]string) string {
	parts := make([]string, 0, len(roleApps))
	for _, role := range []string{
		"LSHandlerRoleAll",
		"LSHandlerRoleViewer",
		"LSHandlerRoleEditor",
		"LSHandlerRoleShell",
	} {
		value := strings.TrimSpace(roleApps[role])
		if value == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%q", strings.TrimPrefix(role, "LSHandlerRole"), value))
	}
	if len(parts) == 0 {
		return "no role handlers"
	}
	return strings.Join(parts, ", ")
}

func valuesFromMap(values map[string]string) []string {
	flattened := make([]string, 0, len(values))
	for _, value := range values {
		flattened = append(flattened, value)
	}
	return flattened
}

func macContentTypeAliasDrift(handlers []map[string]any, aliases []string) string {
	if len(aliases) < 2 {
		return ""
	}
	normalizedAliases := make([]string, 0, len(aliases))
	seenAlias := map[string]struct{}{}
	for _, alias := range aliases {
		alias = strings.ToLower(strings.TrimSpace(alias))
		if alias == "" {
			continue
		}
		if _, ok := seenAlias[alias]; ok {
			continue
		}
		seenAlias[alias] = struct{}{}
		normalizedAliases = append(normalizedAliases, alias)
	}
	if len(normalizedAliases) < 2 {
		return ""
	}

	detector := darwinProvider{}
	assignedByAlias := map[string]string{}
	for _, alias := range normalizedAliases {
		roleApps, err := detector.targetRoleHandlersFromHandlers(Target{Kind: KindMIME, Value: alias}, handlers)
		if err != nil {
			continue
		}
		handler := detector.selectRoleHandler(roleApps)
		if handler == "" {
			continue
		}
		assignedByAlias[strings.TrimSpace(strings.ToLower(alias))] = strings.TrimSpace(strings.ToLower(handler))
	}
	if len(assignedByAlias) < 2 {
		return ""
	}
	distinct := map[string]struct{}{}
	for _, value := range assignedByAlias {
		distinct[value] = struct{}{}
	}
	if len(distinct) <= 1 {
		return ""
	}

	items := make([]string, 0, len(assignedByAlias))
	for alias, value := range assignedByAlias {
		items = append(items, fmt.Sprintf("%s=%q", alias, value))
	}
	sort.Strings(items)
	return fmt.Sprintf("mixed handlers across alias targets: %s", strings.Join(items, "; "))
}

func (p darwinProvider) loadLaunchServicesHandlers(ctx context.Context) ([]map[string]any, error) {
	return p.loadLaunchServicesHandlersFromPath(ctx, p.launchServicesPlistPath())
}

func (p darwinProvider) loadLaunchServicesHandlersFromPath(ctx context.Context, plistPath string) ([]map[string]any, error) {
	output, err := p.runnerOrDefault().Run(ctx, "plutil", "-convert", "json", "-o", "-", plistPath)
	if err != nil {
		return nil, fmt.Errorf("read launch services cache at %s: %w", plistPath, err)
	}

	var payload struct {
		Handlers []map[string]any `json:"LSHandlers"`
	}
	if err := json.Unmarshal([]byte(output), &payload); err != nil {
		return nil, fmt.Errorf("parse LaunchServices cache: %w", err)
	}
	return payload.Handlers, nil
}

func (p darwinProvider) launchServicesSystemPlistPath() string {
	return filepath.Join(string(filepath.Separator), "Library", "Preferences", "com.apple.LaunchServices", "com.apple.launchservices.secure.plist")
}

func (p darwinProvider) canReadLaunchServices() bool {
	return p.runnerOrDefaultHas("plutil") && p.launchServicesPlistPathExists()
}

func (p darwinProvider) launchServicesPlistPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist"
	}
	return filepath.Join(home, "Library", "Preferences", "com.apple.LaunchServices", "com.apple.launchservices.secure.plist")
}

func (p darwinProvider) launchServicesPlistPathExists() bool {
	_, err := os.Stat(p.launchServicesPlistPath())
	return err == nil
}

func inferDarwinBrowserChannel(bundleID string) (string, string) {
	normalized := strings.ToLower(strings.TrimSpace(bundleID))
	if normalized == "" {
		return "", ""
	}
	parts := strings.Split(normalized, ".")
	if len(parts) == 0 {
		return normalized, "stable"
	}
	channel := "stable"
	if len(parts) > 1 {
		switch strings.TrimSpace(parts[len(parts)-1]) {
		case "beta", "canary", "dev", "nightly", "alpha", "insider", "test":
			channel = strings.TrimSpace(parts[len(parts)-1])
			parts = parts[:len(parts)-1]
		}
	}
	family := strings.Join(parts, ".")
	if family == "" {
		family = normalized
	}
	return family, channel
}

func darwinAppNameCandidates(query string) []string {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil
	}
	candidates := []string{query}
	switch darwinNormalizeAppAlias(query) {
	case "brave", "bravebrowser":
		candidates = append(candidates, "Brave Browser")
	case "chrome", "googlechrome":
		candidates = append(candidates, "Google Chrome")
	case "edge", "microsoftedge":
		candidates = append(candidates, "Microsoft Edge")
	case "vivaldi":
		candidates = append(candidates, "Vivaldi")
	}
	candidates = append(candidates, darwinTitleCaseASCII(query))

	seen := map[string]struct{}{}
	unique := candidates[:0]
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, candidate)
	}
	return unique
}

func knownDarwinBundleID(query string) string {
	token := darwinNormalizeAppAlias(query)
	known := map[string]string{
		"brave":         "com.brave.Browser",
		"bravebrowser":  "com.brave.Browser",
		"chrome":        "com.google.Chrome",
		"googlechrome":  "com.google.Chrome",
		"chromium":      "org.chromium.Chromium",
		"edge":          "com.microsoft.edgemac",
		"microsoftedge": "com.microsoft.edgemac",
		"firefox":       "org.mozilla.firefox",
		"safari":        "com.apple.Safari",
		"vivaldi":       "com.vivaldi.Vivaldi",
	}
	if bundleID := known[token]; bundleID != "" {
		return bundleID
	}
	if len(token) < 3 {
		return ""
	}
	matched := ""
	for alias, bundleID := range known {
		if !strings.HasPrefix(alias, token) {
			continue
		}
		if matched != "" && matched != bundleID {
			return ""
		}
		matched = bundleID
	}
	return matched
}

func darwinNormalizeAppAlias(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func darwinTitleCaseASCII(value string) string {
	parts := strings.FieldsFunc(strings.TrimSpace(value), func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
	for i, part := range parts {
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		parts[i] = strings.ToUpper(lower[:1]) + lower[1:]
	}
	return strings.Join(parts, " ")
}

func (p darwinProvider) bundleIDLooksInstalled(ctx context.Context, bundleID string) bool {
	escaped := strings.ReplaceAll(bundleID, `"`, `\"`)
	_, err := p.runnerOrDefault().Run(ctx, "osascript", "-e", `id of application id "`+escaped+`"`)
	return err == nil
}

func (p darwinProvider) darwinUnsupportedOperation(operation string) error {
	if p.dutiAvailable() {
		return fmt.Errorf("macOS %s cannot apply direct LaunchServices writes safely in this build; use --dry-run to review System Settings guidance and emitted duti-style commands", operation)
	}
	return fmt.Errorf("macOS %s cannot apply direct LaunchServices writes safely in this build; use --dry-run for System Settings guidance, and install duti (`brew install duti`) only to compare emitted CLI-style remediation commands", operation)
}

func (p darwinProvider) darwinSetGuidanceOperations(association Association) []string {
	targets := darwinTargetsForAssociation(association.Target())
	operations := make([]string, 0, len(targets)+2)
	for _, target := range targets {
		switch target.Kind {
		case KindScheme:
			operations = append(operations, fmt.Sprintf("Plan LaunchServices scheme handler update: %s -> %s", target.Value, association.App))
			operations = append(operations, fmt.Sprintf("duti preview: duti -s %s %s", association.App, target.Value))
		case KindMIME:
			operations = append(operations, fmt.Sprintf("Plan LaunchServices content-role handler update: %s -> %s", target.Value, association.App))
			for _, contentType := range normalizeMacContentType(target.Value) {
				operations = append(operations, fmt.Sprintf("duti preview: duti -s %s %s all", association.App, contentType))
			}
		}
	}
	operations = append(operations, "Apply through System Settings, browser default prompts, or a future native LaunchServices write backend")
	return operations
}

func darwinTargetsForAssociation(target Target) []Target {
	if target.Kind != KindBrowser && !(target.Kind == KindScheme && (target.Value == "http" || target.Value == "https")) {
		return []Target{target}
	}
	return []Target{
		{Kind: KindScheme, Value: "http"},
		{Kind: KindScheme, Value: "https"},
		{Kind: KindMIME, Value: "text/html"},
		{Kind: KindMIME, Value: "application/xhtml+xml"},
	}
}

func (p darwinProvider) dutiAvailable() bool {
	return p.runnerOrDefaultHas("duti")
}

func (p darwinProvider) runnerOrDefault() commandRunner {
	if p.runner != nil {
		return p.runner
	}
	return execRunner{}
}

func (p darwinProvider) runnerOrDefaultHas(name string) bool {
	_, err := p.runnerOrDefault().LookPath(name)
	return err == nil
}

func stringValue(value any) string {
	str, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(str)
}

func uniqueNonEmptyValues(values []string) []string {
	seen := map[string]struct{}{}
	distinct := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		distinct = append(distinct, value)
	}
	return distinct
}

func normalizeMacContentType(value string) []string {
	value = strings.TrimSpace(strings.ToLower(value))
	switch value {
	case "text/html":
		return []string{value, "public.html"}
	case "application/xhtml+xml":
		return []string{value, "public.xhtml", "public.xhtml+xml"}
	default:
		return []string{value}
	}
}
