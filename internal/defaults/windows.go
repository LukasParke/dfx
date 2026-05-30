//go:build windows

package defaults

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type windowsProvider struct {
	runner commandRunner
}

func newWindowsProvider() Provider {
	return windowsProvider{runner: execRunner{}}
}

func (p windowsProvider) Inspect(context.Context) InspectReport {
	canRead := p.regAvailable()
	return InspectReport{
		Platform: "windows",
		Provider: "windows-default-apps",
		CanRead:  canRead,
		CanWrite: false,
		Capabilities: Capabilities{
			CanReadCurrent:        canRead,
			CanWriteUserDefault:   false,
			CanWriteSystemDefault: false,
			PolicyRestricted:      true,
			SupportsBrowser:       true,
			SupportsScheme:        true,
			SupportsMIME:          true,
			SupportsContentType:   true,
		},
		Notes: []string{
			"modern Windows protects protocol and file associations with per-user choice and policy constraints",
			"dfx provides read-only inspection on native Windows until safe write workflows are standardized",
			"see docs/wiki/windows-default-apps.md for policy-aware constraints and rollout guidance",
		},
	}
}

func (p windowsProvider) Get(ctx context.Context, target Target) (string, error) {
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return "", err
	}
	if !p.regAvailable() {
		return "", windowsUnsupportedOperation("get")
	}

	switch target.Kind {
	case KindBrowser:
		return p.getBrowserDefault(ctx)
	case KindScheme:
		return p.getSchemeDefault(ctx, target.Value)
	case KindMIME:
		return p.getMimeDefault(ctx, target.Value)
	default:
		return "", fmt.Errorf("unsupported target kind %q", target.Kind)
	}
}

func (p windowsProvider) Doctor(ctx context.Context, options DoctorOptions) (DoctorReport, error) {
	if !options.Browser {
		return DoctorReport{}, fmt.Errorf("doctor currently requires --browser")
	}
	if !p.regAvailable() {
		return DoctorReport{}, windowsUnsupportedOperation("doctor")
	}

	httpCandidates := p.getSchemeAssociations(ctx, "http")
	httpsCandidates := p.getSchemeAssociations(ctx, "https")
	mailtoCandidates := p.getSchemeAssociations(ctx, "mailto")
	htmlCandidates := p.getMimeAssociations(ctx, "text/html")
	xhtmlCandidates := p.getMimeAssociations(ctx, "application/xhtml+xml")

	httpValue, _, httpHash, _ := bestAssociation(httpCandidates)
	httpsValue, _, httpsHash, _ := bestAssociation(httpsCandidates)
	mailtoValue, _, _, _ := bestAssociation(mailtoCandidates)
	htmlValue := bestValue(htmlCandidates)
	xhtmlValue := bestValue(xhtmlCandidates)

	report := DoctorReport{
		Platform: "windows",
		Scope:    "browser",
		Healthy:  true,
		Notes: []string{
			"dfx on Windows currently performs read-only checks and does not attempt registry writes",
			"policy/provisioning remains the supported default-assignment channel",
		},
	}

	addFinding := func(id, severity, summary, details string, remediation ...string) {
		if !strings.EqualFold(severity, "info") && !strings.EqualFold(severity, "warning") {
			report.Healthy = false
		}
		remediationText := "use Windows Settings > Apps > Default apps, then re-run dfx doctor"
		if len(remediation) > 0 && strings.TrimSpace(remediation[0]) != "" {
			remediationText = strings.TrimSpace(remediation[0])
		}
		report.Findings = append(report.Findings, DoctorFinding{
			ID:          id,
			Severity:    severity,
			Summary:     summary,
			Details:     details,
			Remediation: remediationText,
		})
	}

	if err := firstError(httpCandidates); err != nil {
		addFinding("W01", "error", "scheme default read failed", err.Error())
	}
	if err := firstError(httpsCandidates); err != nil {
		addFinding("W03", "error", "scheme default read failed", fmt.Sprintf("https: %v", err))
	}
	if err := firstError(mailtoCandidates); err != nil {
		addFinding("W21", "warning", "mailto mapping not read cleanly", fmt.Sprintf("mailto: %v", err))
	}
	if err := firstError(htmlCandidates); err != nil {
		addFinding("W03", "error", "text/html mapping read failed", err.Error())
	}
	if err := firstError(xhtmlCandidates); err != nil {
		addFinding("W03", "warning", "application/xhtml+xml mapping read failed", fmt.Sprintf("xhtml: %v", err))
	}
	policyDetails := p.currentAssociationPolicySignals(ctx)
	policyRecords, policyRecordIssues := p.windowsPolicyAssociationRecordSet(ctx)
	missing, problems, mandatory := p.policyAssociationSignalsFromRecords(policyRecords, policyRecordIssues)
	requiredPolicyTargets := strings.Join(windowsRequiredPolicyTargets(), ", ")
	policyManaged := len(policyDetails) > 0
	if policyManaged {
		for _, detail := range policyDetails {
			addFinding("W06", "info", "association defaults appear policy-driven", detail)
		}
		if len(problems) > 0 {
			for _, problem := range problems {
				addFinding("W07", "warning", "policy association source is invalid or unreadable", problem, "validate policy association XML using enterprise tooling and re-apply policy")
			}
			if len(missing) > 0 {
				addFinding("W08", "warning", "policy association payload misses required defaults", strings.Join(missing, ", "), "include policy entries for "+requiredPolicyTargets)
			}
		} else if len(missing) != 0 {
			addFinding("W08", "warning", "policy association payload misses required defaults", strings.Join(missing, ", "), "include policy entries for "+requiredPolicyTargets)
		}
		if mandatory {
			addFinding("W26", "warning", "mandatory default-association policy blocks remediation", "policy associations for required web targets are marked mandatory and may reassert on sign-in")
		}
		if !hasUsableAssociationFromSource(httpCandidates, "HKCU") && hasUsableAssociationFromSource(httpCandidates, "HKLM") {
			addFinding("W09", "warning", "policy defaults may only be present in machine scope", "http protocol has no HKCU UserChoice but has HKLM values")
		}
		if !hasUsableAssociationFromSource(httpsCandidates, "HKCU") && hasUsableAssociationFromSource(httpsCandidates, "HKLM") {
			addFinding("W09", "warning", "policy defaults may only be present in machine scope", "https protocol has no HKCU UserChoice but has HKLM values")
		}
		if !hasUsableAssociationFromSource(htmlCandidates, "HKCU") && hasUsableAssociationFromSource(htmlCandidates, "HKLM") {
			addFinding("W09", "warning", "policy defaults may only be present in machine scope", "text/html mapping has no HKCU UserChoice but has HKLM values")
		}
		if !hasUsableAssociationFromSource(xhtmlCandidates, "HKCU") && hasUsableAssociationFromSource(xhtmlCandidates, "HKLM") {
			addFinding("W09", "warning", "policy defaults may only be present in machine scope", "application/xhtml+xml mapping has no HKCU UserChoice but has HKLM values")
		}
		currentPolicyTargets := map[string]string{
			"http":                  httpValue,
			"https":                 httpsValue,
			"text/html":             htmlValue,
			"application/xhtml+xml": xhtmlValue,
		}
		if callbackScheme := normalizeCallbackScheme(os.Getenv("DFX_CALLBACK_SCHEME")); callbackScheme != "" {
			if callbackValue, err := p.getSchemeDefault(ctx, callbackScheme); err == nil {
				currentPolicyTargets[callbackScheme] = callbackValue
			}
		}
		if overrideSignals := windowsPolicyAssociationOverrideSignals(policyRecords, currentPolicyTargets); len(overrideSignals) > 0 {
			for _, signal := range overrideSignals {
				addFinding("W06", "warning", "policy-declared default differs from current default", signal, "verify policy scope, user override state, and delayed policy application before treating the default as enforced")
			}
		}
		if isDiverged(httpCandidates) || isDiverged(httpsCandidates) || isDiverged(htmlCandidates) {
			addFinding("W27", "warning", "managed policy may re-apply over user choices", "policy scope and user scope values differ for web defaults")
		}
		if driftSignals := p.windowsPolicyAssociationProgIDSignals(ctx, policyRecords, currentPolicyTargets); len(driftSignals) > 0 {
			for _, signal := range driftSignals {
				addFinding("W10", "warning", "policy ProgID appears stale after browser update", signal, "refresh enterprise policy XML/CSP to match current browser registration identifiers")
			}
		}
	}
	if policyManaged {
		if updateSignals := p.windowsFeatureUpdateResetSignals(ctx); len(updateSignals) > 0 && !mandatory {
			addFinding("W28", "warning", "feature-update state can reset browser defaults", strings.Join(updateSignals, "; "), "re-seed enterprise managed defaults after major Windows upgrades and verify web defaults in each affected user profile")
		}
	}
	if policyManaged {
		if repairSignals := p.windowsBrowserRepairSignals(ctx); len(repairSignals) > 0 {
			for _, signal := range repairSignals {
				addFinding("W29", "warning", "vendor repair tooling may override managed defaults", signal, "disable or gate browser repair/reset tasks while policy-managed defaults are in force")
			}
		}
	}
	hardeningSignals := p.windowsDefaultAppsHardeningSignals(ctx)
	if len(hardeningSignals) > 0 {
		addFinding("W16", "warning", "hardening may block default-app UI or remediation prompts", strings.Join(hardeningSignals, "; "), "review enterprise hardening policies that limit Settings/Apps access before expecting interactive remediation")
	}
	legacyTools := windowsLegacyToolsAvailable(p)
	if len(legacyTools) > 0 {
		addFinding("W14", "info", "legacy assoc/ftype tooling does not model modern browser defaults", fmt.Sprintf("legacy command availability: %s", strings.Join(legacyTools, ", ")))
	}
	if callbackScheme := normalizeCallbackScheme(os.Getenv("DFX_CALLBACK_SCHEME")); callbackScheme != "" {
		callbackValue, err := p.getSchemeDefault(ctx, callbackScheme)
		if err != nil {
			addFinding("W30", "warning", "configured callback scheme is unset", fmt.Sprintf("%s: %v", callbackScheme, err), "set DFX_CALLBACK_SCHEME to a scheme mapped to your native OAuth callback handler")
		} else {
			browserDefaults := map[string]struct{}{
				strings.ToLower(httpValue):   {},
				strings.ToLower(httpsValue):  {},
				strings.ToLower(mailtoValue): {},
				strings.ToLower(htmlValue):   {},
				strings.ToLower(xhtmlValue):  {},
			}
			if _, ok := browserDefaults[strings.ToLower(callbackValue)]; ok && callbackValue != "" {
				addFinding("W30", "warning", "callback scheme points to the browser default", fmt.Sprintf("%s=%q", callbackScheme, callbackValue), "point the callback scheme to a native app handler to avoid browser loop behavior")
			}
		}
	}
	if duplicates := associationCandidateSummary(p.getSchemeAssociations(ctx, "http")); len(duplicates) > 1 {
		addFinding("W12", "warning", "store and desktop handler candidates are both present for http", fmt.Sprintf("http has multiple registration candidates: %s", strings.Join(duplicates, "; ")), "inspect HKCU/HKLM UserChoice and app registration paths and remove stale duplicate handler entries")
	}
	if duplicates := associationCandidateSummary(p.getSchemeAssociations(ctx, "https")); len(duplicates) > 1 {
		addFinding("W12", "warning", "store and desktop handler candidates are both present for https", fmt.Sprintf("https has multiple registration candidates: %s", strings.Join(duplicates, "; ")), "inspect HKCU/HKLM UserChoice and app registration paths and remove stale duplicate handler entries")
	}
	if duplicates := associationCandidateSummary(p.getMimeAssociations(ctx, "text/html")); len(duplicates) > 1 {
		addFinding("W12", "warning", "store and desktop handler candidates are both present for web MIME", fmt.Sprintf("text/html has multiple registration candidates: %s", strings.Join(duplicates, "; ")), "inspect HKCU/HKLM UserChoice and app registration paths and remove stale duplicate handler entries")
	}
	if duplicates := associationCandidateSummary(p.getMimeAssociations(ctx, "application/xhtml+xml")); len(duplicates) > 1 {
		addFinding("W12", "warning", "store and desktop handler candidates are both present for XHTML MIME", fmt.Sprintf("application/xhtml+xml has multiple registration candidates: %s", strings.Join(duplicates, "; ")), "inspect HKCU/HKLM UserChoice and app registration paths and remove stale duplicate handler entries")
	}
	if remoteSignals := windowsRemoteSessionSignals(); len(remoteSignals) > 0 {
		addFinding("W17", "warning", "remote session defaults may follow different launch rules", strings.Join(remoteSignals, "; "), "verify protocol and MIME launches in the target remote session workflow")
	}
	targets := []struct {
		target  Target
		handler string
	}{
		{target: Target{Kind: KindScheme, Value: "http"}, handler: httpValue},
		{target: Target{Kind: KindScheme, Value: "https"}, handler: httpsValue},
		{target: Target{Kind: KindScheme, Value: "mailto"}, handler: mailtoValue},
		{target: Target{Kind: KindMIME, Value: "text/html"}, handler: htmlValue},
		{target: Target{Kind: KindMIME, Value: "application/xhtml+xml"}, handler: xhtmlValue},
	}
	likelyAppXHandlers := map[string]struct{}{}
	channelSignals := map[string]map[string][]string{}
	recordBrowserChannelSignal := func(target string, handler, command string) {
		family, channel := inferWindowsHandlerBrowserChannel(handler, command)
		if family == "" {
			return
		}
		channels, ok := channelSignals[family]
		if !ok {
			channels = map[string][]string{}
			channelSignals[family] = channels
		}
		channels[channel] = append(channels[channel], fmt.Sprintf("%s=%q", target, handler))
	}
	commandsByHandler := map[string]string{}
	checkedHandlers := map[string]struct{}{}
	for _, item := range targets {
		handler := strings.TrimSpace(item.handler)
		if handler == "" {
			continue
		}
		target := item.target

		if _, checked := checkedHandlers[handler]; !checked {
			checkedHandlers[handler] = struct{}{}
			if _, seen := likelyAppXHandlers[handler]; !seen && isLikelyAppContainerHandler(handler) {
				addFinding("W18", "warning", "app-activation path may be AppContainer/AppX-oriented", fmt.Sprintf("%s selected as web default", handler), "expect URI launch differences for AppContainer/Store-backed defaults")
				likelyAppXHandlers[handler] = struct{}{}
			}
			if !p.hasAssocRegistration(ctx, handler) {
				addFinding("W11", "warning", "mapped handler points to an orphaned registry registration", fmt.Sprintf("%s for %s has no discoverable handler registration", handler, target.String()))
				continue
			}

			command, commandErr := p.readAssocCommand(ctx, handler)
			if commandErr != nil {
				addFinding("W19", "warning", "mapped handler is missing an executable command", fmt.Sprintf("%s: %v", handler, commandErr))
			} else {
				if verb, err := p.readAssocDefaultVerb(ctx, handler); err != nil {
					addFinding("W24", "warning", "selected handler missing shell verb defaults", fmt.Sprintf("%s: %v", handler, err))
				} else if !strings.EqualFold(verb, "open") {
					addFinding("W24", "warning", "selected handler default verb is not open", fmt.Sprintf("%s: %s", handler, verb))
				}
				if _, err := p.readAssocDefaultIcon(ctx, handler); err != nil {
					addFinding("W24", "warning", "selected handler has no discoverable icon registration", fmt.Sprintf("%s: %v", handler, err))
				}
				if !supportsURIPayload(command) {
					addFinding("W20", "warning", "selected handler command may not accept URI arguments", fmt.Sprintf("%s: command=%q", handler, command))
				}
				if runtime.GOARCH != "386" && hasLikely32BitExecutableMarker(command) {
					addFinding("W15", "warning", "selected handler appears to target a 32-bit browser install", fmt.Sprintf("%s: command=%q", handler, command))
				}
				if _, err := p.readAssocCapabilities(ctx, handler); err != nil {
					addFinding("W22", "warning", "handler has no discoverable capability registration", fmt.Sprintf("%s: %v", handler, err))
				}
				commandsByHandler[handler] = command
			}
		}

		hasCapability, capErr := p.assocDeclaresTargetCapability(ctx, handler, target)
		if capErr != nil {
			addFinding("W22", "warning", "failed to inspect handler capability mapping", fmt.Sprintf("%s (%s): %v", handler, target.String(), capErr))
			continue
		}
		if !hasCapability {
			addFinding("W02", "warning", "selected handler has no capability mapping for this target", fmt.Sprintf("%s does not declare %s handling for %s", handler, target.Kind, target.Value))
		}
	}
	for _, item := range targets {
		recordBrowserChannelSignal(item.target.String(), item.handler, commandsByHandler[item.handler])
	}
	for family, channels := range channelSignals {
		if len(channels) <= 1 {
			continue
		}
		channelsList := make([]string, 0, len(channels))
		for channel, hits := range channels {
			sort.Strings(hits)
			channelsList = append(channelsList, fmt.Sprintf("%s: %s", channel, strings.Join(hits, ", ")))
		}
		sort.Strings(channelsList)
		addFinding("W23", "warning", "multiple browser channel families appear active", fmt.Sprintf("family=%q channel coverage=%s", family, strings.Join(channelsList, "; ")), "align channel-specific installations so the same browser family owns the web-default handlers")
	}

	if isDiverged(httpCandidates) {
		addFinding("W05", "warning", "per-user vs machine protocol defaults differ", `http exists in both HKCU and HKLM with different values`)
	}
	if isDiverged(httpsCandidates) {
		addFinding("W05", "warning", "per-user vs machine protocol defaults differ", `https exists in both HKCU and HKLM with different values`)
	}
	if isDiverged(htmlCandidates) {
		addFinding("W05", "warning", "per-user vs machine content defaults differ", `text/html exists in both HKCU and HKLM with different values`)
	}

	if httpValue != "" && httpsValue != "" && !strings.EqualFold(httpValue, httpsValue) {
		addFinding("W04", "warning", "related protocols are out of alignment", fmt.Sprintf("http=%q, https=%q", httpValue, httpsValue))
	}
	if httpValue != "" && mailtoValue != "" && !strings.EqualFold(httpValue, mailtoValue) {
		addFinding("W21", "warning", "mailto defaults diverge from browser protocols", fmt.Sprintf("http=%q, mailto=%q", httpValue, mailtoValue))
	}
	if httpsValue != "" && mailtoValue != "" && !strings.EqualFold(httpsValue, mailtoValue) {
		addFinding("W21", "warning", "mailto defaults diverge from https", fmt.Sprintf("https=%q, mailto=%q", httpsValue, mailtoValue))
	}

	if htmlValue != "" && httpValue != "" && !strings.EqualFold(httpValue, htmlValue) {
		addFinding("W03", "warning", "protocol vs extension split", fmt.Sprintf("http=%q, text/html=%q", httpValue, htmlValue))
	}
	if htmlValue != "" && httpsValue != "" && !strings.EqualFold(httpsValue, htmlValue) {
		addFinding("W03", "warning", "protocol vs extension split", fmt.Sprintf("https=%q, text/html=%q", httpsValue, htmlValue))
	}
	if xhtmlValue != "" && htmlValue != "" && !strings.EqualFold(xhtmlValue, htmlValue) {
		addFinding("W03", "warning", "custom handler mismatch for HTML families", fmt.Sprintf(`application/xhtml+xml=%q vs text/html=%q`, xhtmlValue, htmlValue))
	}
	if issue := checkFamilyDivergence(htmlCandidates, mimeToExtensions("text/html")); issue != "" {
		addFinding("W25", "warning", "per-extension file defaults diverge", issue)
	}
	if issue := checkFamilyDivergence(p.getMimeAssociations(ctx, "application/xhtml+xml"), mimeToExtensions("application/xhtml+xml")); issue != "" {
		addFinding("W25", "warning", "xhtml extension family defaults diverge", issue)
	}

	if httpHash {
		addFinding("W01", "info", "UserChoice hash detected", "http scheme has a hash-backed UserChoice entry; user-driven or policy updates are required")
		addFinding("W13", "warning", "UserChoice hash may trigger default reset messaging", "http scheme is hash-backed in UserChoice; users may need explicit reset flow after policy or repair operations")
	}
	if httpsHash {
		addFinding("W01", "info", "UserChoice hash detected", "https scheme has a hash-backed UserChoice entry; user-driven or policy updates are required")
		addFinding("W13", "warning", "UserChoice hash may trigger default reset messaging", "https scheme is hash-backed in UserChoice; users may need explicit reset flow after policy or repair operations")
	}

	return report, nil
}

func (p windowsProvider) DoctorFix(ctx context.Context, options DoctorFixOptions) (DoctorFixResult, error) {
	if !options.Browser {
		return DoctorFixResult{}, fmt.Errorf("Windows doctor fix currently requires --browser")
	}
	operations := []string{
		"Open Windows Settings > Apps > Default apps",
		"Set the intended browser for HTTP and HTTPS protocols",
		"Set the intended browser for .html, .htm, .xhtml, and .xht file extensions",
		"For managed devices, update default-association XML/CSP policy instead of editing UserChoice registry keys",
	}
	operations = appendFindingRemediationOperations(ctx, p, operations)
	if options.DryRun {
		return DoctorFixResult{Changed: false, Operations: operations}, nil
	}
	return DoctorFixResult{Operations: operations}, windowsUnsupportedOperation("doctor fix")
}

func (p windowsProvider) Set(_ context.Context, association Association, options SetOptions) (SetResult, error) {
	association = association.Normalized()
	if err := association.Validate(); err != nil {
		return SetResult{}, err
	}
	operations := windowsSetGuidanceOperations(association)
	if options.DryRun {
		return SetResult{Changed: false, Operations: operations}, nil
	}
	return SetResult{Operations: operations}, windowsUnsupportedOperation("set")
}

func (p windowsProvider) ResolveApp(ctx context.Context, query string, target Target) (AppResolution, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return AppResolution{}, fmt.Errorf("app is required")
	}
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return AppResolution{}, err
	}

	if !p.regAvailable() {
		return AppResolution{App: query, Source: "literal"}, nil
	}
	if p.hasAssocRegistration(ctx, query) {
		return AppResolution{App: query, Source: "Windows ProgID", Candidates: []string{query}}, nil
	}

	candidates := p.windowsRegisteredAppCandidates(ctx, query, target)
	if len(candidates) > 0 {
		if len(candidates) > 1 && candidates[0].score == candidates[1].score {
			return AppResolution{}, fmt.Errorf("app query %q is ambiguous on Windows; use an exact ProgID: %s", query, strings.Join(windowsRegisteredCandidateProgIDs(candidates), ", "))
		}
		return AppResolution{
			App:        candidates[0].progID,
			Source:     "Windows registered application",
			Candidates: windowsRegisteredCandidateProgIDs(candidates),
		}, nil
	}

	for _, progID := range windowsKnownBrowserProgIDs(query) {
		if p.hasAssocRegistration(ctx, progID) {
			return AppResolution{App: progID, Source: "known Windows browser alias", Candidates: []string{progID}}, nil
		}
	}
	if windowsLooksLikeProgID(query) {
		return AppResolution{App: query, Source: "literal ProgID"}, nil
	}
	return AppResolution{}, fmt.Errorf("could not resolve app query %q to a Windows registered application ProgID; use --app with an exact ProgID", query)
}

type windowsRegisteredAppCandidate struct {
	progID string
	score  int
}

func (p windowsProvider) windowsRegisteredAppCandidates(ctx context.Context, query string, target Target) []windowsRegisteredAppCandidate {
	type registeredRoot struct {
		key string
	}
	roots := []registeredRoot{
		{key: `HKCU\Software\RegisteredApplications`},
		{key: `HKLM\Software\RegisteredApplications`},
	}

	seen := map[string]struct{}{}
	var candidates []windowsRegisteredAppCandidate
	for _, root := range roots {
		registered, err := p.readRegValues(ctx, root.key)
		if err != nil {
			continue
		}
		for registeredName, capabilityPath := range registered {
			capabilityKey := windowsCapabilityKey(root.key, capabilityPath)
			if capabilityKey == "" {
				continue
			}
			capabilityValues, _ := p.readRegValues(ctx, capabilityKey)
			progID := p.windowsCapabilityProgID(ctx, capabilityKey, target)
			if progID == "" {
				continue
			}
			key := strings.ToLower(progID)
			if _, ok := seen[key]; ok {
				continue
			}
			score := windowsRegisteredAppScore(query, registeredName, capabilityKey, capabilityValues, progID)
			if score == 0 {
				continue
			}
			seen[key] = struct{}{}
			candidates = append(candidates, windowsRegisteredAppCandidate{progID: progID, score: score})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].progID < candidates[j].progID
	})
	return candidates
}

func windowsCapabilityKey(rootKey, capabilityPath string) string {
	capabilityPath = strings.TrimSpace(capabilityPath)
	if capabilityPath == "" {
		return ""
	}
	upper := strings.ToUpper(capabilityPath)
	switch {
	case strings.HasPrefix(upper, `HKCU\`), strings.HasPrefix(upper, `HKLM\`), strings.HasPrefix(upper, `HKEY_CURRENT_USER\`), strings.HasPrefix(upper, `HKEY_LOCAL_MACHINE\`):
		return capabilityPath
	case strings.HasPrefix(strings.ToUpper(rootKey), `HKCU\`), strings.HasPrefix(strings.ToUpper(rootKey), `HKEY_CURRENT_USER\`):
		return `HKCU\` + strings.TrimLeft(capabilityPath, `\`)
	case strings.HasPrefix(strings.ToUpper(rootKey), `HKLM\`), strings.HasPrefix(strings.ToUpper(rootKey), `HKEY_LOCAL_MACHINE\`):
		return `HKLM\` + strings.TrimLeft(capabilityPath, `\`)
	default:
		return ""
	}
}

type windowsCapabilityAssociationQuery struct {
	subkey string
	names  []string
}

func (p windowsProvider) windowsCapabilityProgID(ctx context.Context, capabilityKey string, target Target) string {
	for _, query := range windowsCapabilityAssociationQueries(target) {
		values, err := p.readRegValues(ctx, capabilityKey+`\`+query.subkey)
		if err != nil {
			continue
		}
		for _, name := range query.names {
			if value := windowsRegValue(values, name); value != "" {
				return value
			}
		}
	}
	return ""
}

func windowsCapabilityAssociationQueries(target Target) []windowsCapabilityAssociationQuery {
	switch target.Kind {
	case KindBrowser:
		return []windowsCapabilityAssociationQuery{
			{subkey: "URLAssociations", names: []string{"https", "http"}},
			{subkey: "MIMEAssociations", names: []string{"text/html", "application/xhtml+xml"}},
			{subkey: "FileAssociations", names: []string{".html", ".htm", ".xhtml", ".xht"}},
		}
	case KindScheme:
		return []windowsCapabilityAssociationQuery{{subkey: "URLAssociations", names: []string{target.Value}}}
	case KindMIME:
		queries := []windowsCapabilityAssociationQuery{{subkey: "MIMEAssociations", names: []string{target.Value}}}
		if extensions := mimeToExtensions(target.Value); len(extensions) > 0 {
			queries = append(queries, windowsCapabilityAssociationQuery{subkey: "FileAssociations", names: extensions})
		}
		return queries
	default:
		return nil
	}
}

func windowsRegisteredAppScore(query, registeredName, capabilityKey string, capabilityValues map[string]string, progID string) int {
	queryToken := windowsNormalizeAppToken(query)
	if queryToken == "" {
		return 0
	}
	fields := []string{
		registeredName,
		windowsRegValue(capabilityValues, "ApplicationName"),
		windowsRegValue(capabilityValues, "ApplicationDescription"),
		capabilityKey,
		progID,
	}
	score := 0
	for _, field := range fields {
		token := windowsNormalizeAppToken(field)
		if token == "" {
			continue
		}
		switch {
		case token == queryToken:
			if score < 900 {
				score = 900
			}
		case strings.HasPrefix(token, queryToken):
			if score < 700 {
				score = 700
			}
		case strings.Contains(token, queryToken):
			if score < 500 {
				score = 500
			}
		}
	}
	if score > 0 {
		score += 100
	}
	return score
}

func windowsRegValue(values map[string]string, name string) string {
	if values == nil {
		return ""
	}
	if value, ok := values[name]; ok {
		return strings.TrimSpace(value)
	}
	for key, value := range values {
		if strings.EqualFold(key, name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func windowsRegisteredCandidateProgIDs(candidates []windowsRegisteredAppCandidate) []string {
	limit := len(candidates)
	if limit > 5 {
		limit = 5
	}
	progIDs := make([]string, 0, limit)
	for _, candidate := range candidates[:limit] {
		progIDs = append(progIDs, candidate.progID)
	}
	return progIDs
}

func windowsKnownBrowserProgIDs(query string) []string {
	switch windowsNormalizeAppToken(query) {
	case "brave", "bravebrowser":
		return []string{"BraveHTML"}
	case "chrome", "googlechrome":
		return []string{"ChromeHTML"}
	case "edge", "microsoftedge":
		return []string{"MSEdgeHTM"}
	case "vivaldi":
		return []string{"VivaldiHTM"}
	default:
		return nil
	}
}

func windowsLooksLikeProgID(query string) bool {
	query = strings.TrimSpace(query)
	if query == "" {
		return false
	}
	lower := strings.ToLower(query)
	return query != lower || strings.Contains(query, ".") || strings.HasSuffix(lower, "html") || strings.HasSuffix(lower, "htm") || strings.HasSuffix(lower, "url")
}

func windowsNormalizeAppToken(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func (p windowsProvider) getBrowserDefault(ctx context.Context) (string, error) {
	https, err := p.getSchemeDefault(ctx, "https")
	if err == nil && https != "" {
		return https, nil
	}
	return p.getSchemeDefault(ctx, "http")
}

func (p windowsProvider) getSchemeDefault(ctx context.Context, scheme string) (string, error) {
	value, _, _, ok := bestAssociation(p.getSchemeAssociations(ctx, scheme))
	if !ok {
		return "", fmt.Errorf("no handler found for %q scheme", strings.TrimSpace(strings.ToLower(scheme)))
	}
	return value, nil
}

func (p windowsProvider) getMimeDefault(ctx context.Context, mime string) (string, error) {
	value := bestValue(p.getMimeAssociations(ctx, mime))
	if value == "" {
		return "", fmt.Errorf("no handler found for %q MIME", strings.TrimSpace(strings.ToLower(mime)))
	}
	return value, nil
}

func (p windowsProvider) getSchemeAssociations(ctx context.Context, scheme string) []associationEntry {
	scheme = strings.TrimSpace(strings.ToLower(scheme))
	if scheme == "" {
		return []associationEntry{{err: fmt.Errorf("empty scheme is not valid"), source: "unknown"}}
	}
	registry := []regKeySource{
		{
			source: "HKCU",
			path:   `HKCU\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\` + scheme + `\UserChoice`,
		},
		{
			source: "HKLM",
			path:   `HKLM\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\` + scheme + `\UserChoice`,
		},
	}
	return p.readAssociations(ctx, registry)
}

func (p windowsProvider) getMimeAssociations(ctx context.Context, mime string) []associationEntry {
	mime = strings.TrimSpace(strings.ToLower(mime))
	extensions := mimeToExtensions(mime)
	if len(extensions) == 0 {
		return []associationEntry{{
			err:    fmt.Errorf("no file extension mapping available for MIME %q", mime),
			source: "unknown",
			mime:   mime,
		}}
	}

	var result []associationEntry
	for _, extension := range extensions {
		keys := []regKeySource{
			{
				source: "HKCU",
				path:   `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\` + extension + `\UserChoice`,
			},
			{
				source: "HKLM",
				path:   `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\` + extension + `\UserChoice`,
			},
		}
		entries := p.readAssociations(ctx, keys)
		for i := range entries {
			entries[i].extension = extension
			if entries[i].mime == "" {
				entries[i].mime = mime
			}
		}
		result = append(result, entries...)
	}
	return result
}

func (p windowsProvider) readAssociations(ctx context.Context, keys []regKeySource) []associationEntry {
	entries := make([]associationEntry, 0, len(keys)*2)
	for _, key := range keys {
		values, err := p.readRegValues(ctx, key.path)
		if err != nil {
			entries = append(entries, associationEntry{
				source: key.source,
				err:    err,
			})
			continue
		}
		progID, progFound := values["ProgId"]
		if !progFound || strings.TrimSpace(progID) == "" {
			entries = append(entries, associationEntry{
				source: key.source,
				err:    fmt.Errorf("%s has no ProgId", key.path),
			})
			continue
		}
		entries = append(entries, associationEntry{
			source:  key.source,
			value:   progID,
			hasHash: strings.TrimSpace(values["Hash"]) != "",
			err:     nil,
		})
	}
	return entries
}

func (p windowsProvider) readAssocCommand(ctx context.Context, assoc string) (string, error) {
	assoc = strings.TrimSpace(assoc)
	if assoc == "" {
		return "", fmt.Errorf("empty association identifier")
	}
	keys := []regKeySource{
		{
			source: "HKCU",
			path:   `HKCU\Software\Classes\` + assoc + `\shell\open\command`,
		},
		{
			source: "HKLM",
			path:   `HKLM\Software\Classes\` + assoc + `\shell\open\command`,
		},
		{
			source: "HKCUApp",
			path:   `HKCU\Software\Classes\Applications\` + assoc + `\shell\open\command`,
		},
		{
			source: "HKLMApp",
			path:   `HKLM\Software\Classes\Applications\` + assoc + `\shell\open\command`,
		},
	}
	for _, key := range keys {
		values, err := p.readRegValues(ctx, key.path)
		if err != nil {
			continue
		}
		command, ok := values[""]
		if ok && strings.TrimSpace(command) != "" {
			return strings.TrimSpace(command), nil
		}
	}
	return "", fmt.Errorf("no executable command registration found in UserChoice-compatible locations")
}

func (p windowsProvider) readAssocDefaultIcon(ctx context.Context, assoc string) (string, error) {
	assoc = strings.TrimSpace(assoc)
	if assoc == "" {
		return "", fmt.Errorf("empty association identifier")
	}
	keys := []regKeySource{
		{
			path: `HKCU\Software\Classes\` + assoc + `\DefaultIcon`,
		},
		{
			path: `HKLM\Software\Classes\` + assoc + `\DefaultIcon`,
		},
		{
			path: `HKCU\Software\Classes\Applications\` + assoc + `\DefaultIcon`,
		},
		{
			path: `HKLM\Software\Classes\Applications\` + assoc + `\DefaultIcon`,
		},
	}
	for _, key := range keys {
		if values, err := p.readRegValues(ctx, key.path); err == nil {
			if icon, ok := values[""]; ok {
				icon = strings.TrimSpace(icon)
				if icon != "" {
					return icon, nil
				}
			}
			// fallback to first value if tool output is not using "(default)" consistently
			for _, value := range values {
				if strings.TrimSpace(value) != "" {
					return strings.TrimSpace(value), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no DefaultIcon value found in registry")
}

func (p windowsProvider) readAssocDefaultVerb(ctx context.Context, assoc string) (string, error) {
	assoc = strings.TrimSpace(assoc)
	if assoc == "" {
		return "", fmt.Errorf("empty association identifier")
	}
	keys := []regKeySource{
		{
			source: "HKCU",
			path:   `HKCU\Software\Classes\` + assoc + `\shell`,
		},
		{
			source: "HKLM",
			path:   `HKLM\Software\Classes\` + assoc + `\shell`,
		},
		{
			source: "HKCUApp",
			path:   `HKCU\Software\Classes\Applications\` + assoc + `\shell`,
		},
		{
			source: "HKLMApp",
			path:   `HKLM\Software\Classes\Applications\` + assoc + `\shell`,
		},
	}
	for _, key := range keys {
		values, err := p.readRegValues(ctx, key.path)
		if err == nil {
			if verb, ok := values[""]; ok && strings.TrimSpace(verb) != "" {
				return strings.TrimSpace(verb), nil
			}
		}
		if p.regKeyExists(ctx, key.path) {
			return "open", nil
		}
	}
	return "", fmt.Errorf("no shell key found in UserChoice-compatible locations")
}

func (p windowsProvider) readAssocCapabilities(ctx context.Context, assoc string) (bool, error) {
	assoc = strings.TrimSpace(assoc)
	if assoc == "" {
		return false, fmt.Errorf("empty association identifier")
	}

	paths := []regKeySource{
		{
			path: `HKCU\Software\Classes\` + assoc + `\Capabilities`,
		},
		{
			path: `HKLM\Software\Classes\` + assoc + `\Capabilities`,
		},
		{
			path: `HKCU\Software\Classes\Applications\` + assoc + `\Capabilities`,
		},
		{
			path: `HKLM\Software\Classes\Applications\` + assoc + `\Capabilities`,
		},
	}
	for _, pth := range paths {
		if _, err := p.readRegValues(ctx, pth.path); err == nil {
			return true, nil
		}
		if p.regKeyExists(ctx, pth.path) {
			return true, nil
		}
	}
	return false, fmt.Errorf("no capabilities block found in registry")
}

func (p windowsProvider) assocDeclaresTargetCapability(ctx context.Context, assoc string, target Target) (bool, error) {
	assoc = strings.TrimSpace(assoc)
	if assoc == "" {
		return false, fmt.Errorf("empty association identifier")
	}

	valueToMatch := strings.TrimSpace(target.Value)
	if valueToMatch == "" {
		return false, fmt.Errorf("empty target value")
	}

	type capabilityCheck struct {
		subkey string
		values map[string]struct{}
	}
	checks := []capabilityCheck{}
	valuesFor := func(values ...string) map[string]struct{} {
		result := map[string]struct{}{}
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value != "" {
				result[value] = struct{}{}
			}
		}
		return result
	}

	switch target.Kind {
	case KindScheme:
		checks = append(checks, capabilityCheck{subkey: "URLAssociations", values: valuesFor(valueToMatch)})
	case KindMIME:
		checks = append(checks, capabilityCheck{subkey: "MIMEAssociations", values: valuesFor(valueToMatch)})
		if extensions := mimeToExtensions(valueToMatch); len(extensions) > 0 {
			checks = append(checks, capabilityCheck{subkey: "FileAssociations", values: valuesFor(extensions...)})
		}
	default:
		return false, fmt.Errorf("unsupported target kind %q", target.Kind)
	}

	checkedAnyKey := false
	for _, check := range checks {
		if len(check.values) == 0 {
			continue
		}
		for _, value := range []string{
			fmt.Sprintf(`HKCU\Software\Classes\%s\Capabilities\%s`, assoc, check.subkey),
			fmt.Sprintf(`HKLM\Software\Classes\%s\Capabilities\%s`, assoc, check.subkey),
			fmt.Sprintf(`HKCU\Software\Classes\Applications\%s\Capabilities\%s`, assoc, check.subkey),
			fmt.Sprintf(`HKLM\Software\Classes\Applications\%s\Capabilities\%s`, assoc, check.subkey),
		} {
			values, err := p.readRegValues(ctx, value)
			if err == nil {
				checkedAnyKey = true
				for keyName := range values {
					if _, ok := check.values[strings.ToLower(strings.TrimSpace(keyName))]; ok {
						return true, nil
					}
				}
				continue
			}
			if p.regKeyExists(ctx, value) {
				checkedAnyKey = true
			}
		}
	}

	if checkedAnyKey {
		return false, nil
	}
	return false, fmt.Errorf("no capability mapping key found for %q (%s)", assoc, strings.TrimSpace(valueToMatch))
}

func (p windowsProvider) hasAssocRegistration(ctx context.Context, assoc string) bool {
	assoc = strings.TrimSpace(assoc)
	if assoc == "" {
		return false
	}

	for _, value := range []string{
		fmt.Sprintf(`HKCU\Software\Classes\%s`, assoc),
		fmt.Sprintf(`HKLM\Software\Classes\%s`, assoc),
		fmt.Sprintf(`HKCU\Software\Classes\Applications\%s`, assoc),
		fmt.Sprintf(`HKLM\Software\Classes\Applications\%s`, assoc),
	} {
		if p.regKeyExists(ctx, value) {
			return true
		}
	}
	return false
}

func (p windowsProvider) currentAssociationPolicySignals(ctx context.Context) []string {
	keys := []string{
		`HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`,
		`HKLM\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`,
	}
	valueNames := []string{"Associations", "AssociationsFile", "DefaultAssociationsConfiguration"}
	var findings []string
	for _, key := range keys {
		values, err := p.readRegValues(ctx, key)
		if err != nil {
			if !p.regKeyExists(ctx, key) {
				continue
			}
			findings = append(findings, fmt.Sprintf("%s policy key exists with no readable values", key))
			continue
		}
		matched := false
		for _, valueName := range valueNames {
			value, ok := values[valueName]
			if !ok {
				continue
			}
			matched = true
			value = strings.TrimSpace(value)
			if value == "" {
				findings = append(findings, fmt.Sprintf("%s policy key has empty %q value", key, valueName))
				continue
			}
			findings = append(findings, fmt.Sprintf("%s policy key advertises %q=%q", key, valueName, value))
		}
		if !matched {
			findings = append(findings, fmt.Sprintf("%s policy key exists but no policy value matched expected names", key))
		}
	}
	return findings
}

func (p windowsProvider) policyAssociationSignals(ctx context.Context) (missing []string, issues []string, mandatory bool) {
	records, issues := p.windowsPolicyAssociationRecordSet(ctx)
	return p.policyAssociationSignalsFromRecords(records, issues)
}

func (p windowsProvider) policyAssociationSignalsFromRecords(records []windowsPolicyAssociationRecord, issues []string) (missing []string, sortedIssues []string, mandatory bool) {
	requiredTargets := map[string]struct{}{}
	for _, target := range windowsRequiredPolicyTargets() {
		requiredTargets[target] = struct{}{}
	}
	configuredTargets := map[string]struct{}{}
	for _, record := range records {
		targets := mapWindowsPolicyIdentifierToTargets(record.identifier)
		for _, target := range targets {
			configuredTargets[target] = struct{}{}
			if _, ok := requiredTargets[target]; ok && (!record.suggestedSet || !record.suggested) {
				mandatory = true
			}
		}
	}
	for target := range requiredTargets {
		if _, ok := configuredTargets[target]; ok {
			continue
		}
		missing = append(missing, target)
	}
	sort.Strings(missing)
	seen := map[string]struct{}{}
	for _, issue := range issues {
		issue = strings.TrimSpace(issue)
		if issue == "" {
			continue
		}
		key := strings.ToLower(issue)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		sortedIssues = append(sortedIssues, issue)
	}
	sort.Strings(sortedIssues)
	return missing, sortedIssues, mandatory
}

func windowsRequiredPolicyTargets() []string {
	targets := []string{"http", "https", "text/html", "application/xhtml+xml"}
	if callbackScheme := normalizeCallbackScheme(os.Getenv("DFX_CALLBACK_SCHEME")); callbackScheme != "" {
		for _, target := range targets {
			if target == callbackScheme {
				return targets
			}
		}
		targets = append(targets, callbackScheme)
	}
	return targets
}

func (p windowsProvider) windowsPolicyAssociationRecordSet(ctx context.Context) ([]windowsPolicyAssociationRecord, []string) {
	keys := []string{
		`HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`,
		`HKLM\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`,
	}
	valueNames := []string{"Associations", "AssociationsFile", "DefaultAssociationsConfiguration"}
	rawValues := []struct {
		source string
		value  string
	}{}
	for _, key := range keys {
		values, err := p.readRegValues(ctx, key)
		if err != nil {
			continue
		}
		for _, valueName := range valueNames {
			value, ok := values[valueName]
			if !ok {
				continue
			}
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			rawValues = append(rawValues, struct {
				source string
				value  string
			}{
				source: fmt.Sprintf("%s/%s", key, valueName),
				value:  trimmed,
			})
		}
	}

	seenProblem := map[string]struct{}{}
	problemMessages := []string{}
	addProblem := func(source, message string) {
		source = strings.TrimSpace(source)
		message = strings.TrimSpace(message)
		if source == "" || message == "" {
			return
		}
		key := strings.ToLower(source + ":" + message)
		if _, ok := seenProblem[key]; ok {
			return
		}
		seenProblem[key] = struct{}{}
		problemMessages = append(problemMessages, message)
	}

	records := make([]windowsPolicyAssociationRecord, 0, len(rawValues)*2)
	for _, item := range rawValues {
		raw := normalizeWindowsPolicyAssociationXMLText(item.value)
		if raw == "" {
			continue
		}
		if strings.HasPrefix(raw, "<") {
			parsed, err := windowsPolicyAssociationMetadataFromXMLSource([]byte(raw))
			if err != nil {
				addProblem(item.source, "policy associations could not be parsed from inline XML: "+err.Error())
				continue
			}
			records = append(records, parsed...)
			continue
		}
		for _, path := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			path = strings.Trim(path, `"`)
			path = strings.TrimSpace(path)
			if path == "" {
				continue
			}
			resolved := strings.TrimSpace(expandWindowsEnvPath(path))
			if resolved == "" {
				resolved = path
			}
			content, err := os.ReadFile(resolved)
			if err != nil {
				addProblem(item.source, fmt.Sprintf("policy associations source not readable: %s: %v", resolved, err))
				continue
			}
			parsed, err := windowsPolicyAssociationMetadataFromXMLSource(content)
			if err != nil {
				addProblem(item.source, fmt.Sprintf("policy association XML parse failed: %s: %v", resolved, err))
				continue
			}
			records = append(records, parsed...)
		}
	}

	dedup := make([]windowsPolicyAssociationRecord, 0, len(records))
	seenRecord := map[string]struct{}{}
	for _, record := range records {
		recordKey := windowsPolicyAssociationRecordKey(record)
		if recordKey == "" {
			continue
		}
		if _, ok := seenRecord[recordKey]; ok {
			continue
		}
		seenRecord[recordKey] = struct{}{}
		dedup = append(dedup, record)
	}
	sort.SliceStable(dedup, func(i, j int) bool {
		return windowsPolicyAssociationRecordKey(dedup[i]) < windowsPolicyAssociationRecordKey(dedup[j])
	})
	sort.Strings(problemMessages)
	return dedup, problemMessages
}

func normalizeWindowsPolicyAssociationXMLText(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "\ufeff")
}

func expandWindowsEnvPath(raw string) string {
	expanded := os.ExpandEnv(strings.TrimSpace(raw))
	if expanded == "" {
		return ""
	}

	var out strings.Builder
	for i := 0; i < len(expanded); {
		if expanded[i] != '%' {
			out.WriteByte(expanded[i])
			i++
			continue
		}
		end := strings.IndexByte(expanded[i+1:], '%')
		if end == -1 {
			out.WriteByte(expanded[i])
			i++
			continue
		}
		name := expanded[i+1 : i+1+end]
		if value, ok := lookupWindowsEnv(name); ok {
			out.WriteString(value)
			i += end + 2
			continue
		}
		out.WriteString(expanded[i : i+end+2])
		i += end + 2
	}
	return strings.TrimSpace(out.String())
}

func lookupWindowsEnv(name string) (string, bool) {
	if value, ok := os.LookupEnv(name); ok {
		return value, true
	}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

func (p windowsProvider) windowsPolicyAssociationProgIDSignals(ctx context.Context, records []windowsPolicyAssociationRecord, current map[string]string) []string {
	policyByTarget := make(map[string]map[string]struct{})
	for _, record := range records {
		progID := strings.ToLower(strings.TrimSpace(record.progID))
		if progID == "" {
			continue
		}
		for _, target := range mapWindowsPolicyIdentifierToTargets(record.identifier) {
			target = strings.ToLower(strings.TrimSpace(target))
			if target == "" {
				continue
			}
			values, ok := policyByTarget[target]
			if !ok {
				values = map[string]struct{}{}
				policyByTarget[target] = values
			}
			values[progID] = struct{}{}
		}
	}

	signals := []string{}
	seen := map[string]struct{}{}
	addSignal := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" {
			return
		}
		key := strings.ToLower(message)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		signals = append(signals, message)
	}

	for target, configuredValues := range policyByTarget {
		currentValue := strings.TrimSpace(current[target])
		if currentValue == "" || len(configuredValues) == 0 {
			continue
		}
		if _, ok := configuredValues[strings.ToLower(currentValue)]; ok {
			continue
		}

		staleConfigured := []string{}
		for configuredProgID := range configuredValues {
			if strings.TrimSpace(configuredProgID) == "" {
				continue
			}
			if p.hasAssocRegistration(ctx, configuredProgID) {
				continue
			}
			staleConfigured = append(staleConfigured, configuredProgID)
		}
		if len(staleConfigured) == 0 {
			continue
		}
		sort.Strings(staleConfigured)
		addSignal(fmt.Sprintf(`%s policy ProgID(s) %s do not resolve, current mapping is %q`, target, strings.Join(staleConfigured, ", "), currentValue))
	}

	sort.Strings(signals)
	return signals
}

func windowsPolicyAssociationOverrideSignals(records []windowsPolicyAssociationRecord, current map[string]string) []string {
	policyByTarget := make(map[string]map[string]string)
	for _, record := range records {
		progID := strings.TrimSpace(record.progID)
		if progID == "" {
			continue
		}
		for _, target := range mapWindowsPolicyIdentifierToTargets(record.identifier) {
			target = strings.ToLower(strings.TrimSpace(target))
			if target == "" {
				continue
			}
			values, ok := policyByTarget[target]
			if !ok {
				values = map[string]string{}
				policyByTarget[target] = values
			}
			values[strings.ToLower(progID)] = progID
		}
	}

	signals := []string{}
	for target, policyValues := range policyByTarget {
		currentValue := strings.TrimSpace(current[target])
		if currentValue == "" || len(policyValues) == 0 {
			continue
		}
		if _, ok := policyValues[strings.ToLower(currentValue)]; ok {
			continue
		}
		values := make([]string, 0, len(policyValues))
		for _, value := range policyValues {
			values = append(values, value)
		}
		sort.Strings(values)
		signals = append(signals, fmt.Sprintf(`%s policy ProgID(s) %s differ from current mapping %q`, target, strings.Join(values, ", "), currentValue))
	}
	sort.Strings(signals)
	return signals
}

func (p windowsProvider) windowsFeatureUpdateResetSignals(ctx context.Context) []string {
	signals := []string{}
	seen := map[string]struct{}{}
	addSignal := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" {
			return
		}
		if _, ok := seen[message]; ok {
			return
		}
		seen[message] = struct{}{}
		signals = append(signals, message)
	}

	pendingValueChecks := []struct {
		key       string
		valueName string
	}{
		{key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Component Based Servicing\RebootPending`, valueName: ""},
		{key: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Component Based Servicing\RebootInProgress`, valueName: ""},
		{key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, valueName: ""},
		{key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\OSUpgrade`, valueName: ""},
	}
	for _, check := range pendingValueChecks {
		if !p.regKeyExists(ctx, check.key) {
			continue
		}
		if check.valueName == "" {
			addSignal(check.key)
			continue
		}
		values, err := p.readRegValues(ctx, check.key)
		if err != nil {
			continue
		}
		if value, ok := values[check.valueName]; ok {
			addSignal(fmt.Sprintf("%s=%q", check.key, value))
		}
	}

	stateChecks := []string{
		`HKLM\SYSTEM\Setup\MoSetup`,
		`HKLM\SYSTEM\Setup\State`,
	}
	for _, key := range stateChecks {
		values, err := p.readRegValues(ctx, key)
		if err != nil {
			continue
		}
		state, ok := values["ImageState"]
		if !ok {
			continue
		}
		state = strings.ToLower(strings.TrimSpace(state))
		if state != "" && !strings.Contains(state, "complete") {
			addSignal(fmt.Sprintf(`%s ImageState=%q`, key, state))
		}
	}

	sort.Strings(signals)
	return signals
}

func (p windowsProvider) windowsBrowserRepairSignals(ctx context.Context) []string {
	runKeys := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`,
		`HKCU\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunServices`,
	}
	signals := []string{}
	seen := map[string]struct{}{}
	addSignal := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" {
			return
		}
		if _, ok := seen[message]; ok {
			return
		}
		seen[message] = struct{}{}
		signals = append(signals, message)
	}
	for _, key := range runKeys {
		values, err := p.readRegValues(ctx, key)
		if err != nil {
			continue
		}
		for name, value := range values {
			record := fmt.Sprintf(`%s\%s=%q`, key, name, value)
			if p.windowsBrowserRepairToolSignal(name, value, record) {
				addSignal(record)
			}
		}
	}
	sort.Strings(signals)
	return signals
}

func (p windowsProvider) windowsBrowserRepairToolSignal(entryName, entryValue, fallbackRecord string) bool {
	name := strings.ToLower(strings.TrimSpace(entryName))
	value := strings.ToLower(strings.TrimSpace(entryValue))
	fallback := strings.ToLower(strings.TrimSpace(fallbackRecord))
	if name == "" && value == "" && fallback == "" {
		return false
	}
	repairHints := []string{
		"set-default-browser",
		"setdefaultbrowser",
		"default-browser",
		"set-default",
		"setdefault",
		"make-default",
		"makedefault",
		"set user",
		"set-user",
		"setuser",
		"set as default",
		"set-as-default",
		"set default",
		"reset-default",
		"resetdefault",
		"repair",
		"re-register",
		"restore default",
	}
	vendorHints := []string{
		"chrome",
		"chromium",
		"google",
		"edge",
		"msedge",
		"firefox",
		"mozilla",
		"brave",
		"opera",
		"vivaldi",
		"iexplore",
		"internetexplorer",
		"safari",
		"setuserfta",
		"defaultbrowser",
		"default browser",
	}
	isDefaultBrowserPhrase := func(text string) bool {
		if text == "" {
			return false
		}
		return strings.Contains(text, "default") && strings.Contains(text, "browser")
	}

	hasRepairHint := false
	for _, hint := range repairHints {
		if strings.Contains(name, hint) || strings.Contains(value, hint) {
			hasRepairHint = true
			break
		}
	}
	if !hasRepairHint {
		for _, hint := range repairHints {
			if strings.Contains(fallback, hint) {
				hasRepairHint = true
				break
			}
		}
	}
	if !hasRepairHint {
		return false
	}

	hasVendorHint := false
	for _, hint := range vendorHints {
		if strings.Contains(name, hint) || strings.Contains(value, hint) {
			hasVendorHint = true
			break
		}
	}
	if !hasVendorHint {
		for _, hint := range vendorHints {
			if strings.Contains(fallback, hint) {
				hasVendorHint = true
				break
			}
		}
	}
	if !hasVendorHint {
		if isDefaultBrowserPhrase(name) || isDefaultBrowserPhrase(value) || isDefaultBrowserPhrase(fallback) {
			return true
		}
		return false
	}

	return true
}

func (p windowsProvider) windowsDefaultAppsHardeningSignals(ctx context.Context) []string {
	signals := []string{}
	seen := map[string]struct{}{}
	addSignal := func(message string) {
		message = strings.TrimSpace(message)
		if message == "" {
			return
		}
		if _, ok := seen[message]; ok {
			return
		}
		seen[message] = struct{}{}
		signals = append(signals, message)
	}

	pathValueChecks := []struct {
		key   string
		value string
	}{
		{key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, value: "SettingsPageVisibility"},
		{key: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, value: "SettingsPageVisibility"},
		{key: `HKCU\Software\Policies\Microsoft\Windows\Explorer`, value: "NoNewAppAlert"},
		{key: `HKLM\Software\Policies\Microsoft\Windows\Explorer`, value: "NoNewAppAlert"},
		{key: `HKCU\Software\Policies\Microsoft\Windows\Explorer`, value: "NoOpenWith"},
		{key: `HKLM\Software\Policies\Microsoft\Windows\Explorer`, value: "NoOpenWith"},
		{key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, value: "NoInternetOpenWith"},
		{key: `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`, value: "NoInternetOpenWith"},
	}
	for _, check := range pathValueChecks {
		values, err := p.readRegValues(ctx, check.key)
		if err != nil {
			continue
		}
		raw, ok := values[check.value]
		if !ok {
			continue
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		if check.value == "SettingsPageVisibility" {
			if windowsSettingsPageVisibilityRestrictsDefaultApps(raw) {
				addSignal(fmt.Sprintf("Settings visibility policy in %s=%q", check.key, raw))
			}
			continue
		}
		if isPolicyValueEnabled(raw) {
			addSignal(fmt.Sprintf("%s\\%s=%q", check.key, check.value, raw))
		}
	}

	sort.Strings(signals)
	return signals
}

func windowsLegacyToolsAvailable(p windowsProvider) []string {
	tools := []string{"assoc", "ftype"}
	found := make([]string, 0, len(tools))
	for _, tool := range tools {
		if p.runnerOrDefaultHas(tool) {
			found = append(found, tool)
		}
	}
	sort.Strings(found)
	return found
}

func isPolicyValueEnabled(raw string) bool {
	value := strings.TrimSpace(strings.ToLower(raw))
	value = strings.Trim(value, `"'`)
	if value == "" {
		return false
	}
	switch strings.Fields(value)[0] {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	value = strings.Fields(strings.TrimSpace(value))[0]
	parsed, err := strconv.ParseInt(value, 0, 64)
	return err == nil && parsed != 0
}

func windowsSettingsPageVisibilityRestrictsDefaultApps(raw string) bool {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.Trim(normalized, " ")
	normalized = strings.Trim(normalized, `"`)
	normalized = strings.ReplaceAll(normalized, " ", "")
	if normalized == "" {
		return false
	}

	pageMatchesDefaultApps := func(page string) bool {
		switch strings.TrimSpace(page) {
		case "defaultapps", "default-apps":
			return true
		default:
			return false
		}
	}
	parsePages := func(prefix string) []string {
		rest := strings.TrimPrefix(normalized, prefix)
		return strings.FieldsFunc(rest, func(r rune) bool { return r == ';' || r == ',' })
	}

	if strings.HasPrefix(normalized, "hide:") {
		for _, page := range parsePages("hide:") {
			if pageMatchesDefaultApps(page) {
				return true
			}
		}
		return false
	}

	if !strings.HasPrefix(normalized, "showonly:") {
		return false
	}

	pages := parsePages("showonly:")
	visible := make(map[string]struct{}, len(pages))
	for _, page := range pages {
		page = strings.TrimSpace(strings.ToLower(strings.TrimSpace(page)))
		if page != "" {
			visible[page] = struct{}{}
		}
	}
	_, hasDefaultApps := visible["defaultapps"]
	_, hasDefaultAppsDashed := visible["default-apps"]
	return !hasDefaultApps && !hasDefaultAppsDashed
}

func windowsPolicyAssociationMetadataFromXMLSource(content []byte) ([]windowsPolicyAssociationRecord, error) {
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	content = bytes.TrimSpace(content)
	records := make([]windowsPolicyAssociationRecord, 0, 16)
	decoder := xml.NewDecoder(bytes.NewReader(content))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return records, nil
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "Association") {
			continue
		}
		association := struct {
			Identifier string `xml:"Identifier,attr"`
			Suggested  string `xml:"Suggested,attr"`
			ProgID1    string `xml:"ProgId,attr"`
			ProgID2    string `xml:"ProgID,attr"`
		}{}
		if err := decoder.DecodeElement(&association, &start); err != nil {
			return nil, err
		}
		identifier := strings.TrimSpace(strings.ToLower(association.Identifier))
		if identifier == "" {
			continue
		}
		progID := strings.TrimSpace(association.ProgID1)
		if progID == "" {
			progID = strings.TrimSpace(association.ProgID2)
		}
		suggestedSet, suggested := windowsPolicyAssociationSuggested(association.Suggested)
		records = append(records, windowsPolicyAssociationRecord{
			identifier:   identifier,
			suggestedSet: suggestedSet,
			suggested:    suggested,
			progID:       progID,
		})
	}
	return records, nil
}

func windowsPolicyAssociationRecordKey(record windowsPolicyAssociationRecord) string {
	return strings.ToLower(strings.TrimSpace(record.identifier)) + "|" + strings.TrimSpace(record.progID) + "|" + strconv.FormatBool(record.suggestedSet) + "|" + strconv.FormatBool(record.suggested)
}

type windowsPolicyAssociationRecord struct {
	identifier   string
	progID       string
	suggestedSet bool
	suggested    bool
}

func windowsPolicyAssociationSuggested(raw string) (set bool, value bool) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return true, false
	default:
		return false, false
	}
}

func windowsPolicyTargetsFromXMLSource(content []byte, source string) ([]string, error) {
	records, err := windowsPolicyAssociationMetadataFromXMLSource(content)
	if err != nil {
		if strings.TrimSpace(source) != "" {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		return nil, err
	}
	targets := map[string]struct{}{}
	for _, record := range records {
		identifier := strings.TrimSpace(record.identifier)
		if identifier == "" {
			continue
		}
		for _, target := range mapWindowsPolicyIdentifierToTargets(identifier) {
			targets[target] = struct{}{}
		}
	}
	result := make([]string, 0, len(targets))
	for target := range targets {
		result = append(result, target)
	}
	sort.Strings(result)
	return result, nil
}

func mapWindowsPolicyIdentifierToTargets(identifier string) []string {
	identifier = strings.TrimSpace(strings.ToLower(identifier))
	if identifier == "" {
		return nil
	}
	if strings.HasPrefix(identifier, ".") {
		switch identifier {
		case ".html", ".htm":
			return []string{"text/html"}
		case ".xhtml", ".xht":
			return []string{"application/xhtml+xml"}
		default:
			return nil
		}
	}
	switch identifier {
	case "http", "https", "text/html", "application/xhtml+xml":
		return []string{identifier}
	default:
		if validURLScheme(identifier) {
			return []string{identifier}
		}
		return nil
	}
}

func hasUsableAssociationFromSource(entries []associationEntry, source string) bool {
	targetSource := strings.TrimSpace(strings.ToUpper(source))
	if targetSource == "" {
		return false
	}
	for _, entry := range entries {
		if entry.err != nil {
			continue
		}
		if strings.TrimSpace(entry.value) == "" {
			continue
		}
		if strings.TrimSpace(strings.ToUpper(entry.source)) == targetSource {
			return true
		}
	}
	return false
}

func windowsRemoteSessionSignals() []string {
	signals := []string{}
	sessionName := strings.TrimSpace(os.Getenv("SESSIONNAME"))
	if sessionName != "" {
		upper := strings.ToUpper(sessionName)
		if upper == "RDP-Tcp" || strings.HasPrefix(upper, "RDP-") {
			signals = append(signals, "SESSIONNAME="+sessionName)
		}
	}
	if client := strings.TrimSpace(os.Getenv("CLIENTNAME")); client != "" {
		signals = append(signals, "CLIENTNAME="+client)
	}
	if remote := strings.TrimSpace(os.Getenv("REMOTEAPP")); remote != "" {
		signals = append(signals, "REMOTEAPP="+remote)
	}
	if winStation := strings.TrimSpace(os.Getenv("SESSIONTYPE")); winStation != "" {
		signals = append(signals, "SESSIONTYPE="+winStation)
	}
	return signals
}

func isLikelyAppContainerHandler(handler string) bool {
	value := strings.ToLower(strings.TrimSpace(handler))
	if value == "" {
		return false
	}
	markers := []string{
		".appx", "appx", "uwp", "windows.store", "windowsapps", "windows.store", "store:", "windowsapp",
	}
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func hasLikely32BitExecutableMarker(command string) bool {
	normalized := strings.ToLower(strings.TrimSpace(command))
	markers := []string{
		`program files (x86)`,
		`%programfiles(x86)%`,
		`%programfiles(x86)`,
		`%pf(x86)%`,
	}
	for _, marker := range markers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func checkFamilyDivergence(entries []associationEntry, extensions []string) string {
	if len(extensions) == 0 {
		return ""
	}
	mapped := map[string]string{}
	for _, entry := range entries {
		ext := strings.TrimSpace(entry.extension)
		if ext == "" || entry.err != nil {
			continue
		}
		value := strings.TrimSpace(entry.value)
		if value == "" {
			continue
		}
		mapped[ext] = value
	}
	parts := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		if value, ok := mapped[extension]; ok {
			parts = append(parts, fmt.Sprintf(`%s=%q`, extension, value))
			continue
		}
		parts = append(parts, fmt.Sprintf(`%s=%s`, extension, "missing"))
	}
	if len(mapped) == 0 || len(parts) == 0 {
		return ""
	}
	values := map[string]struct{}{}
	for _, value := range mapped {
		values[value] = struct{}{}
	}
	if len(mapped) < len(extensions) || len(values) > 1 {
		parts = append(parts, fmt.Sprintf("mapped=%d/%d", len(mapped), len(extensions)))
		return strings.Join(parts, "; ")
	}
	return ""
}

func associationCandidateSummary(entries []associationEntry) []string {
	raw := map[string][]string{}
	for _, entry := range entries {
		if entry.err != nil {
			continue
		}
		value := strings.TrimSpace(entry.value)
		if value == "" {
			continue
		}
		source := strings.TrimSpace(entry.source)
		if source == "" {
			source = "unknown"
		}
		sources, ok := raw[value]
		if !ok {
			raw[value] = []string{source}
			continue
		}
		exists := false
		for _, existing := range sources {
			if strings.EqualFold(existing, source) {
				exists = true
				break
			}
		}
		if !exists {
			raw[value] = append(raw[value], source)
		}
	}
	if len(raw) <= 1 {
		return nil
	}
	items := make([]string, 0, len(raw))
	for value, sources := range raw {
		sort.Strings(sources)
		items = append(items, fmt.Sprintf("%s via %s", value, strings.Join(sources, ", ")))
	}
	sort.Strings(items)
	return items
}

func inferWindowsHandlerBrowserChannel(handler, command string) (string, string) {
	family, channel := inferWindowsHandlerChannelFromIdentifier(handler)
	if channel == "" {
		channel = inferWindowsHandlerChannelFromCommand(command)
	}
	if channel == "" {
		channel = "stable"
	}
	return family, channel
}

func inferWindowsHandlerChannelFromIdentifier(value string) (string, string) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", ""
	}
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '.' || r == '-' || r == '_' || r == ' '
	})
	channel := ""
	for i := len(parts) - 1; i > 0; i-- {
		switch strings.TrimSpace(parts[i]) {
		case "canary", "beta", "dev", "nightly", "preview", "alpha", "stable":
			channel = strings.TrimSpace(parts[i])
			parts = parts[:i]
			break
		}
	}
	family := strings.Join(parts, ".")
	if family == "" {
		return normalized, channel
	}
	return family, channel
}

func inferWindowsHandlerChannelFromCommand(command string) string {
	normalized := strings.ToLower(strings.TrimSpace(command))
	if normalized == "" {
		return ""
	}
	for _, channel := range []string{"canary", "beta", "dev", "nightly", "preview", "alpha"} {
		if strings.Contains(normalized, channel) {
			return channel
		}
	}
	return ""
}

func supportsURIPayload(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	if command == "" {
		return false
	}
	return strings.Contains(command, "%1") || strings.Contains(command, "%u") || strings.Contains(command, "%l") || strings.Contains(command, "%*")
}

func (p windowsProvider) regKeyExists(ctx context.Context, key string) bool {
	output, err := p.runnerOrDefault().Run(ctx, "reg", "query", key)
	if err != nil {
		return false
	}
	return strings.TrimSpace(output) != ""
}

func (p windowsProvider) readRegValues(ctx context.Context, key string) (map[string]string, error) {
	output, err := p.runnerOrDefault().Run(ctx, "reg", "query", key)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) < 3 {
			continue
		}
		if strings.EqualFold(parts[0], "HKEY_CURRENT_USER") || strings.EqualFold(parts[0], "HKEY_LOCAL_MACHINE") {
			continue
		}
		typeIndex := -1
		for i, part := range parts {
			if strings.HasPrefix(strings.ToUpper(part), "REG_") {
				typeIndex = i
				break
			}
		}
		if typeIndex <= 0 || typeIndex >= len(parts)-1 {
			continue
		}
		valueName := strings.TrimSpace(strings.Trim(strings.Join(parts[:typeIndex], " "), `"`))
		if strings.EqualFold(valueName, "(default)") || strings.EqualFold(valueName, "(Default)") {
			valueName = ""
		}
		values[valueName] = strings.Join(parts[typeIndex+1:], " ")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no values found in %s", key)
	}
	return values, nil
}

func (p windowsProvider) regAvailable() bool {
	return p.runnerOrDefaultHas("reg")
}

func (p windowsProvider) runnerOrDefault() commandRunner {
	if p.runner != nil {
		return p.runner
	}
	return execRunner{}
}

func (p windowsProvider) runnerOrDefaultHas(name string) bool {
	_, err := p.runnerOrDefault().LookPath(name)
	return err == nil
}

func bestAssociation(entries []associationEntry) (value string, source string, hasHash bool, ok bool) {
	for _, entry := range entries {
		if entry.err != nil {
			continue
		}
		if strings.TrimSpace(entry.value) == "" {
			continue
		}
		return entry.value, entry.source, entry.hasHash, true
	}
	return "", "", false, false
}

func bestValue(entries []associationEntry) string {
	value, _, _, ok := bestAssociation(entries)
	if !ok {
		return ""
	}
	return value
}

func firstError(entries []associationEntry) error {
	reasons := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.err == nil && entry.value != "" {
			return nil
		}
		if entry.err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: %v", entry.source, entry.err))
		}
	}
	if len(reasons) > 0 {
		return fmt.Errorf("no usable registry association found: %s", strings.Join(reasons, "; "))
	}
	return nil
}

func isDiverged(entries []associationEntry) bool {
	values := make(map[string]int)
	for _, entry := range entries {
		if entry.err != nil || entry.value == "" {
			continue
		}
		values[entry.value]++
	}
	sourcesCount := 0
	if len(values) > 1 {
		for _, count := range values {
			sourcesCount += count
		}
		return sourcesCount >= 2
	}
	return false
}

func mimeToExtensions(mime string) []string {
	switch strings.TrimSpace(strings.ToLower(mime)) {
	case "text/html":
		return []string{".html", ".htm"}
	case "application/xhtml+xml":
		return []string{".xhtml", ".xht"}
	case "text/plain":
		return []string{".txt"}
	default:
		return nil
	}
}

func windowsSetGuidanceOperations(association Association) []string {
	targets := windowsTargetsForAssociation(association.Target())
	operations := make([]string, 0, len(targets)+2)
	xmlRecords := make([]string, 0, len(targets)*2)
	app := windowsXMLAttributeEscape(association.App)
	for _, target := range targets {
		switch target.Kind {
		case KindScheme:
			operations = append(operations, fmt.Sprintf("Plan Default apps protocol assignment: %s -> %s", strings.ToUpper(target.Value), association.App))
			xmlRecords = append(xmlRecords, fmt.Sprintf(`<Association Identifier="%s" ProgId="%s" ApplicationName="%s" />`, windowsXMLAttributeEscape(target.Value), app, app))
		case KindMIME:
			if extensions := mimeToExtensions(target.Value); len(extensions) > 0 {
				for _, extension := range extensions {
					operations = append(operations, fmt.Sprintf("Plan Default apps file-extension assignment: %s -> %s", extension, association.App))
					xmlRecords = append(xmlRecords, fmt.Sprintf(`<Association Identifier="%s" ProgId="%s" ApplicationName="%s" />`, windowsXMLAttributeEscape(extension), app, app))
				}
				continue
			}
			operations = append(operations, fmt.Sprintf("Plan Default apps MIME-equivalent assignment: %s -> %s", target.Value, association.App))
		}
	}
	if len(xmlRecords) > 0 {
		operations = append(operations, "Policy XML template:")
		operations = append(operations, "<DefaultAssociations>")
		for _, record := range xmlRecords {
			operations = append(operations, "  "+record)
		}
		operations = append(operations, "</DefaultAssociations>")
	}
	operations = append(operations, "Do not edit UserChoice registry keys directly; Windows protects them with per-user hashes and may reject or reset forced values")
	operations = append(operations, "Apply through Windows Settings > Apps > Default apps or enterprise default-association XML/CSP policy")
	return operations
}

func windowsXMLAttributeEscape(value string) string {
	replacer := strings.NewReplacer(
		`&`, `&amp;`,
		`<`, `&lt;`,
		`>`, `&gt;`,
		`"`, `&quot;`,
		`'`, `&apos;`,
	)
	return replacer.Replace(value)
}

func windowsTargetsForAssociation(target Target) []Target {
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

func windowsUnsupportedOperation(operation string) error {
	return fmt.Errorf("Windows %s support is not implemented for safe writes here because UserChoice assignments are hash-protected; use Windows Settings > Apps > Default apps or enterprise default-association XML/CSP policy instead of direct registry edits", operation)
}

func uniqueStrings(values ...string) []string {
	seen := map[string]struct{}{}
	ordered := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		ordered = append(ordered, value)
	}
	return ordered
}

type regKeySource struct {
	source string
	path   string
}

type associationEntry struct {
	source    string
	value     string
	hasHash   bool
	err       error
	mime      string
	extension string
}
