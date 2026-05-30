package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/LukasParke/dfx/internal/defaults"
)

type profile struct {
	Defaults []defaults.Association `json:"defaults"`
}

type profileValidationReport struct {
	Path     string                 `json:"path,omitempty"`
	Valid    bool                   `json:"valid"`
	Count    int                    `json:"count"`
	Defaults []defaults.Association `json:"defaults,omitempty"`
}

type openTestReport struct {
	Target      defaults.Target `json:"target"`
	ActualApp   string          `json:"actual_app,omitempty"`
	ExpectedApp string          `json:"expected_app,omitempty"`
	Matched     *bool           `json:"matched,omitempty"`
	Launched    bool            `json:"launched"`
	Launch      *openTestLaunch `json:"launch,omitempty"`
	Evidence    []string        `json:"evidence,omitempty"`
	Notes       []string        `json:"notes,omitempty"`
}

type openTestLaunch struct {
	Subject string   `json:"subject"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

var runOpenTestLauncher = defaultOpenTestLauncher

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	wantsJSON := false
	command := args[0]
	commandArgs := args[1:]
	if firstArg := args[0]; firstArg == "--json" || firstArg == "-json" || strings.HasPrefix(firstArg, "--json=") || strings.HasPrefix(firstArg, "-json=") {
		if firstArg == "--json" || firstArg == "-json" {
			wantsJSON = true
		} else {
			_, value, hasValue := strings.Cut(firstArg, "=")
			if hasValue {
				parsed, err := strconv.ParseBool(strings.TrimSpace(value))
				if err != nil {
					if len(args) >= 2 {
						switch args[1] {
						case "help", "--help", "-h":
							usage(stdout)
							return 0
						}
					}
					return commandError(stdout, stderr, false, fmt.Sprintf("invalid boolean value %q for --json", value), 2)
				}
				wantsJSON = parsed
			}
		}
		if len(args) < 2 {
			if wantsJSON {
				return commandError(stdout, stderr, wantsJSON, "missing command", 2)
			}
			usage(stderr)
			return 2
		}
		command = args[1]
		commandArgs = args[2:]
		if wantsJSON {
			switch command {
			case "profile", "windows-policy":
				if len(commandArgs) > 0 && !jsonArgProvided(commandArgs) {
					commandArgs = append([]string{commandArgs[0], "--json"}, commandArgs[1:]...)
				}
			case "help", "-h", "--help":
			default:
				if !jsonArgProvided(commandArgs) {
					commandArgs = append([]string{"--json"}, commandArgs...)
				}
			}
		}
	} else {
		wantsJSON = argsWantJSON(args, runJSONFlags)
	}

	if command == "help" || command == "-h" || command == "--help" {
		usage(stdout)
		return 0
	}

	if wantsJSON && command == "profile" && len(commandArgs) == 0 {
		return commandError(stdout, stderr, true, "profile requires validate or template", 2)
	}
	if wantsJSON && command == "windows-policy" && len(commandArgs) == 0 {
		return commandError(stdout, stderr, true, "windows-policy requires a subcommand", 2)
	}

	provider := defaults.CurrentProvider()
	ctx := context.Background()

	switch command {
	case "inspect":
		return inspect(ctx, provider, commandArgs, stdout, stderr)
	case "doctor":
		return doctor(ctx, provider, commandArgs, stdout, stderr)
	case "get":
		return get(ctx, provider, commandArgs, stdout, stderr)
	case "open-test":
		return openTest(ctx, provider, commandArgs, stdout, stderr)
	case "profile":
		return profileCommand(commandArgs, stdout, stderr)
	case "windows-policy":
		return windowsPolicy(commandArgs, stdout, stderr)
	case "set":
		return set(ctx, provider, commandArgs, stdout, stderr)
	case "apply":
		return apply(ctx, provider, commandArgs, stdout, stderr)
	default:
		if !wantsJSON {
			usage(stderr)
		}
		return commandError(stdout, stderr, wantsJSON, fmt.Sprintf("unknown command %q", command), 2)
	}
}

func doctor(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, doctorJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	browser := fs.Bool("browser", false, "Run browser-default diagnostics")
	asJSON := fs.Bool("json", false, "Print doctor output as JSON")
	strict := fs.Bool("strict", false, "Return non-zero when warnings are present")
	fix := fs.Bool("fix", false, "Apply safe automated remediations for the selected scope")
	dryRun := fs.Bool("dry-run", false, "Preview fix operations without applying them")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "doctor does not accept positional arguments", 2)
	}
	if !*browser {
		return commandError(stdout, stderr, *asJSON, "doctor currently requires --browser", 2)
	}
	if *dryRun && !*fix {
		return commandError(stdout, stderr, *asJSON, "--dry-run requires --fix", 2)
	}

	report, err := provider.Doctor(ctx, defaults.DoctorOptions{Browser: *browser})
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 1)
	}

	var fixResult defaults.DoctorFixResult
	var fixErr error
	if *fix {
		fixResult, fixErr = provider.DoctorFix(ctx, defaults.DoctorFixOptions{Browser: *browser, DryRun: *dryRun})
	}

	shouldFail := fixErr != nil || !report.Healthy || (*strict && doctorHasStrictFinding(report.Findings))
	exitCode := 0
	if shouldFail {
		exitCode = 1
	}
	if *asJSON {
		status := map[string]any{
			"exit_code":  exitCode,
			"would_fail": shouldFail,
			"strict":     *strict,
			"fix_failed": fixErr != nil,
		}
		if *fix {
			status["changed"] = fixResult.Changed
			status["dry_run"] = *dryRun
		}
		payload := map[string]any{
			"report": report,
			"status": status,
		}
		if *fix {
			if fixErr == nil || fixResult.Changed || len(fixResult.Operations) > 0 {
				payload["fix"] = fixResult
			}
			if fixErr != nil {
				payload["fix_error"] = fixErr.Error()
			}
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if shouldFail {
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "platform: %s\n", report.Platform)
	fmt.Fprintf(stdout, "scope: %s\n", report.Scope)
	fmt.Fprintf(stdout, "healthy: %t\n", report.Healthy)
	for _, note := range report.Notes {
		fmt.Fprintf(stdout, "note: %s\n", note)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(stdout, "finding: [%s] %s %s\n", finding.ID, finding.Severity, finding.Summary)
		if finding.Details != "" {
			fmt.Fprintf(stdout, "detail: %s\n", finding.Details)
		}
		if finding.Remediation != "" {
			fmt.Fprintf(stdout, "remediation: %s\n", finding.Remediation)
		}
	}
	if *fix {
		if fixErr != nil {
			for _, op := range fixResult.Operations {
				fmt.Fprintf(stdout, "fix: %s\n", op)
			}
			fmt.Fprintf(stdout, "fix.dry_run: %t\n", *dryRun)
			fmt.Fprintf(stdout, "fix.changed: %t\n", fixResult.Changed)
			fmt.Fprintf(stdout, "fix.error: %s\n", fixErr)
		} else {
			for _, op := range fixResult.Operations {
				fmt.Fprintf(stdout, "fix: %s\n", op)
			}
			fmt.Fprintf(stdout, "fix.dry_run: %t\n", *dryRun)
			fmt.Fprintf(stdout, "fix.changed: %t\n", fixResult.Changed)
		}
	}
	if shouldFail {
		return 1
	}
	return 0
}

func doctorHasStrictFinding(findings []defaults.DoctorFinding) bool {
	for _, finding := range findings {
		severity := strings.ToLower(strings.TrimSpace(finding.Severity))
		if severity == "" || severity == "info" {
			continue
		}
		return true
	}
	return false
}

func inspect(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, inspectJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	verbose := fs.Bool("verbose", false, "Print extended capability details")
	asJSON := fs.Bool("json", false, "Print inspect output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "inspect does not accept positional arguments", 2)
	}

	report := provider.Inspect(ctx)
	if *asJSON {
		payload := struct {
			defaults.InspectReport
			Status map[string]any `json:"status"`
		}{
			InspectReport: report,
			Status: map[string]any{
				"exit_code": 0,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}

	fmt.Fprintf(stdout, "platform: %s\n", report.Platform)
	fmt.Fprintf(stdout, "provider: %s\n", report.Provider)
	fmt.Fprintf(stdout, "can_read: %t\n", report.CanRead)
	fmt.Fprintf(stdout, "can_write: %t\n", report.CanWrite)
	if *verbose {
		fmt.Fprintf(stdout, "capability.can_read_current: %t\n", report.Capabilities.CanReadCurrent)
		fmt.Fprintf(stdout, "capability.can_write_user_default: %t\n", report.Capabilities.CanWriteUserDefault)
		fmt.Fprintf(stdout, "capability.can_write_system_default: %t\n", report.Capabilities.CanWriteSystemDefault)
		fmt.Fprintf(stdout, "capability.policy_restricted: %t\n", report.Capabilities.PolicyRestricted)
		fmt.Fprintf(stdout, "capability.supports_browser: %t\n", report.Capabilities.SupportsBrowser)
		fmt.Fprintf(stdout, "capability.supports_scheme: %t\n", report.Capabilities.SupportsScheme)
		fmt.Fprintf(stdout, "capability.supports_mime: %t\n", report.Capabilities.SupportsMIME)
		fmt.Fprintf(stdout, "capability.supports_content_type: %t\n", report.Capabilities.SupportsContentType)
	}
	for _, note := range report.Notes {
		fmt.Fprintf(stdout, "note: %s\n", note)
	}
	return 0
}

func openTest(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("open-test", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, openTestJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	mime := fs.String("mime", "", "MIME type to verify")
	scheme := fs.String("scheme", "", "URL scheme or URI to verify")
	browser := fs.Bool("browser", false, "Verify the default browser association")
	callback := fs.Bool("callback", false, "Verify the callback scheme from DFX_CALLBACK_SCHEME")
	expected := fs.String("expected", "", "Expected application identifier")
	launch := fs.Bool("launch", false, "Explicitly launch the resolved target after resolution checks pass")
	path := fs.String("path", "", "File path to launch when verifying a MIME handler")
	asJSON := fs.Bool("json", false, "Print open-test output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "open-test does not accept positional arguments", 2)
	}

	target, err := openTestTargetFromFlags(*mime, *scheme, *browser, *callback)
	if err != nil {
		return openTestError(stdout, stderr, *asJSON, err.Error(), 2, nil)
	}
	actual, err := provider.Get(ctx, target)
	if err != nil {
		return openTestError(stdout, stderr, *asJSON, err.Error(), 1, &target)
	}

	report := openTestReport{
		Target:    target,
		ActualApp: strings.TrimSpace(actual),
		Launched:  false,
		Evidence:  []string{"resolved current handler through provider.Get"},
	}
	expectedApp := strings.TrimSpace(*expected)
	exitCode := 0
	if expectedApp != "" {
		matched := strings.EqualFold(report.ActualApp, expectedApp)
		report.ExpectedApp = expectedApp
		report.Matched = &matched
		if !matched {
			exitCode = 1
		}
	}
	if *launch {
		if exitCode != 0 {
			report.Evidence = append(report.Evidence, "launch skipped because expected handler did not match")
		} else {
			if target.Kind == defaults.KindMIME {
				if errMessage, errCode := validateOpenTestMimeLaunchPath(*path); errMessage != "" {
					return openTestError(stdout, stderr, *asJSON, errMessage, errCode, &target)
				}
			}
			if strings.TrimSpace(*path) != "" && target.Kind != defaults.KindMIME {
				report.Evidence = append(report.Evidence, "provided --path is ignored for non-MIME launch targets")
			}
			subject, err := openTestLaunchSubject(target, *scheme, *callback, *path)
			if err != nil {
				return openTestReportError(stdout, stderr, *asJSON, err.Error(), 2, report)
			}
			report.Launch = &openTestLaunch{Subject: subject}
			command, args, err := runOpenTestLauncher(ctx, subject)
			report.Launch.Command = command
			report.Launch.Args = args
			if err != nil {
				return openTestReportError(stdout, stderr, *asJSON, err.Error(), 1, report)
			}
			report.Launched = true
			report.Evidence = append(report.Evidence, "explicit launch requested and launcher command completed")
		}
	} else {
		report.Notes = append(report.Notes, "safe preflight only; no external application was launched")
	}

	if *asJSON {
		payload := map[string]any{
			"report": report,
			"status": map[string]any{
				"exit_code":  exitCode,
				"would_fail": exitCode != 0,
				"launched":   report.Launched,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return exitCode
	}

	fmt.Fprintf(stdout, "target: %s\n", target.String())
	if expectedApp != "" {
		fmt.Fprintf(stdout, "expected: %s\n", report.ExpectedApp)
	}
	fmt.Fprintf(stdout, "actual: %s\n", report.ActualApp)
	if report.Matched != nil {
		fmt.Fprintf(stdout, "matched: %t\n", *report.Matched)
	}
	writeOpenTestReportDetails(stdout, report)
	return exitCode
}

func profileCommand(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	wantsJSON := argsWantJSON(args, profileValidateJSONFlags)
	if !wantsJSON && len(args) > 1 {
		wantsJSON = argsWantJSON(args[1:], profileValidateJSONFlags)
	}
	if len(args) == 0 || (len(args) == 1 && isJSONFlagArgument(args[0])) {
		return commandError(stdout, stderr, wantsJSON, "profile requires validate or template", 2)
	}
	switch args[0] {
	case "template":
		return profileTemplate(args[1:], stdout, stderr)
	case "validate":
		return profileValidate(args[1:], stdout, stderr)
	default:
		return commandError(stdout, stderr, wantsJSON, fmt.Sprintf("unknown profile subcommand %q", args[0]), 2)
	}
}

func profileValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("profile validate", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, profileValidateJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	asJSON := fs.Bool("json", false, "Print profile validation output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() == 0 {
		return commandError(stdout, stderr, *asJSON, "profile validate requires exactly one profile path", 2)
	}
	if fs.NArg() > 1 {
		return commandError(stdout, stderr, *asJSON, "profile validate does not accept positional arguments", 2)
	}
	path := expandPolicyFilePath(fs.Arg(0))
	cfg, err := readProfile(path)
	if err != nil {
		return profileValidationError(stdout, stderr, *asJSON, path, err.Error(), 1, -1, defaults.Association{})
	}
	associations, failedIndex, failedAssociation, err := validateProfile(cfg)
	if err != nil {
		return profileValidationError(stdout, stderr, *asJSON, path, err.Error(), 2, failedIndex, failedAssociation)
	}
	report := profileValidationReport{
		Path:     path,
		Valid:    true,
		Count:    len(associations),
		Defaults: associations,
	}
	if *asJSON {
		payload := map[string]any{
			"profile": report,
			"status": map[string]any{
				"exit_code": 0,
				"valid":     true,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "path: %s\n", path)
	fmt.Fprintln(stdout, "valid: true")
	fmt.Fprintf(stdout, "count: %d\n", len(associations))
	for index, association := range associations {
		fmt.Fprintf(stdout, "default[%d]: %s -> %s\n", index, association.Target().String(), association.App)
	}
	return 0
}

func profileTemplate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("profile template", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, profileTemplateJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	app := fs.String("app", "", "Application identifier to use for the browser default")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI to include")
	callbackApp := fs.String("callback-app", "", "Application identifier to use for the callback scheme")
	asJSON := fs.Bool("json", false, "Wrap generated profile in status JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "profile template does not accept positional arguments", 2)
	}

	browserApp := strings.TrimSpace(*app)
	callbackSchemeValue := strings.TrimSpace(*callbackScheme)
	callbackAppValue := strings.TrimSpace(*callbackApp)
	if browserApp == "" {
		return commandError(stdout, stderr, *asJSON, "profile template requires --app", 2)
	}
	if callbackSchemeValue == "" && callbackAppValue != "" {
		return commandError(stdout, stderr, *asJSON, "--callback-app requires --callback-scheme", 2)
	}
	if callbackSchemeValue != "" && callbackAppValue == "" {
		return commandError(stdout, stderr, *asJSON, "--callback-scheme requires --callback-app", 2)
	}

	cfg := profile{
		Defaults: []defaults.Association{
			{Kind: defaults.KindBrowser, App: browserApp},
		},
	}
	if callbackSchemeValue != "" {
		cfg.Defaults = append(cfg.Defaults, defaults.Association{Kind: defaults.KindScheme, Value: callbackSchemeValue, App: callbackAppValue})
	}

	associations, failedIndex, failedAssociation, err := validateProfile(cfg)
	if err != nil {
		return profileTemplateError(stdout, stderr, *asJSON, err.Error(), 2, failedIndex, failedAssociation, cfg)
	}
	cfg.Defaults = associations

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if *asJSON {
		payload := map[string]any{
			"profile": cfg,
			"status": map[string]any{
				"exit_code": 0,
				"valid":     true,
				"count":     len(associations),
			},
		}
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	if err := encoder.Encode(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func windowsPolicy(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if !wantsJSON && len(args) > 1 {
		wantsJSON = argsWantJSON(args[1:], windowsPolicyJSONFlags)
	}
	if len(args) == 0 || (len(args) == 1 && isJSONFlagArgument(args[0])) {
		return commandError(stdout, stderr, wantsJSON, "windows-policy requires a subcommand", 2)
	}
	switch args[0] {
	case "audit":
		return windowsPolicyAudit(args[1:], stdout, stderr)
	case "backup":
		return windowsPolicyBackup(args[1:], stdout, stderr)
	case "bundle":
		return windowsPolicyBundle(args[1:], stdout, stderr)
	case "bundle-inspect":
		return windowsPolicyBundleInspect(args[1:], stdout, stderr)
	case "compile":
		return windowsPolicyCompile(args[1:], stdout, stderr)
	case "csp":
		return windowsPolicyCSP(args[1:], stdout, stderr)
	case "deploy":
		return windowsPolicyDeploy(args[1:], stdout, stderr)
	case "diff":
		return windowsPolicyDiff(args[1:], stdout, stderr)
	case "export":
		return windowsPolicyExport(args[1:], stdout, stderr)
	case "gpo":
		return windowsPolicyGPO(args[1:], stdout, stderr)
	case "gpo-backup":
		return windowsPolicyGPOBackup(args[1:], stdout, stderr)
	case "gpo-restore":
		return windowsPolicyGPORestore(args[1:], stdout, stderr)
	case "gpo-report":
		return windowsPolicyGPOReport(args[1:], stdout, stderr)
	case "gpo-status":
		return windowsPolicyGPOStatus(args[1:], stdout, stderr)
	case "gpresult":
		return windowsPolicyGPResult(args[1:], stdout, stderr)
	case "install":
		return windowsPolicyInstall(args[1:], stdout, stderr)
	case "invoke-refresh":
		return windowsPolicyInvokeRefresh(args[1:], stdout, stderr)
	case "import":
		return windowsPolicyDISMImport(args[1:], stdout, stderr)
	case "intune":
		return windowsPolicyIntune(args[1:], stdout, stderr)
	case "list":
		return windowsPolicyDISMList(args[1:], stdout, stderr)
	case "lgpo":
		return windowsPolicyLGPO(args[1:], stdout, stderr)
	case "merge":
		return windowsPolicyMerge(args[1:], stdout, stderr)
	case "normalize":
		return windowsPolicyNormalize(args[1:], stdout, stderr)
	case "pol":
		return windowsPolicyPOL(args[1:], stdout, stderr)
	case "profile":
		return windowsPolicyProfile(args[1:], stdout, stderr)
	case "remove":
		return windowsPolicyDISMRemove(args[1:], stdout, stderr)
	case "registered":
		return windowsPolicyRegistered(args[1:], stdout, stderr)
	case "refresh":
		return windowsPolicyRefresh(args[1:], stdout, stderr)
	case "reg":
		return windowsPolicyReg(args[1:], stdout, stderr)
	case "restore":
		return windowsPolicyRestore(args[1:], stdout, stderr)
	case "script":
		return windowsPolicyScript(args[1:], stdout, stderr)
	case "status":
		return windowsPolicyStatus(args[1:], stdout, stderr)
	case "uninstall":
		return windowsPolicyUninstall(args[1:], stdout, stderr)
	case "validate":
		return windowsPolicyValidate(args[1:], stdout, stderr)
	case "template":
		return windowsPolicyTemplate(args[1:], stdout, stderr)
	case "targets":
		return windowsPolicyTargets(args[1:], stdout, stderr)
	default:
		return commandError(stdout, stderr, wantsJSON, fmt.Sprintf("unknown windows-policy subcommand %q", args[0]), 2)
	}
}

func windowsPolicyAudit(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy audit", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	progID := fs.String("prog-id", "", "Windows ProgID to audit")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI to include in capability checks")
	asJSON := fs.Bool("json", false, "Print audit output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy audit does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*progID) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy audit requires --prog-id", 2)
	}
	audit, err := defaults.AuditWindowsProgID(context.Background(), *progID, *callbackScheme)
	exitCode := 0
	if err != nil || !audit.Healthy {
		exitCode = 1
	}
	if *asJSON {
		status := map[string]any{
			"exit_code":  exitCode,
			"would_fail": exitCode != 0,
			"healthy":    audit.Healthy,
		}
		payload := map[string]any{
			"audit":  audit,
			"status": status,
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return exitCode
	}
	writeWindowsCapabilityAudit(stdout, audit)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyBackup(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy backup", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Destination XML file for backing up the active policy payload")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	dryRun := fs.Bool("dry-run", false, "Print planned backup operations without writing the XML file")
	asJSON := fs.Bool("json", false, "Print backup output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy backup does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy backup requires --file", 2)
	}
	result, err := defaults.BackupWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyBackupOptions{
		File:           *file,
		CallbackScheme: *callbackScheme,
		DryRun:         *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"backup": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyBackupResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyBundle(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy bundle", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Reviewed default-association XML file to bundle")
	profilePath := fs.String("profile", "", "dfx profile path to compile into bundled policy XML")
	output := fs.String("output", "", "Bundle output directory")
	archive := fs.String("archive", "", "Optional zip archive path for the generated bundle")
	policyPath := fs.String("policy-path", "", "Policy XML destination path used by generated artifacts")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	version := fs.String("version", "", "DefaultAssociations Version attribute for profile-generated suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on profile-generated associations")
	resolveApps := fs.Bool("resolve-apps", false, "Resolve profile app queries to Windows ProgIDs using registry metadata")
	gpupdate := fs.Bool("gpupdate", false, "Include gpupdate in the bundled local deployment script")
	deleteBundle := fs.Bool("delete", false, "Generate a removal bundle instead of a deployment bundle")
	deleteFile := fs.Bool("delete-file", false, "Include bundled local removal script logic to delete the policy XML file")
	gpoName := fs.String("gpo-name", "", "Display name of the domain GPO script to include")
	gpoGUID := fs.String("gpo-guid", "", "GUID of the domain GPO script to include")
	domain := fs.String("domain", "", "FQDN of the domain containing the GPO")
	server := fs.String("server", "", "Domain controller to contact")
	createGPO := fs.Bool("create", false, "Include New-GPO in the bundled domain GPO script")
	comment := fs.String("comment", "", "Comment for a newly created GPO")
	linkTarget := fs.String("link-target", "", "LDAP distinguished name of a site, domain, or OU to link the GPO")
	linkDisabled := fs.Bool("link-disabled", false, "Create the GPO link with LinkEnabled No")
	enforced := fs.Bool("enforced", false, "Create the GPO link with Enforced Yes")
	order := fs.Int("order", 0, "Link order to use when --link-target is provided")
	whatIf := fs.Bool("what-if", false, "Include PowerShell WhatIf in the bundled GPO script")
	dryRun := fs.Bool("dry-run", false, "Print planned bundle files without writing them")
	asJSON := fs.Bool("json", false, "Print bundle output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) != "" && strings.TrimSpace(*profilePath) != "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle accepts either --file or --profile, not both", 2)
	}
	if *deleteBundle && (strings.TrimSpace(*file) != "" || strings.TrimSpace(*profilePath) != "") {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle --delete does not accept --file or --profile", 2)
	}
	if strings.TrimSpace(*output) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle requires --output", 2)
	}
	var associations []defaults.Association
	if strings.TrimSpace(*profilePath) != "" && !*deleteBundle {
		cfg, err := readProfile(expandPolicyFilePath(*profilePath))
		if err != nil {
			return commandError(stdout, stderr, *asJSON, err.Error(), 1)
		}
		resolved, failedIndex, failedAssociation, err := validateProfile(cfg)
		if err != nil {
			fields := map[string]any{}
			if failedIndex >= 0 {
				fields["failed_index"] = failedIndex
				fields["association"] = failedAssociation
			}
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, false, fields)
		}
		associations = resolved
	}
	if *resolveApps && len(associations) > 0 && !*deleteBundle {
		resolution, err := defaults.ResolveWindowsPolicyAssociations(context.Background(), defaults.WindowsPolicyAppResolutionOptions{Associations: associations})
		if err != nil {
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, false, map[string]any{
				"app_resolution": resolution,
			})
		}
		associations = resolution.Associations
	}
	if strings.TrimSpace(*file) == "" && len(associations) == 0 && !*deleteBundle {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle requires --file or --profile", 2)
	}
	result, err := defaults.BundleWindowsDefaultAssociationsPolicy(defaults.WindowsPolicyBundleOptions{
		File:           *file,
		Associations:   associations,
		CallbackScheme: *callbackScheme,
		Version:        *version,
		Suggested:      *suggested,
		Output:         *output,
		Archive:        *archive,
		PolicyPath:     *policyPath,
		RefreshPolicy:  *gpupdate,
		Delete:         *deleteBundle,
		DeleteFile:     *deleteFile,
		DryRun:         *dryRun,
		GPO: defaults.WindowsPolicyGPOOptions{
			GPOName:      *gpoName,
			GPOGUID:      *gpoGUID,
			PolicyPath:   *policyPath,
			Domain:       *domain,
			Server:       *server,
			Create:       *createGPO,
			Comment:      *comment,
			LinkTarget:   *linkTarget,
			LinkDisabled: *linkDisabled,
			Enforced:     *enforced,
			Order:        *order,
			WhatIf:       *whatIf,
		},
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"bundle": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
				"valid":     result.Validation.Valid,
				"complete":  result.Validation.Complete,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyBundleResult(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyBundleInspect(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy bundle-inspect", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	path := fs.String("path", "", "Bundle output directory to inspect")
	archive := fs.String("archive", "", "Bundle zip archive to inspect")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in bundled XML validation")
	asJSON := fs.Bool("json", false, "Print bundle inspection as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle-inspect does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*path) != "" && strings.TrimSpace(*archive) != "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle-inspect accepts either --path or --archive, not both", 2)
	}
	if strings.TrimSpace(*path) == "" && strings.TrimSpace(*archive) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy bundle-inspect requires --path or --archive", 2)
	}
	result, err := defaults.InspectWindowsDefaultAssociationsPolicyBundle(defaults.WindowsPolicyBundleInspectOptions{
		Path:           *path,
		Archive:        *archive,
		CallbackScheme: *callbackScheme,
	})
	exitCode := 0
	if err != nil || !result.Valid {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"bundle": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"valid":     result.Valid,
				"complete":  result.Complete,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyBundleInspectResult(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyTargets(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy targets", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI to include in target coverage")
	asJSON := fs.Bool("json", false, "Print target mapping as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy targets does not accept positional arguments", 2)
	}
	targets := defaults.WindowsPolicyRequiredTargets(*callbackScheme)
	type targetMapping struct {
		Target      string   `json:"target"`
		Identifiers []string `json:"identifiers"`
	}
	mappings := make([]targetMapping, 0, len(targets))
	for _, target := range targets {
		mappings = append(mappings, targetMapping{
			Target:      target,
			Identifiers: windowsPolicyTargetIdentifiers(target),
		})
	}
	if *asJSON {
		payload := map[string]any{
			"targets": mappings,
			"status": map[string]any{
				"exit_code": 0,
				"count":     len(mappings),
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	for _, mapping := range mappings {
		fmt.Fprintf(stdout, "target: %s\n", mapping.Target)
		for _, identifier := range mapping.Identifiers {
			fmt.Fprintf(stdout, "identifier: %s\n", identifier)
		}
	}
	return 0
}

func windowsPolicyCompile(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy compile", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	profilePath := fs.String("profile", "", "dfx profile path to compile into policy XML")
	file := fs.String("file", "", "Destination default-association XML file")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that must be present in compiled XML")
	version := fs.String("version", "", "DefaultAssociations Version attribute for suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on generated associations")
	resolveApps := fs.Bool("resolve-apps", false, "Resolve profile app queries to Windows ProgIDs using registry metadata")
	dryRun := fs.Bool("dry-run", false, "Print planned compile operations without writing the XML file")
	asJSON := fs.Bool("json", false, "Print compile output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy compile does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*profilePath) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy compile requires --profile", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy compile requires --file", 2)
	}
	cfg, err := readProfile(expandPolicyFilePath(*profilePath))
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 1)
	}
	associations, failedIndex, failedAssociation, err := validateProfile(cfg)
	if err != nil {
		fields := map[string]any{}
		if failedIndex >= 0 {
			fields["failed_index"] = failedIndex
			fields["association"] = failedAssociation
		}
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, fields)
	}
	if *resolveApps {
		resolution, err := defaults.ResolveWindowsPolicyAssociations(context.Background(), defaults.WindowsPolicyAppResolutionOptions{Associations: associations})
		if err != nil {
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, map[string]any{
				"app_resolution": resolution,
			})
		}
		associations = resolution.Associations
	}
	result, err := defaults.CompileWindowsDefaultAssociationsPolicyXML(defaults.WindowsPolicyCompileOptions{
		File:           *file,
		Associations:   associations,
		CallbackScheme: *callbackScheme,
		Version:        *version,
		Suggested:      *suggested,
		DryRun:         *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyCompileResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyCSP(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy csp", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to encode for ApplicationDefaults CSP")
	profilePath := fs.String("profile", "", "dfx profile path to compile into a CSP payload")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	version := fs.String("version", "", "DefaultAssociations Version attribute for suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on profile-generated associations")
	resolveApps := fs.Bool("resolve-apps", false, "Resolve profile app queries to Windows ProgIDs using registry metadata")
	locURI := fs.String("loc-uri", "", "OMA-URI/LocURI for ApplicationDefaults CSP")
	cmdID := fs.String("cmd-id", "", "SyncML CmdID to use when --syncml is provided")
	syncML := fs.Bool("syncml", false, "Emit a SyncML Replace payload in addition to the base64 data")
	deletePayload := fs.Bool("delete", false, "Emit a CSP Delete payload instead of a Replace payload")
	asJSON := fs.Bool("json", false, "Print CSP output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy csp does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) != "" && strings.TrimSpace(*profilePath) != "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy csp accepts either --file or --profile, not both", 2)
	}
	var associations []defaults.Association
	if strings.TrimSpace(*profilePath) != "" {
		cfg, err := readProfile(expandPolicyFilePath(*profilePath))
		if err != nil {
			return commandError(stdout, stderr, *asJSON, err.Error(), 1)
		}
		resolved, failedIndex, failedAssociation, err := validateProfile(cfg)
		if err != nil {
			fields := map[string]any{}
			if failedIndex >= 0 {
				fields["failed_index"] = failedIndex
				fields["association"] = failedAssociation
			}
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, false, fields)
		}
		associations = resolved
	}
	if *resolveApps && len(associations) > 0 {
		resolution, err := defaults.ResolveWindowsPolicyAssociations(context.Background(), defaults.WindowsPolicyAppResolutionOptions{Associations: associations})
		if err != nil {
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, false, map[string]any{
				"app_resolution": resolution,
			})
		}
		associations = resolution.Associations
	}
	if strings.TrimSpace(*file) == "" && len(associations) == 0 && !*deletePayload {
		return commandError(stdout, stderr, *asJSON, "windows-policy csp requires --file or --profile", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyCSP(defaults.WindowsPolicyCSPOptions{
		File:           *file,
		Associations:   associations,
		CallbackScheme: *callbackScheme,
		Version:        *version,
		Suggested:      *suggested,
		LocURI:         *locURI,
		CmdID:          *cmdID,
		SyncML:         *syncML,
		Delete:         *deletePayload,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"csp": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"valid":     result.Validation.Valid,
				"complete":  result.Validation.Complete,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyCSPResult(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyIntune(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy intune", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to encode for Intune custom OMA-URI")
	profilePath := fs.String("profile", "", "dfx profile path to compile into an Intune payload")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	version := fs.String("version", "", "DefaultAssociations Version attribute for suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on profile-generated associations")
	resolveApps := fs.Bool("resolve-apps", false, "Resolve profile app queries to Windows ProgIDs using registry metadata")
	name := fs.String("name", "", "Intune custom OMA-URI setting name")
	description := fs.String("description", "", "Intune custom OMA-URI setting description")
	asJSON := fs.Bool("json", false, "Print Intune output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy intune does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) != "" && strings.TrimSpace(*profilePath) != "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy intune accepts either --file or --profile, not both", 2)
	}
	var associations []defaults.Association
	if strings.TrimSpace(*profilePath) != "" {
		cfg, err := readProfile(expandPolicyFilePath(*profilePath))
		if err != nil {
			return commandError(stdout, stderr, *asJSON, err.Error(), 1)
		}
		resolved, failedIndex, failedAssociation, err := validateProfile(cfg)
		if err != nil {
			fields := map[string]any{}
			if failedIndex >= 0 {
				fields["failed_index"] = failedIndex
				fields["association"] = failedAssociation
			}
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, false, fields)
		}
		associations = resolved
	}
	if *resolveApps && len(associations) > 0 {
		resolution, err := defaults.ResolveWindowsPolicyAssociations(context.Background(), defaults.WindowsPolicyAppResolutionOptions{Associations: associations})
		if err != nil {
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, false, map[string]any{
				"app_resolution": resolution,
			})
		}
		associations = resolution.Associations
	}
	if strings.TrimSpace(*file) == "" && len(associations) == 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy intune requires --file or --profile", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyIntune(defaults.WindowsPolicyIntuneOptions{
		File:           *file,
		Associations:   associations,
		CallbackScheme: *callbackScheme,
		Version:        *version,
		Suggested:      *suggested,
		Name:           *name,
		Description:    *description,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"intune": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"valid":     result.CSP.Validation.Valid,
				"complete":  result.CSP.Validation.Complete,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyIntuneResult(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyDeploy(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy deploy", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	profilePath := fs.String("profile", "", "dfx profile path to compile and deploy as policy XML")
	file := fs.String("file", "", "Policy XML staging path")
	destination := fs.String("destination", "", "Destination XML path for policy processing")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that must be present in deployed XML")
	version := fs.String("version", "", "DefaultAssociations Version attribute for suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on generated associations")
	resolveApps := fs.Bool("resolve-apps", false, "Resolve profile app queries to Windows ProgIDs using registry metadata")
	allowIncomplete := fs.Bool("allow-incomplete", false, "Deploy valid XML even if required browser targets are incomplete")
	dryRun := fs.Bool("dry-run", false, "Print planned deploy operations without writing or installing policy")
	gpupdate := fs.Bool("gpupdate", false, "Run gpupdate /target:computer /force after installing policy")
	asJSON := fs.Bool("json", false, "Print deploy output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy deploy does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*profilePath) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy deploy requires --profile", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy deploy requires --file", 2)
	}
	cfg, err := readProfile(expandPolicyFilePath(*profilePath))
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 1)
	}
	associations, failedIndex, failedAssociation, err := validateProfile(cfg)
	if err != nil {
		fields := map[string]any{}
		if failedIndex >= 0 {
			fields["failed_index"] = failedIndex
			fields["association"] = failedAssociation
		}
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, fields)
	}
	if *resolveApps {
		resolution, err := defaults.ResolveWindowsPolicyAssociations(context.Background(), defaults.WindowsPolicyAppResolutionOptions{Associations: associations})
		if err != nil {
			return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, map[string]any{
				"app_resolution": resolution,
			})
		}
		associations = resolution.Associations
	}
	result, err := defaults.DeployWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyDeployOptions{
		File:            *file,
		Destination:     *destination,
		Associations:    associations,
		CallbackScheme:  *callbackScheme,
		Version:         *version,
		Suggested:       *suggested,
		AllowIncomplete: *allowIncomplete,
		DryRun:          *dryRun,
		RefreshPolicy:   *gpupdate,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyDeployResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyDiff(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy diff", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Desired default-association XML file")
	current := fs.String("current", "", "Current/default-association XML file to compare; defaults to installed policy")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	asJSON := fs.Bool("json", false, "Print diff output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy diff does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy diff requires --file", 2)
	}
	result, err := defaults.DiffWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyDiffOptions{
		File:           *file,
		CurrentFile:    *current,
		CallbackScheme: *callbackScheme,
	})
	exitCode := 0
	if err != nil || !result.Equal {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"diff": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"equal":     result.Equal,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyDiffResult(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyValidate(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy validate", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to validate")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that must be present")
	asJSON := fs.Bool("json", false, "Print validation output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy validate does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy validate requires --file", 2)
	}
	content, err := os.ReadFile(expandPolicyFilePath(*file))
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 1)
	}
	validation := defaults.ValidateWindowsPolicyXML(content, *callbackScheme)
	exitCode := 0
	if !validation.Valid || !validation.Complete {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"validation": validation,
			"status": map[string]any{
				"exit_code":  exitCode,
				"would_fail": exitCode != 0,
				"valid":      validation.Valid,
				"complete":   validation.Complete,
				"mandatory":  validation.Mandatory,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return exitCode
	}
	fmt.Fprintf(stdout, "file: %s\n", expandPolicyFilePath(*file))
	fmt.Fprintf(stdout, "valid: %t\n", validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", validation.Mandatory)
	if validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", validation.Suggested)
	for _, target := range validation.Required {
		fmt.Fprintf(stdout, "required: %s\n", target)
	}
	for _, missing := range validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, record := range validation.Records {
		fmt.Fprintf(stdout, "association: %s -> %s\n", record.Identifier, record.ProgID)
	}
	return exitCode
}

func windowsPolicyInstall(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy install", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to install")
	destination := fs.String("destination", "", "Destination XML path for policy processing")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that must be present")
	allowIncomplete := fs.Bool("allow-incomplete", false, "Install valid XML even if required browser targets are incomplete")
	dryRun := fs.Bool("dry-run", false, "Print planned install operations without applying them")
	gpupdate := fs.Bool("gpupdate", false, "Run gpupdate /target:computer /force after installing policy")
	asJSON := fs.Bool("json", false, "Print install output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy install does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy install requires --file", 2)
	}
	result, err := defaults.InstallWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyInstallOptions{
		File:            *file,
		Destination:     *destination,
		CallbackScheme:  *callbackScheme,
		AllowIncomplete: *allowIncomplete,
		DryRun:          *dryRun,
		RefreshPolicy:   *gpupdate,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyInstallResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyDISMImport(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy import", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to import with DISM")
	image := fs.String("image", "", "Offline Windows image path; defaults to /Online")
	dryRun := fs.Bool("dry-run", false, "Print planned DISM import without running it")
	asJSON := fs.Bool("json", false, "Print DISM import output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy import does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy import requires --file", 2)
	}
	result, err := defaults.ImportWindowsDefaultAssociationsWithDISM(context.Background(), defaults.WindowsPolicyDISMOptions{
		File:   *file,
		Image:  *image,
		DryRun: *dryRun,
	})
	return writeWindowsPolicyDISMCommandResult(stdout, stderr, *asJSON, *dryRun, result, err)
}

func windowsPolicyDISMList(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy list", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	image := fs.String("image", "", "Offline Windows image path; defaults to /Online")
	dryRun := fs.Bool("dry-run", false, "Print planned DISM list without running it")
	asJSON := fs.Bool("json", false, "Print DISM list output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy list does not accept positional arguments", 2)
	}
	result, err := defaults.ListWindowsDefaultAssociationsWithDISM(context.Background(), defaults.WindowsPolicyDISMOptions{
		Image:  *image,
		DryRun: *dryRun,
	})
	return writeWindowsPolicyDISMCommandResult(stdout, stderr, *asJSON, *dryRun, result, err)
}

func windowsPolicyDISMRemove(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy remove", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	image := fs.String("image", "", "Offline Windows image path; defaults to /Online")
	dryRun := fs.Bool("dry-run", false, "Print planned DISM remove without running it")
	asJSON := fs.Bool("json", false, "Print DISM remove output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy remove does not accept positional arguments", 2)
	}
	result, err := defaults.RemoveWindowsDefaultAssociationsWithDISM(context.Background(), defaults.WindowsPolicyDISMOptions{
		Image:  *image,
		DryRun: *dryRun,
	})
	return writeWindowsPolicyDISMCommandResult(stdout, stderr, *asJSON, *dryRun, result, err)
}

func windowsPolicyRegistered(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy registered", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	query := fs.String("query", "", "Filter registered applications by name, ProgID, identifier, or target")
	asJSON := fs.Bool("json", false, "Print registered applications as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy registered does not accept positional arguments", 2)
	}
	result, err := defaults.ListWindowsRegisteredApplications(context.Background(), defaults.WindowsRegisteredApplicationsOptions{
		Query: *query,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"registered": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"count":     len(result.Applications),
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsRegisteredApplications(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyReg(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy reg", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	policyPath := fs.String("policy-path", "", "Policy XML path to write into the registry artifact")
	deleteValue := fs.Bool("delete", false, "Generate a registry artifact that deletes the policy pointer")
	asJSON := fs.Bool("json", false, "Print registry artifact as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy reg does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyRegistryFile(defaults.WindowsPolicyRegistryFileOptions{
		PolicyPath: *policyPath,
		Delete:     *deleteValue,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"reg": result,
			"status": map[string]any{
				"exit_code": exitCode,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	fmt.Fprint(stdout, result.Content)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyLGPO(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy lgpo", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	policyPath := fs.String("policy-path", "", "Policy XML path to write into the LGPO text artifact")
	deleteValue := fs.Bool("delete", false, "Generate an LGPO text artifact that deletes the policy pointer")
	asJSON := fs.Bool("json", false, "Print LGPO text artifact as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy lgpo does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyLGPOText(defaults.WindowsPolicyLGPOTextOptions{
		PolicyPath: *policyPath,
		Delete:     *deleteValue,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"lgpo": result,
			"status": map[string]any{
				"exit_code": exitCode,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	fmt.Fprint(stdout, result.Content)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyPOL(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy pol", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	policyPath := fs.String("policy-path", "", "Policy XML path to write into the Registry.pol artifact")
	output := fs.String("output", "", "Registry.pol output path")
	deleteValue := fs.Bool("delete", false, "Generate a Registry.pol artifact that removes the policy pointer")
	dryRun := fs.Bool("dry-run", false, "Preview Registry.pol artifact generation without writing --output")
	asJSON := fs.Bool("json", false, "Print Registry.pol artifact metadata as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy pol does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyRegistryPOL(defaults.WindowsPolicyRegistryPOLOptions{
		PolicyPath: *policyPath,
		Output:     *output,
		Delete:     *deleteValue,
		DryRun:     *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"pol": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyPOLResult(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyGPO(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy gpo", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	gpoName := fs.String("gpo-name", "", "Display name of the GPO to update")
	gpoGUID := fs.String("gpo-guid", "", "GUID of the GPO to update")
	policyPath := fs.String("policy-path", "", "Policy XML path to configure in the GPO")
	domain := fs.String("domain", "", "FQDN of the domain containing the GPO")
	server := fs.String("server", "", "Domain controller to contact")
	createGPO := fs.Bool("create", false, "Include New-GPO before configuring the policy")
	comment := fs.String("comment", "", "Comment for a newly created GPO")
	linkTarget := fs.String("link-target", "", "LDAP distinguished name of a site, domain, or OU to link the GPO")
	linkDisabled := fs.Bool("link-disabled", false, "Create the GPO link with LinkEnabled No")
	enforced := fs.Bool("enforced", false, "Create the GPO link with Enforced Yes")
	order := fs.Int("order", 0, "Link order to use when --link-target is provided")
	deleteValue := fs.Bool("delete", false, "Generate a GroupPolicy command that disables the policy value so clients delete it")
	whatIf := fs.Bool("what-if", false, "Include PowerShell WhatIf in the generated GroupPolicy command")
	asJSON := fs.Bool("json", false, "Print GroupPolicy artifact as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy gpo does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyGPO(defaults.WindowsPolicyGPOOptions{
		GPOName:      *gpoName,
		GPOGUID:      *gpoGUID,
		PolicyPath:   *policyPath,
		Domain:       *domain,
		Server:       *server,
		Create:       *createGPO,
		Comment:      *comment,
		LinkTarget:   *linkTarget,
		LinkDisabled: *linkDisabled,
		Enforced:     *enforced,
		Order:        *order,
		Delete:       *deleteValue,
		WhatIf:       *whatIf,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"gpo": result,
			"status": map[string]any{
				"exit_code": exitCode,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	fmt.Fprint(stdout, result.Content)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyGPResult(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy gpresult", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	scope := fs.String("scope", "computer", "gpresult scope: computer or user")
	format := fs.String("format", "summary", "gpresult format: summary, verbose, superverbose, html, or xml")
	file := fs.String("file", "", "Report file for html or xml gpresult output")
	system := fs.String("system", "", "Remote system name or IP address for gpresult /s")
	user := fs.String("user", "", "Target user for gpresult /user")
	force := fs.Bool("force", false, "Overwrite existing html/xml report with gpresult /f")
	dryRun := fs.Bool("dry-run", false, "Print gpresult command without running it")
	asJSON := fs.Bool("json", false, "Print gpresult evidence as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy gpresult does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyGPResult(context.Background(), defaults.WindowsPolicyGPResultOptions{
		Scope:  *scope,
		Format: *format,
		File:   *file,
		System: *system,
		User:   *user,
		Force:  *force,
		DryRun: *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"gpresult": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyGPResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyGPOReport(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy gpo-report", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	gpoName := fs.String("gpo-name", "", "Display name of the GPO to report")
	gpoGUID := fs.String("gpo-guid", "", "GUID of the GPO to report")
	all := fs.Bool("all", false, "Report all GPOs in the domain")
	reportType := fs.String("format", "html", "GPO report type: html or xml")
	file := fs.String("file", "", "Report output file")
	domain := fs.String("domain", "", "FQDN of the domain containing the GPO")
	server := fs.String("server", "", "Domain controller to contact")
	script := fs.Bool("script", false, "Print the generated PowerShell script instead of running it")
	output := fs.String("output", "", "Write the generated PowerShell script to a file")
	dryRun := fs.Bool("dry-run", false, "Print Get-GPOReport command without running it")
	asJSON := fs.Bool("json", false, "Print GPO report output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy gpo-report does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyGPOReport(context.Background(), defaults.WindowsPolicyGPOReportOptions{
		GPOName:    *gpoName,
		GPOGUID:    *gpoGUID,
		All:        *all,
		ReportType: *reportType,
		File:       *file,
		Domain:     *domain,
		Server:     *server,
		Script:     *script,
		Output:     *output,
		DryRun:     *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"gpo_report": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	if *script {
		fmt.Fprint(stdout, result.Script)
	} else {
		writeWindowsPolicyGPOReport(stdout, result, *dryRun)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyGPOBackup(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy gpo-backup", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	gpoName := fs.String("gpo-name", "", "Display name of the GPO to back up")
	gpoGUID := fs.String("gpo-guid", "", "GUID of the GPO to back up")
	all := fs.Bool("all", false, "Back up all GPOs in the domain")
	path := fs.String("path", "", "Backup-GPO backup directory")
	comment := fs.String("comment", "", "Backup comment")
	domain := fs.String("domain", "", "FQDN of the domain containing the GPO")
	server := fs.String("server", "", "Domain controller to contact")
	whatIf := fs.Bool("what-if", false, "Include Backup-GPO -WhatIf")
	script := fs.Bool("script", false, "Print the generated PowerShell script instead of running it")
	output := fs.String("output", "", "Write the generated PowerShell script to a file")
	dryRun := fs.Bool("dry-run", false, "Print Backup-GPO command without running it")
	asJSON := fs.Bool("json", false, "Print GPO backup output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy gpo-backup does not accept positional arguments", 2)
	}
	result, err := defaults.BackupWindowsDefaultAssociationsPolicyGPO(context.Background(), defaults.WindowsPolicyGPOBackupOptions{
		GPOName: *gpoName,
		GPOGUID: *gpoGUID,
		All:     *all,
		Path:    *path,
		Comment: *comment,
		Domain:  *domain,
		Server:  *server,
		WhatIf:  *whatIf,
		Script:  *script,
		Output:  *output,
		DryRun:  *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"gpo_backup": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	if *script {
		fmt.Fprint(stdout, result.Script)
	} else {
		writeWindowsPolicyGPOBackup(stdout, result, *dryRun)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyGPORestore(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy gpo-restore", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	gpoName := fs.String("gpo-name", "", "Display name of the GPO to restore")
	gpoGUID := fs.String("gpo-guid", "", "GUID of the GPO to restore")
	path := fs.String("path", "", "Restore-GPO backup directory")
	domain := fs.String("domain", "", "FQDN of the domain containing the GPO")
	server := fs.String("server", "", "Domain controller to contact")
	whatIf := fs.Bool("what-if", false, "Include Restore-GPO -WhatIf")
	script := fs.Bool("script", false, "Print the generated PowerShell script instead of running it")
	output := fs.String("output", "", "Write the generated PowerShell script to a file")
	dryRun := fs.Bool("dry-run", false, "Print Restore-GPO command without running it")
	asJSON := fs.Bool("json", false, "Print GPO restore output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy gpo-restore does not accept positional arguments", 2)
	}
	result, err := defaults.RestoreWindowsDefaultAssociationsPolicyGPO(context.Background(), defaults.WindowsPolicyGPORestoreOptions{
		GPOName: *gpoName,
		GPOGUID: *gpoGUID,
		Path:    *path,
		Domain:  *domain,
		Server:  *server,
		WhatIf:  *whatIf,
		Script:  *script,
		Output:  *output,
		DryRun:  *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"gpo_restore": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	if *script {
		fmt.Fprint(stdout, result.Script)
	} else {
		writeWindowsPolicyGPORestore(stdout, result, *dryRun)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyGPOStatus(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy gpo-status", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	gpoName := fs.String("gpo-name", "", "Display name of the GPO to inspect")
	gpoGUID := fs.String("gpo-guid", "", "GUID of the GPO to inspect")
	domain := fs.String("domain", "", "FQDN of the domain containing the GPO")
	server := fs.String("server", "", "Domain controller to contact")
	script := fs.Bool("script", false, "Print the generated PowerShell script instead of running it")
	output := fs.String("output", "", "Write the generated PowerShell script to a file")
	dryRun := fs.Bool("dry-run", false, "Print Get-GPRegistryValue command without running it")
	asJSON := fs.Bool("json", false, "Print GPO status output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy gpo-status does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyGPOStatus(context.Background(), defaults.WindowsPolicyGPOStatusOptions{
		GPOName: *gpoName,
		GPOGUID: *gpoGUID,
		Domain:  *domain,
		Server:  *server,
		Script:  *script,
		Output:  *output,
		DryRun:  *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"gpo_status": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	if *script {
		fmt.Fprint(stdout, result.Script)
	} else {
		writeWindowsPolicyGPOStatus(stdout, result, *dryRun)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyRefresh(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy refresh", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	target := fs.String("target", "computer", "gpupdate target: computer or user")
	force := fs.Bool("force", false, "Reapply all Group Policy settings")
	wait := fs.String("wait", "", "Seconds to wait for policy processing: number, 0, or -1")
	logoff := fs.Bool("logoff", false, "Pass gpupdate /logoff")
	boot := fs.Bool("boot", false, "Pass gpupdate /boot")
	sync := fs.Bool("sync", false, "Pass gpupdate /sync")
	dryRun := fs.Bool("dry-run", false, "Print gpupdate command without running it")
	asJSON := fs.Bool("json", false, "Print refresh output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy refresh does not accept positional arguments", 2)
	}
	result, err := defaults.RefreshWindowsDefaultAssociationsGroupPolicy(context.Background(), defaults.WindowsPolicyGPUpdateOptions{
		Target: *target,
		Force:  *force,
		Wait:   *wait,
		Logoff: *logoff,
		Boot:   *boot,
		Sync:   *sync,
		DryRun: *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"refresh": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyRefresh(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyInvokeRefresh(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy invoke-refresh", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	computer := fs.String("computer", "", "Remote computer for Invoke-GPUpdate")
	target := fs.String("target", "computer", "Invoke-GPUpdate target: computer or user")
	randomDelay := fs.String("random-delay", "0", "RandomDelayInMinutes for Invoke-GPUpdate")
	force := fs.Bool("force", false, "Pass Invoke-GPUpdate -Force")
	logoff := fs.Bool("logoff", false, "Pass Invoke-GPUpdate -LogOff")
	boot := fs.Bool("boot", false, "Pass Invoke-GPUpdate -Boot")
	sync := fs.Bool("sync", false, "Pass Invoke-GPUpdate -Sync")
	asJob := fs.Bool("as-job", false, "Pass Invoke-GPUpdate -AsJob")
	script := fs.Bool("script", false, "Print the generated PowerShell script instead of running it")
	output := fs.String("output", "", "Write the generated PowerShell script to a file")
	dryRun := fs.Bool("dry-run", false, "Print Invoke-GPUpdate command without running it")
	asJSON := fs.Bool("json", false, "Print Invoke-GPUpdate output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy invoke-refresh does not accept positional arguments", 2)
	}
	result, err := defaults.InvokeWindowsDefaultAssociationsGroupPolicyRefresh(context.Background(), defaults.WindowsPolicyInvokeGPUpdateOptions{
		Computer:    *computer,
		Target:      *target,
		RandomDelay: *randomDelay,
		Force:       *force,
		Logoff:      *logoff,
		Boot:        *boot,
		Sync:        *sync,
		AsJob:       *asJob,
		Script:      *script,
		Output:      *output,
		DryRun:      *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"invoke_refresh": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	if *script {
		fmt.Fprint(stdout, result.Script)
	} else {
		writeWindowsPolicyInvokeRefresh(stdout, result, *dryRun)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyScript(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy script", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Policy XML source path to validate and copy in the script")
	destination := fs.String("destination", "", "Policy XML destination path for the script")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	deleteValue := fs.Bool("delete", false, "Generate a script that removes the policy pointer")
	deleteFile := fs.Bool("delete-file", false, "When --delete is used, also remove the policy XML file")
	gpupdate := fs.Bool("gpupdate", false, "Include gpupdate /target:computer /force in the generated script")
	asJSON := fs.Bool("json", false, "Print generated script as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy script does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyScript(defaults.WindowsPolicyScriptOptions{
		File:           *file,
		Destination:    *destination,
		CallbackScheme: *callbackScheme,
		Delete:         *deleteValue,
		DeleteFile:     *deleteFile,
		RefreshPolicy:  *gpupdate,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"script": result,
			"status": map[string]any{
				"exit_code": exitCode,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	fmt.Fprint(stdout, result.Content)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyRestore(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy restore", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Backup/default-association XML file to restore")
	destination := fs.String("destination", "", "Destination XML path for policy processing")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	allowIncomplete := fs.Bool("allow-incomplete", false, "Restore valid XML even if required browser targets are incomplete")
	dryRun := fs.Bool("dry-run", false, "Print planned restore operations without applying them")
	gpupdate := fs.Bool("gpupdate", false, "Run gpupdate /target:computer /force after restoring policy")
	asJSON := fs.Bool("json", false, "Print restore output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy restore does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy restore requires --file", 2)
	}
	result, err := defaults.InstallWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyInstallOptions{
		File:            *file,
		Destination:     *destination,
		CallbackScheme:  *callbackScheme,
		AllowIncomplete: *allowIncomplete,
		DryRun:          *dryRun,
		RefreshPolicy:   *gpupdate,
	})
	result.Operations = append([]string{"Restore Windows default-association policy from backup XML"}, result.Operations...)
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"restore": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyInstallResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyExport(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy export", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Destination XML file for exported default associations")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	dryRun := fs.Bool("dry-run", false, "Print planned export operations without applying them")
	asJSON := fs.Bool("json", false, "Print export output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy export does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy export requires --file", 2)
	}
	result, err := defaults.ExportWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyExportOptions{
		File:           *file,
		CallbackScheme: *callbackScheme,
		DryRun:         *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyExportResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyMerge(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy merge", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to update")
	progID := fs.String("prog-id", "", "Windows ProgID to write into the policy XML")
	applicationName := fs.String("application-name", "", "ApplicationName to include in updated XML records")
	mime := fs.String("mime", "", "MIME type to update")
	scheme := fs.String("scheme", "", "URL scheme to update")
	browser := fs.Bool("browser", false, "Update all default browser policy associations")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI to include with browser/protocol policy")
	version := fs.String("version", "", "DefaultAssociations Version attribute for suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on merged associations")
	dryRun := fs.Bool("dry-run", false, "Print planned merge operations without writing the XML file")
	asJSON := fs.Bool("json", false, "Print merge output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy merge does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy merge requires --file", 2)
	}
	if strings.TrimSpace(*progID) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy merge requires --prog-id", 2)
	}
	target, err := targetFromFlags(*mime, *scheme, *browser)
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 2)
	}
	result, err := defaults.MergeWindowsDefaultAssociationsPolicyXML(defaults.WindowsPolicyMergeOptions{
		File:            *file,
		Target:          target,
		ProgID:          *progID,
		ApplicationName: *applicationName,
		CallbackScheme:  *callbackScheme,
		Version:         *version,
		Suggested:       *suggested,
		DryRun:          *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyMergeResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyNormalize(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy normalize", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to normalize")
	output := fs.String("output", "", "Output XML file; defaults to rewriting --file")
	version := fs.String("version", "", "Override DefaultAssociations Version while normalizing")
	dryRun := fs.Bool("dry-run", false, "Print planned normalization without writing the XML file")
	asJSON := fs.Bool("json", false, "Print normalized policy output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy normalize does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy normalize requires --file", 2)
	}
	result, err := defaults.NormalizeWindowsDefaultAssociationsPolicyXML(defaults.WindowsPolicyNormalizeOptions{
		File:    *file,
		Output:  *output,
		Version: *version,
		DryRun:  *dryRun,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"normalize": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyNormalizeResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyProfile(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy profile", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	file := fs.String("file", "", "Default-association XML file to convert into a dfx profile")
	asJSON := fs.Bool("json", false, "Wrap converted profile output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy profile does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*file) == "" {
		return commandError(stdout, stderr, *asJSON, "windows-policy profile requires --file", 2)
	}
	content, err := os.ReadFile(expandPolicyFilePath(*file))
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 1)
	}
	result, err := defaults.WindowsPolicyProfileFromXML(content)
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	converted := profile{Defaults: result.Associations}
	if *asJSON {
		payload := map[string]any{
			"profile":    converted,
			"conversion": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"count":     len(converted.Defaults),
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(converted); encodeErr != nil {
		fmt.Fprintln(stderr, encodeErr)
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyStatus(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy status", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI that should be present in validation")
	asJSON := fs.Bool("json", false, "Print status output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy status does not accept positional arguments", 2)
	}
	result, err := defaults.WindowsDefaultAssociationsPolicyStatus(context.Background(), defaults.WindowsPolicyStatusOptions{
		CallbackScheme: *callbackScheme,
	})
	exitCode := 0
	if err != nil || !result.Healthy {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"status_result": result,
			"status": map[string]any{
				"exit_code":  exitCode,
				"healthy":    result.Healthy,
				"configured": result.Configured,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyStatus(stdout, result)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func windowsPolicyUninstall(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy uninstall", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	destination := fs.String("destination", "", "Policy XML path to delete when --delete-file is used")
	deleteFile := fs.Bool("delete-file", false, "Delete the policy XML file after removing the registry policy value")
	dryRun := fs.Bool("dry-run", false, "Print planned uninstall operations without applying them")
	gpupdate := fs.Bool("gpupdate", false, "Run gpupdate /target:computer /force after uninstalling policy")
	asJSON := fs.Bool("json", false, "Print uninstall output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy uninstall does not accept positional arguments", 2)
	}
	result, err := defaults.UninstallWindowsDefaultAssociationsPolicy(context.Background(), defaults.WindowsPolicyUninstallOptions{
		Destination:   *destination,
		DeleteFile:    *deleteFile,
		DryRun:        *dryRun,
		RefreshPolicy: *gpupdate,
	})
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if *asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyUninstallResult(stdout, result, *dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func expandPolicyFilePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	raw = os.ExpandEnv(raw)
	out := strings.Builder{}
	for i := 0; i < len(raw); {
		if raw[i] != '%' {
			out.WriteByte(raw[i])
			i++
			continue
		}
		if i+1 >= len(raw) {
			out.WriteByte(raw[i])
			i++
			continue
		}
		end := strings.IndexByte(raw[i+1:], '%')
		if end == -1 {
			out.WriteByte(raw[i])
			i++
			continue
		}
		name := strings.TrimSpace(raw[i+1 : i+1+end])
		if value, ok := lookupEnvCaseFold(name); ok {
			out.WriteString(value)
			i += end + 2
			continue
		}
		out.WriteString(raw[i : i+end+2])
		i += end + 2
	}
	return strings.TrimSpace(out.String())
}

func lookupEnvCaseFold(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	if value, ok := os.LookupEnv(name); ok {
		return value, true
	}
	for _, env := range os.Environ() {
		key, value, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(key), name) {
			return value, true
		}
	}
	return "", false
}

func windowsPolicyTemplate(args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("windows-policy template", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, windowsPolicyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	progID := fs.String("prog-id", "", "Windows ProgID to use in generated associations")
	applicationName := fs.String("application-name", "", "ApplicationName to include in generated XML")
	callbackScheme := fs.String("callback-scheme", "", "Callback scheme or URI to include")
	version := fs.String("version", "", "DefaultAssociations Version attribute for suggested associations")
	suggested := fs.Bool("suggested", false, "Emit Suggested=true on generated associations")
	asJSON := fs.Bool("json", false, "Print template output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy template does not accept positional arguments", 2)
	}
	template, err := defaults.WindowsBrowserPolicyXMLTemplateWithOptions(defaults.WindowsPolicyTemplateOptions{
		ProgID:          *progID,
		ApplicationName: *applicationName,
		CallbackScheme:  *callbackScheme,
		Version:         *version,
		Suggested:       *suggested,
	})
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 2)
	}
	if *asJSON {
		payload := map[string]any{
			"xml": template,
			"status": map[string]any{
				"exit_code": 0,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprint(stdout, template)
	return 0
}

func writeWindowsCapabilityAudit(stdout io.Writer, audit defaults.WindowsCapabilityAudit) {
	fmt.Fprintf(stdout, "platform: %s\n", audit.Platform)
	fmt.Fprintf(stdout, "prog_id: %s\n", audit.ProgID)
	fmt.Fprintf(stdout, "healthy: %t\n", audit.Healthy)
	fmt.Fprintf(stdout, "has_registration: %t\n", audit.HasRegistration)
	fmt.Fprintf(stdout, "has_capabilities: %t\n", audit.HasCapabilities)
	if audit.Command != "" {
		fmt.Fprintf(stdout, "command: %s\n", audit.Command)
	}
	if audit.DefaultIcon != "" {
		fmt.Fprintf(stdout, "default_icon: %s\n", audit.DefaultIcon)
	}
	for _, target := range audit.Targets {
		fmt.Fprintf(stdout, "target: %s declared=%t\n", target.Target.String(), target.Declared)
		if target.Error != "" {
			fmt.Fprintf(stdout, "target_error: %s %s\n", target.Target.String(), target.Error)
		}
	}
	for _, issue := range audit.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
}

func windowsPolicyTargetIdentifiers(target string) []string {
	switch strings.TrimSpace(strings.ToLower(target)) {
	case "text/html":
		return []string{".html", ".htm"}
	case "application/xhtml+xml":
		return []string{".xhtml", ".xht"}
	default:
		return []string{strings.TrimSpace(strings.ToLower(target))}
	}
}

func writeWindowsPolicyBackupResult(stdout io.Writer, result defaults.WindowsPolicyBackupResult, dryRun bool) {
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	fmt.Fprintf(stdout, "destination: %s\n", result.Destination)
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	if result.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyBundleResult(stdout io.Writer, result defaults.WindowsPolicyBundleResult) {
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	fmt.Fprintf(stdout, "output: %s\n", result.Output)
	if result.Archive != "" {
		fmt.Fprintf(stdout, "archive: %s\n", result.Archive)
	}
	fmt.Fprintf(stdout, "policy_path: %s\n", result.PolicyPath)
	fmt.Fprintf(stdout, "delete: %t\n", result.Delete)
	fmt.Fprintf(stdout, "delete_file: %t\n", result.DeleteFile)
	fmt.Fprintf(stdout, "dry_run: %t\n", result.DryRun)
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	if result.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, file := range result.Files {
		fmt.Fprintf(stdout, "file: %s %s %d", file.Type, file.Path, file.Bytes)
		if file.Description != "" {
			fmt.Fprintf(stdout, " %s", file.Description)
		}
		fmt.Fprintln(stdout)
	}
	for _, operation := range result.Operations {
		if result.DryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
}

func writeWindowsPolicyBundleInspectResult(stdout io.Writer, result defaults.WindowsPolicyBundleInspectResult) {
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	fmt.Fprintf(stdout, "archive: %t\n", result.Archive)
	if result.Kind != "" {
		fmt.Fprintf(stdout, "kind: %s\n", result.Kind)
	}
	fmt.Fprintf(stdout, "valid: %t\n", result.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Complete)
	fmt.Fprintf(stdout, "manifest_present: %t\n", result.ManifestPresent)
	if result.ManifestType != "" {
		fmt.Fprintf(stdout, "manifest_type: %s\n", result.ManifestType)
	}
	if result.Validation != nil {
		fmt.Fprintf(stdout, "xml_valid: %t\n", result.Validation.Valid)
		fmt.Fprintf(stdout, "xml_complete: %t\n", result.Validation.Complete)
		fmt.Fprintf(stdout, "xml_mandatory: %t\n", result.Validation.Mandatory)
	}
	for _, file := range result.Files {
		fmt.Fprintf(stdout, "file: %s present=%t expected=%t bytes=%d", file.Path, file.Present, file.Expected, file.Bytes)
		if file.Type != "" {
			fmt.Fprintf(stdout, " type=%s", file.Type)
		}
		fmt.Fprintln(stdout)
	}
	for _, missing := range result.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
}

func writeWindowsPolicyCompileResult(stdout io.Writer, result defaults.WindowsPolicyCompileResult, dryRun bool) {
	fmt.Fprintf(stdout, "file: %s\n", result.File)
	if result.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Suggested)
	for index, association := range result.Associations {
		fmt.Fprintf(stdout, "association: %d %s -> %s\n", index, association.Target().String(), association.App)
	}
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	if result.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyCSPResult(stdout io.Writer, result defaults.WindowsPolicyCSPResult) {
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	if result.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Suggested)
	for index, association := range result.Associations {
		fmt.Fprintf(stdout, "association: %d %s -> %s\n", index, association.Target().String(), association.App)
	}
	fmt.Fprintf(stdout, "loc_uri: %s\n", result.LocURI)
	fmt.Fprintf(stdout, "command: %s\n", result.Command)
	fmt.Fprintf(stdout, "format: %s\n", result.Format)
	fmt.Fprintf(stdout, "type: %s\n", result.Type)
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	if result.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	if result.Data != "" {
		fmt.Fprintf(stdout, "data: %s\n", result.Data)
	}
	if result.SyncML != "" {
		fmt.Fprintf(stdout, "syncml:\n%s", result.SyncML)
	}
	for _, operation := range result.Operations {
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
}

func writeWindowsPolicyIntuneResult(stdout io.Writer, result defaults.WindowsPolicyIntuneResult) {
	fmt.Fprintf(stdout, "name: %s\n", result.Name)
	if result.Description != "" {
		fmt.Fprintf(stdout, "description: %s\n", result.Description)
	}
	fmt.Fprintf(stdout, "oma_uri: %s\n", result.OMAURI)
	fmt.Fprintf(stdout, "data_type: %s\n", result.DataType)
	fmt.Fprintf(stdout, "valid: %t\n", result.CSP.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.CSP.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.CSP.Validation.Mandatory)
	if result.CSP.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.CSP.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.CSP.Validation.Suggested)
	for _, missing := range result.CSP.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.CSP.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "value: %s\n", result.Value)
}

func writeWindowsPolicyPOLResult(stdout io.Writer, result defaults.WindowsPolicyRegistryPOLResult) {
	fmt.Fprintf(stdout, "scope: %s\n", result.Scope)
	fmt.Fprintf(stdout, "registry_key: %s\n", result.RegistryKey)
	fmt.Fprintf(stdout, "value_name: %s\n", result.ValueName)
	if result.PolicyPath != "" {
		fmt.Fprintf(stdout, "policy_path: %s\n", result.PolicyPath)
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "output: %s\n", result.Output)
	}
	fmt.Fprintf(stdout, "delete: %t\n", result.Delete)
	fmt.Fprintf(stdout, "dry_run: %t\n", result.DryRun)
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
	fmt.Fprintf(stdout, "bytes: %d\n", result.Bytes)
	for _, operation := range result.Operations {
		if result.DryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	if result.Output == "" || result.DryRun {
		fmt.Fprintf(stdout, "content_base64: %s\n", result.ContentBase64)
	}
}

func writeWindowsPolicyGPResult(stdout io.Writer, result defaults.WindowsPolicyGPResultResult, dryRun bool) {
	fmt.Fprintf(stdout, "scope: %s\n", result.Scope)
	fmt.Fprintf(stdout, "format: %s\n", result.Format)
	if result.File != "" {
		fmt.Fprintf(stdout, "file: %s\n", result.File)
	}
	if result.System != "" {
		fmt.Fprintf(stdout, "system: %s\n", result.System)
	}
	if result.User != "" {
		fmt.Fprintf(stdout, "user: %s\n", result.User)
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyGPOReport(stdout io.Writer, result defaults.WindowsPolicyGPOReportResult, dryRun bool) {
	if result.GPOName != "" {
		fmt.Fprintf(stdout, "gpo_name: %s\n", result.GPOName)
	}
	if result.GPOGUID != "" {
		fmt.Fprintf(stdout, "gpo_guid: %s\n", result.GPOGUID)
	}
	fmt.Fprintf(stdout, "all: %t\n", result.All)
	fmt.Fprintf(stdout, "format: %s\n", result.ReportType)
	if result.File != "" {
		fmt.Fprintf(stdout, "file: %s\n", result.File)
	}
	if result.Domain != "" {
		fmt.Fprintf(stdout, "domain: %s\n", result.Domain)
	}
	if result.Server != "" {
		fmt.Fprintf(stdout, "server: %s\n", result.Server)
	}
	if result.OutputFile != "" {
		fmt.Fprintf(stdout, "output: %s\n", result.OutputFile)
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "command_output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyGPOBackup(stdout io.Writer, result defaults.WindowsPolicyGPOBackupResult, dryRun bool) {
	if result.GPOName != "" {
		fmt.Fprintf(stdout, "gpo_name: %s\n", result.GPOName)
	}
	if result.GPOGUID != "" {
		fmt.Fprintf(stdout, "gpo_guid: %s\n", result.GPOGUID)
	}
	fmt.Fprintf(stdout, "all: %t\n", result.All)
	fmt.Fprintf(stdout, "path: %s\n", result.Path)
	if result.Comment != "" {
		fmt.Fprintf(stdout, "comment: %s\n", result.Comment)
	}
	if result.Domain != "" {
		fmt.Fprintf(stdout, "domain: %s\n", result.Domain)
	}
	if result.Server != "" {
		fmt.Fprintf(stdout, "server: %s\n", result.Server)
	}
	fmt.Fprintf(stdout, "what_if: %t\n", result.WhatIf)
	if result.OutputFile != "" {
		fmt.Fprintf(stdout, "output: %s\n", result.OutputFile)
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "command_output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyGPORestore(stdout io.Writer, result defaults.WindowsPolicyGPORestoreResult, dryRun bool) {
	if result.GPOName != "" {
		fmt.Fprintf(stdout, "gpo_name: %s\n", result.GPOName)
	}
	if result.GPOGUID != "" {
		fmt.Fprintf(stdout, "gpo_guid: %s\n", result.GPOGUID)
	}
	fmt.Fprintf(stdout, "path: %s\n", result.Path)
	if result.Domain != "" {
		fmt.Fprintf(stdout, "domain: %s\n", result.Domain)
	}
	if result.Server != "" {
		fmt.Fprintf(stdout, "server: %s\n", result.Server)
	}
	fmt.Fprintf(stdout, "what_if: %t\n", result.WhatIf)
	if result.OutputFile != "" {
		fmt.Fprintf(stdout, "output: %s\n", result.OutputFile)
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "command_output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyGPOStatus(stdout io.Writer, result defaults.WindowsPolicyGPOStatusResult, dryRun bool) {
	if result.GPOName != "" {
		fmt.Fprintf(stdout, "gpo_name: %s\n", result.GPOName)
	}
	if result.GPOGUID != "" {
		fmt.Fprintf(stdout, "gpo_guid: %s\n", result.GPOGUID)
	}
	fmt.Fprintf(stdout, "registry_key: %s\n", result.RegistryKey)
	fmt.Fprintf(stdout, "value_name: %s\n", result.ValueName)
	if result.Domain != "" {
		fmt.Fprintf(stdout, "domain: %s\n", result.Domain)
	}
	if result.Server != "" {
		fmt.Fprintf(stdout, "server: %s\n", result.Server)
	}
	if result.OutputFile != "" {
		fmt.Fprintf(stdout, "output: %s\n", result.OutputFile)
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "command_output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyRefresh(stdout io.Writer, result defaults.WindowsPolicyGPUpdateResult, dryRun bool) {
	if result.Target != "" {
		fmt.Fprintf(stdout, "target: %s\n", result.Target)
	}
	fmt.Fprintf(stdout, "force: %t\n", result.Force)
	if result.Wait != "" {
		fmt.Fprintf(stdout, "wait: %s\n", result.Wait)
	}
	fmt.Fprintf(stdout, "logoff: %t\n", result.Logoff)
	fmt.Fprintf(stdout, "boot: %t\n", result.Boot)
	fmt.Fprintf(stdout, "sync: %t\n", result.Sync)
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyInvokeRefresh(stdout io.Writer, result defaults.WindowsPolicyInvokeGPUpdateResult, dryRun bool) {
	if result.Computer != "" {
		fmt.Fprintf(stdout, "computer: %s\n", result.Computer)
	}
	if result.Target != "" {
		fmt.Fprintf(stdout, "target: %s\n", result.Target)
	}
	if result.RandomDelay != "" {
		fmt.Fprintf(stdout, "random_delay: %s\n", result.RandomDelay)
	}
	fmt.Fprintf(stdout, "force: %t\n", result.Force)
	fmt.Fprintf(stdout, "logoff: %t\n", result.Logoff)
	fmt.Fprintf(stdout, "boot: %t\n", result.Boot)
	fmt.Fprintf(stdout, "sync: %t\n", result.Sync)
	fmt.Fprintf(stdout, "as_job: %t\n", result.AsJob)
	if result.OutputFile != "" {
		fmt.Fprintf(stdout, "output: %s\n", result.OutputFile)
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "command_output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyDISMCommandResult(stdout, stderr io.Writer, asJSON bool, dryRun bool, result defaults.WindowsPolicyDISMResult, err error) int {
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	if asJSON {
		payload := map[string]any{
			"result": result,
			"status": map[string]any{
				"exit_code": exitCode,
				"changed":   result.Changed,
				"dry_run":   dryRun,
			},
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(payload); encodeErr != nil {
			fmt.Fprintln(stderr, encodeErr)
			return 1
		}
		return exitCode
	}
	writeWindowsPolicyDISMResult(stdout, result, dryRun)
	if err != nil {
		fmt.Fprintln(stderr, err)
	}
	return exitCode
}

func writeWindowsPolicyDISMResult(stdout io.Writer, result defaults.WindowsPolicyDISMResult, dryRun bool) {
	fmt.Fprintf(stdout, "mode: %s\n", result.Mode)
	if result.File != "" {
		fmt.Fprintf(stdout, "file: %s\n", result.File)
	}
	if result.Image != "" {
		fmt.Fprintf(stdout, "image: %s\n", result.Image)
	} else {
		fmt.Fprintln(stdout, "image: online")
	}
	if len(result.Command) > 0 {
		fmt.Fprintf(stdout, "command: %s\n", strings.Join(result.Command, " "))
	}
	if result.Output != "" {
		fmt.Fprintf(stdout, "output:\n%s\n", result.Output)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsRegisteredApplications(stdout io.Writer, result defaults.WindowsRegisteredApplicationsResult) {
	fmt.Fprintf(stdout, "platform: %s\n", result.Platform)
	if result.Query != "" {
		fmt.Fprintf(stdout, "query: %s\n", result.Query)
	}
	fmt.Fprintf(stdout, "count: %d\n", len(result.Applications))
	for _, app := range result.Applications {
		displayName := app.ApplicationName
		if displayName == "" {
			displayName = app.Name
		}
		fmt.Fprintf(stdout, "application: %s scope=%s browser_candidate=%t\n", displayName, app.Scope, app.BrowserCandidate)
		fmt.Fprintf(stdout, "registered_name: %s\n", app.Name)
		fmt.Fprintf(stdout, "capabilities_key: %s\n", app.CapabilitiesKey)
		for _, association := range app.Associations {
			fmt.Fprintf(stdout, "association: %s %s -> %s", association.Kind, association.Identifier, association.ProgID)
			if len(association.Targets) > 0 {
				fmt.Fprintf(stdout, " targets=%s", strings.Join(association.Targets, ","))
			}
			fmt.Fprintln(stdout)
		}
		for _, issue := range app.Issues {
			fmt.Fprintf(stdout, "issue: %s\n", issue)
		}
	}
	for _, operation := range result.Operations {
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
}

func writeWindowsPolicyDeployResult(stdout io.Writer, result defaults.WindowsPolicyDeployResult, dryRun bool) {
	fmt.Fprintf(stdout, "compile_file: %s\n", result.Compile.File)
	fmt.Fprintf(stdout, "install_destination: %s\n", result.Install.Destination)
	fmt.Fprintf(stdout, "valid: %t\n", result.Compile.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Compile.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Compile.Validation.Mandatory)
	if result.Compile.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Compile.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Compile.Validation.Suggested)
	fmt.Fprintf(stdout, "policy_refresh_requested: %t\n", result.Install.PolicyRefreshRequested)
	fmt.Fprintf(stdout, "policy_refreshed: %t\n", result.Install.PolicyRefreshed)
	fmt.Fprintf(stdout, "requires_sign_in: %t\n", result.Install.RequiresSignIn)
	for _, missing := range result.Compile.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Compile.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyDiffResult(stdout io.Writer, result defaults.WindowsPolicyDiffResult) {
	fmt.Fprintf(stdout, "desired_source: %s\n", result.DesiredSource)
	fmt.Fprintf(stdout, "current_source: %s\n", result.CurrentSource)
	fmt.Fprintf(stdout, "equal: %t\n", result.Equal)
	fmt.Fprintf(stdout, "desired_valid: %t\n", result.DesiredValidation.Valid)
	fmt.Fprintf(stdout, "desired_complete: %t\n", result.DesiredValidation.Complete)
	if result.DesiredValidation.Version != "" {
		fmt.Fprintf(stdout, "desired_version: %s\n", result.DesiredValidation.Version)
	}
	fmt.Fprintf(stdout, "desired_suggested: %t\n", result.DesiredValidation.Suggested)
	fmt.Fprintf(stdout, "current_valid: %t\n", result.CurrentValidation.Valid)
	fmt.Fprintf(stdout, "current_complete: %t\n", result.CurrentValidation.Complete)
	if result.CurrentValidation.Version != "" {
		fmt.Fprintf(stdout, "current_version: %s\n", result.CurrentValidation.Version)
	}
	fmt.Fprintf(stdout, "current_suggested: %t\n", result.CurrentValidation.Suggested)
	for _, entry := range result.Entries {
		fmt.Fprintf(stdout, "diff: %s status=%s current=%s desired=%s\n", entry.Target, entry.Status, entry.CurrentProgID, entry.DesiredProgID)
	}
	for _, operation := range result.Operations {
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
}

func writeWindowsPolicyInstallResult(stdout io.Writer, result defaults.WindowsPolicyInstallResult, dryRun bool) {
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	fmt.Fprintf(stdout, "destination: %s\n", result.Destination)
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	if result.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	fmt.Fprintf(stdout, "policy_refresh_requested: %t\n", result.PolicyRefreshRequested)
	fmt.Fprintf(stdout, "policy_refreshed: %t\n", result.PolicyRefreshed)
	fmt.Fprintf(stdout, "requires_sign_in: %t\n", result.RequiresSignIn)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyExportResult(stdout io.Writer, result defaults.WindowsPolicyExportResult, dryRun bool) {
	fmt.Fprintf(stdout, "destination: %s\n", result.Destination)
	if result.Validation != nil {
		fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
		fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
		fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
		if result.Validation.Version != "" {
			fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
		}
		fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
		for _, missing := range result.Validation.Missing {
			fmt.Fprintf(stdout, "missing: %s\n", missing)
		}
		for _, issue := range result.Validation.Issues {
			fmt.Fprintf(stdout, "issue: %s\n", issue)
		}
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyMergeResult(stdout io.Writer, result defaults.WindowsPolicyMergeResult, dryRun bool) {
	fmt.Fprintf(stdout, "file: %s\n", result.File)
	fmt.Fprintf(stdout, "target: %s\n", result.Target.String())
	fmt.Fprintf(stdout, "prog_id: %s\n", result.ProgID)
	if result.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Suggested)
	for _, identifier := range result.Identifiers {
		fmt.Fprintf(stdout, "identifier: %s\n", identifier)
	}
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	if result.Validation.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Validation.Version)
	}
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyNormalizeResult(stdout io.Writer, result defaults.WindowsPolicyNormalizeResult, dryRun bool) {
	fmt.Fprintf(stdout, "source: %s\n", result.Source)
	fmt.Fprintf(stdout, "destination: %s\n", result.Destination)
	if result.Version != "" {
		fmt.Fprintf(stdout, "version: %s\n", result.Version)
	}
	fmt.Fprintf(stdout, "valid: %t\n", result.Validation.Valid)
	fmt.Fprintf(stdout, "complete: %t\n", result.Validation.Complete)
	fmt.Fprintf(stdout, "mandatory: %t\n", result.Validation.Mandatory)
	fmt.Fprintf(stdout, "suggested: %t\n", result.Validation.Suggested)
	for _, missing := range result.Validation.Missing {
		fmt.Fprintf(stdout, "missing: %s\n", missing)
	}
	for _, issue := range result.Validation.Issues {
		fmt.Fprintf(stdout, "issue: %s\n", issue)
	}
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func writeWindowsPolicyStatus(stdout io.Writer, result defaults.WindowsPolicyStatusResult) {
	fmt.Fprintf(stdout, "platform: %s\n", result.Platform)
	fmt.Fprintf(stdout, "configured: %t\n", result.Configured)
	fmt.Fprintf(stdout, "healthy: %t\n", result.Healthy)
	for _, source := range result.Sources {
		fmt.Fprintf(stdout, "policy_source: %s/%s\n", source.RegistryKey, source.ValueName)
		fmt.Fprintf(stdout, "policy_value: %s\n", source.Value)
		if source.Path != "" {
			fmt.Fprintf(stdout, "policy_path: %s\n", source.Path)
		}
		fmt.Fprintf(stdout, "policy_inline_xml: %t\n", source.InlineXML)
		fmt.Fprintf(stdout, "policy_readable: %t\n", source.Readable)
		if source.Validation != nil {
			fmt.Fprintf(stdout, "valid: %t\n", source.Validation.Valid)
			fmt.Fprintf(stdout, "complete: %t\n", source.Validation.Complete)
			fmt.Fprintf(stdout, "mandatory: %t\n", source.Validation.Mandatory)
			if source.Validation.Version != "" {
				fmt.Fprintf(stdout, "version: %s\n", source.Validation.Version)
			}
			fmt.Fprintf(stdout, "suggested: %t\n", source.Validation.Suggested)
			for _, missing := range source.Validation.Missing {
				fmt.Fprintf(stdout, "missing: %s\n", missing)
			}
			for _, issue := range source.Validation.Issues {
				fmt.Fprintf(stdout, "issue: %s\n", issue)
			}
		}
		for _, issue := range source.Issues {
			fmt.Fprintf(stdout, "issue: %s\n", issue)
		}
	}
	for _, operation := range result.Operations {
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
}

func writeWindowsPolicyUninstallResult(stdout io.Writer, result defaults.WindowsPolicyUninstallResult, dryRun bool) {
	fmt.Fprintf(stdout, "registry_key: %s\n", result.RegistryKey)
	fmt.Fprintf(stdout, "value_name: %s\n", result.ValueName)
	if result.Destination != "" {
		fmt.Fprintf(stdout, "destination: %s\n", result.Destination)
	}
	fmt.Fprintf(stdout, "deleted_file: %t\n", result.DeletedFile)
	fmt.Fprintf(stdout, "policy_refresh_requested: %t\n", result.PolicyRefreshRequested)
	fmt.Fprintf(stdout, "policy_refreshed: %t\n", result.PolicyRefreshed)
	fmt.Fprintf(stdout, "requires_sign_in: %t\n", result.RequiresSignIn)
	for _, operation := range result.Operations {
		if dryRun {
			fmt.Fprintf(stdout, "would: %s\n", operation)
			continue
		}
		fmt.Fprintf(stdout, "operation: %s\n", operation)
	}
	fmt.Fprintf(stdout, "changed: %t\n", result.Changed)
}

func get(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, getJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	mime := fs.String("mime", "", "MIME type to inspect")
	scheme := fs.String("scheme", "", "URL scheme to inspect")
	browser := fs.Bool("browser", false, "Inspect the default browser")
	asJSON := fs.Bool("json", false, "Print get output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "get does not accept positional arguments", 2)
	}

	target, err := targetFromFlags(*mime, *scheme, *browser)
	if err != nil {
		if err.Error() == "one of --mime, --scheme, or --browser is required" {
			return commandError(stdout, stderr, *asJSON, "get requires exactly one target selector; one of --mime, --scheme, or --browser is required", 2)
		}
		return commandError(stdout, stderr, *asJSON, err.Error(), 2)
	}

	app, err := provider.Get(ctx, target)
	if err != nil {
		return commandError(stdout, stderr, *asJSON, err.Error(), 1)
	}
	if *asJSON {
		payload := map[string]any{
			"target": target,
			"app":    app,
			"status": map[string]any{
				"exit_code": 0,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	fmt.Fprintln(stdout, app)
	return 0
}

func set(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	flagArgs, positionalApp, positionalErr := splitSetAppArgument(args)
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	wantsJSON := argsWantJSON(flagArgs, setJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	mime := fs.String("mime", "", "MIME type to update")
	scheme := fs.String("scheme", "", "URL scheme to update")
	browser := fs.Bool("browser", false, "Update all default browser associations")
	app := fs.String("app", "", "Application identifier for the current platform")
	dryRun := fs.Bool("dry-run", false, "Print planned operations without applying them")
	asJSON := fs.Bool("json", false, "Print set output as JSON")
	if err := fs.Parse(flagArgs); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if positionalErr != nil {
		return commandError(stdout, stderr, *asJSON, positionalErr.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "set does not accept positional arguments", 2)
	}
	if strings.TrimSpace(*app) != "" && strings.TrimSpace(positionalApp) != "" {
		return commandError(stdout, stderr, *asJSON, "set accepts either --app or one positional app query, not both", 2)
	}

	target, err := targetFromFlags(*mime, *scheme, *browser)
	if err != nil {
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, nil)
	}
	appQuery := strings.TrimSpace(*app)
	if appQuery == "" {
		appQuery = strings.TrimSpace(positionalApp)
	}
	resolution, err := defaults.ResolveApp(ctx, provider, appQuery, target)
	if err != nil {
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, map[string]any{
			"target":    target,
			"app_query": appQuery,
		})
	}
	association := defaults.Association{Kind: target.Kind, Value: target.Value, App: resolution.App}
	if err := association.Validate(); err != nil {
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, map[string]any{
			"association":    association,
			"app_resolution": resolution,
		})
	}

	result, err := provider.Set(ctx, association, defaults.SetOptions{DryRun: *dryRun})
	if err != nil {
		return mutationError(stdout, stderr, *asJSON, err.Error(), 1, *dryRun, result.Changed, result, map[string]any{
			"association":    association,
			"app_resolution": resolution,
		})
	}
	if *asJSON {
		payload := map[string]any{
			"association":    association,
			"app_resolution": resolution,
			"result":         result,
			"status": map[string]any{
				"exit_code": 0,
				"changed":   result.Changed,
				"dry_run":   *dryRun,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	}
	writeResult(stdout, result, *dryRun)
	return 0
}

func splitSetAppArgument(args []string) ([]string, string, error) {
	flagArgs := make([]string, 0, len(args))
	var positional []string
	valueFlags := flagNames("app", "mime", "scheme")

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			flagArgs = append(flagArgs, arg)
			name, _, hasValue := strings.Cut(arg, "=")
			if valueFlags[name] && !hasValue {
				if i+1 < len(args) {
					i++
					flagArgs = append(flagArgs, args[i])
				}
			}
			continue
		}
		positional = append(positional, arg)
	}

	filtered := positional[:0]
	for _, value := range positional {
		value = strings.TrimSpace(value)
		if value != "" {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) > 1 {
		return flagArgs, "", fmt.Errorf("set accepts at most one positional app query")
	}
	if len(filtered) == 1 {
		return flagArgs, filtered[0], nil
	}
	return flagArgs, "", nil
}

func apply(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	if hasHelpFlag(args) {
		usage(stdout)
		return 0
	}
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	wantsJSON := argsWantJSON(args, applyJSONFlags)
	if wantsJSON {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	dryRun := fs.Bool("dry-run", false, "Print planned operations without applying them")
	asJSON := fs.Bool("json", false, "Print apply output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 1 {
		return mutationValidationError(stdout, stderr, *asJSON, "apply requires exactly one profile path", 2, *dryRun, nil)
	}

	cfg, err := readProfile(expandPolicyFilePath(fs.Arg(0)))
	if err != nil {
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 1, *dryRun, nil)
	}
	associations, failedIndex, failedAssociation, err := validateProfile(cfg)
	if err != nil {
		fields := map[string]any{}
		if failedIndex >= 0 {
			fields["failed_index"] = failedIndex
			fields["association"] = failedAssociation
		}
		return mutationValidationError(stdout, stderr, *asJSON, err.Error(), 2, *dryRun, fields)
	}

	type applyResult struct {
		Index         int                    `json:"index"`
		Association   defaults.Association   `json:"association"`
		AppResolution defaults.AppResolution `json:"app_resolution"`
		Result        defaults.SetResult     `json:"result"`
	}

	results := make([]applyResult, 0, len(associations))
	for index, association := range associations {
		resolution, err := defaults.ResolveApp(ctx, provider, association.App, association.Target())
		if err != nil {
			changed := false
			for _, previous := range results {
				if previous.Result.Changed {
					changed = true
					break
				}
			}
			return mutationError(stdout, stderr, *asJSON, fmt.Sprintf("defaults[%d]: %v", index, err), 2, *dryRun, changed, defaults.SetResult{}, map[string]any{
				"failed_index": index,
				"association":  association,
				"results":      results,
			})
		}
		association.App = resolution.App
		result, err := provider.Set(ctx, association, defaults.SetOptions{DryRun: *dryRun})
		if err != nil {
			changed := result.Changed
			for _, previous := range results {
				if previous.Result.Changed {
					changed = true
					break
				}
			}
			return mutationError(stdout, stderr, *asJSON, fmt.Sprintf("defaults[%d]: %v", index, err), 1, *dryRun, changed, result, map[string]any{
				"failed_index":   index,
				"association":    association,
				"app_resolution": resolution,
				"results":        results,
			})
		}
		if *asJSON {
			results = append(results, applyResult{Index: index, Association: association, AppResolution: resolution, Result: result})
			continue
		}
		writeResult(stdout, result, *dryRun)
	}
	if *asJSON {
		changed := false
		for _, result := range results {
			if result.Result.Changed {
				changed = true
				break
			}
		}
		payload := map[string]any{
			"results": results,
			"status": map[string]any{
				"exit_code": 0,
				"changed":   changed,
				"dry_run":   *dryRun,
			},
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(payload); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	return 0
}

func readProfile(path string) (profile, error) {
	file, err := os.Open(path)
	if err != nil {
		return profile{}, err
	}
	defer file.Close()

	var cfg profile
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return profile{}, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return profile{}, errors.New("profile contains trailing JSON data")
		}
		return profile{}, err
	}
	return cfg, nil
}

func validateProfile(cfg profile) ([]defaults.Association, int, defaults.Association, error) {
	if len(cfg.Defaults) == 0 {
		return nil, -1, defaults.Association{}, errors.New("profile contains no defaults")
	}
	associations := make([]defaults.Association, 0, len(cfg.Defaults))
	seenTargets := map[string]int{}
	seenPrimaryTargets := map[string]string{}
	for index, association := range cfg.Defaults {
		association = association.Normalized()
		if err := association.Validate(); err != nil {
			return nil, index, association, fmt.Errorf("defaults[%d]: %v", index, err)
		}
		primaryTargetKey := association.Target().String()
		for _, targetKey := range applyTargetKeys(association) {
			if firstIndex, ok := seenTargets[targetKey]; ok {
				conflict := "overlapping"
				if primaryTargetKey == targetKey && seenPrimaryTargets[targetKey] == targetKey {
					conflict = "duplicate"
				}
				return nil, index, association, fmt.Errorf("defaults[%d]: %s target %s; duplicate or overlapping target %s already defined at defaults[%d]", index, conflict, targetKey, targetKey, firstIndex)
			}
			seenTargets[targetKey] = index
			seenPrimaryTargets[targetKey] = primaryTargetKey
		}
		associations = append(associations, association)
	}
	return associations, -1, defaults.Association{}, nil
}

func commandError(stdout, stderr io.Writer, asJSON bool, message string, exitCode int) int {
	if !asJSON {
		fmt.Fprintln(stderr, message)
		return exitCode
	}
	payload := map[string]any{
		"error": message,
		"status": map[string]any{
			"exit_code":  exitCode,
			"would_fail": true,
		},
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return exitCode
}

func profileValidationError(stdout, stderr io.Writer, asJSON bool, path string, message string, exitCode int, failedIndex int, association defaults.Association) int {
	if !asJSON {
		fmt.Fprintln(stderr, message)
		return exitCode
	}
	status := map[string]any{
		"exit_code":  exitCode,
		"would_fail": true,
		"valid":      false,
	}
	payload := map[string]any{
		"error": message,
		"profile": profileValidationReport{
			Path:  path,
			Valid: false,
		},
		"status": status,
	}
	if failedIndex >= 0 {
		payload["failed_index"] = failedIndex
		payload["association"] = association
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return exitCode
}

func profileTemplateError(stdout, stderr io.Writer, asJSON bool, message string, exitCode int, failedIndex int, association defaults.Association, cfg profile) int {
	if !asJSON {
		fmt.Fprintln(stderr, message)
		return exitCode
	}
	payload := map[string]any{
		"error": message,
		"profile": profileValidationReport{
			Valid:    false,
			Count:    len(cfg.Defaults),
			Defaults: cfg.Defaults,
		},
		"status": map[string]any{
			"exit_code":  exitCode,
			"would_fail": true,
			"valid":      false,
		},
	}
	if failedIndex >= 0 {
		payload["failed_index"] = failedIndex
		payload["association"] = association
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return exitCode
}

func openTestReportError(stdout, stderr io.Writer, asJSON bool, message string, exitCode int, report openTestReport) int {
	if !asJSON {
		fmt.Fprintf(stdout, "target: %s\n", report.Target.String())
		if report.ExpectedApp != "" {
			fmt.Fprintf(stdout, "expected: %s\n", report.ExpectedApp)
		}
		if report.ActualApp != "" {
			fmt.Fprintf(stdout, "actual: %s\n", report.ActualApp)
		}
		if report.Matched != nil {
			fmt.Fprintf(stdout, "matched: %t\n", *report.Matched)
		}
		writeOpenTestReportDetails(stdout, report)
		fmt.Fprintln(stderr, message)
		return exitCode
	}
	payload := map[string]any{
		"error":  message,
		"report": report,
		"status": map[string]any{
			"exit_code":  exitCode,
			"would_fail": true,
			"launched":   report.Launched,
		},
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return exitCode
}

func openTestError(stdout, stderr io.Writer, asJSON bool, message string, exitCode int, target *defaults.Target) int {
	if !asJSON {
		fmt.Fprintln(stderr, message)
		return exitCode
	}
	payload := map[string]any{
		"error": message,
		"status": map[string]any{
			"exit_code":  exitCode,
			"would_fail": true,
			"launched":   false,
		},
	}
	if target != nil {
		payload["target"] = *target
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return exitCode
}

func writeOpenTestReportDetails(stdout io.Writer, report openTestReport) {
	fmt.Fprintf(stdout, "launched: %t\n", report.Launched)
	if report.Launch != nil {
		fmt.Fprintf(stdout, "launch.subject: %s\n", report.Launch.Subject)
		fmt.Fprintf(stdout, "launch.command: %s\n", report.Launch.Command)
		if len(report.Launch.Args) > 0 {
			fmt.Fprintf(stdout, "launch.args: %s\n", strings.Join(report.Launch.Args, " "))
		}
	}
	for _, evidence := range report.Evidence {
		fmt.Fprintf(stdout, "evidence: %s\n", evidence)
	}
	for _, note := range report.Notes {
		fmt.Fprintf(stdout, "note: %s\n", note)
	}
}

func mutationValidationError(stdout, stderr io.Writer, asJSON bool, message string, exitCode int, dryRun bool, fields map[string]any) int {
	return mutationError(stdout, stderr, asJSON, message, exitCode, dryRun, false, defaults.SetResult{}, fields)
}

func mutationError(stdout, stderr io.Writer, asJSON bool, message string, exitCode int, dryRun bool, changed bool, result defaults.SetResult, fields map[string]any) int {
	if !asJSON {
		if hasMutationResult(result) {
			writeResult(stdout, result, dryRun)
		}
		fmt.Fprintln(stderr, message)
		return exitCode
	}
	payload := map[string]any{
		"error": message,
		"status": map[string]any{
			"exit_code":  exitCode,
			"would_fail": true,
			"changed":    changed,
			"dry_run":    dryRun,
		},
	}
	for key, value := range fields {
		payload[key] = value
	}
	if hasMutationResult(result) {
		payload["result"] = result
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return exitCode
}

func hasMutationResult(result defaults.SetResult) bool {
	return result.Changed || len(result.Operations) > 0
}

type jsonFlagScan struct {
	valueFlags map[string]bool
	boolFlags  map[string]bool
}

var (
	runJSONFlags             = jsonFlagScan{boolFlags: flagNames("json")}
	doctorJSONFlags          = jsonFlagScan{boolFlags: flagNames("browser", "dry-run", "fix", "json", "strict")}
	inspectJSONFlags         = jsonFlagScan{boolFlags: flagNames("json", "verbose")}
	getJSONFlags             = jsonFlagScan{valueFlags: flagNames("mime", "scheme"), boolFlags: flagNames("browser", "json")}
	openTestJSONFlags        = jsonFlagScan{valueFlags: flagNames("expected", "mime", "path", "scheme"), boolFlags: flagNames("browser", "callback", "json", "launch")}
	profileValidateJSONFlags = jsonFlagScan{boolFlags: flagNames("json")}
	profileTemplateJSONFlags = jsonFlagScan{valueFlags: flagNames("app", "callback-app", "callback-scheme"), boolFlags: flagNames("json")}
	windowsPolicyJSONFlags   = jsonFlagScan{valueFlags: flagNames("application-name", "archive", "callback-scheme", "cmd-id", "comment", "computer", "current", "description", "destination", "domain", "file", "format", "gpo-guid", "gpo-name", "image", "link-target", "loc-uri", "mime", "name", "order", "output", "path", "policy-path", "profile", "prog-id", "query", "random-delay", "scheme", "scope", "server", "system", "target", "user", "version", "wait"), boolFlags: flagNames("all", "allow-incomplete", "as-job", "boot", "browser", "create", "delete", "delete-file", "dry-run", "enforced", "force", "gpupdate", "json", "link-disabled", "logoff", "resolve-apps", "script", "suggested", "sync", "syncml", "what-if")}
	setJSONFlags             = jsonFlagScan{valueFlags: flagNames("app", "mime", "scheme"), boolFlags: flagNames("browser", "dry-run", "json")}
	applyJSONFlags           = jsonFlagScan{boolFlags: flagNames("dry-run", "json")}
)

func flagNames(names ...string) map[string]bool {
	flags := make(map[string]bool, len(names)*2)
	for _, name := range names {
		flags["-"+name] = true
		flags["--"+name] = true
	}
	return flags
}

func isJSONFlagArgument(arg string) bool {
	return arg == "--json" || arg == "-json" || strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json=")
}

func argsWantJSON(args []string, scan jsonFlagScan) bool {
	skipValue := false
	for _, arg := range args {
		if skipValue {
			skipValue = false
			continue
		}
		if arg == "--" {
			return false
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return false
		}

		name, value, hasValue := strings.Cut(arg, "=")
		switch name {
		case "--json", "-json":
			if !hasValue {
				return true
			}
			parsed, err := strconv.ParseBool(strings.TrimSpace(value))
			return err == nil && parsed
		}
		if scan.valueFlags[name] {
			skipValue = !hasValue
			continue
		}
		if scan.boolFlags[name] {
			if hasValue {
				if _, err := strconv.ParseBool(strings.TrimSpace(value)); err != nil {
					return false
				}
			}
			continue
		}
		return false
	}
	return false
}

func applyTargetKeys(association defaults.Association) []string {
	target := association.Target().Normalized()
	switch target.Kind {
	case defaults.KindBrowser:
		return []string{
			"browser:default",
			"scheme:http",
			"scheme:https",
			"mime:text/html",
			"mime:application/xhtml+xml",
		}
	case defaults.KindScheme:
		switch target.Value {
		case "http", "https":
			return []string{"scheme:" + target.Value}
		default:
			return []string{target.String()}
		}
	case defaults.KindMIME:
		switch target.Value {
		case "text/html", "application/xhtml+xml":
			return []string{"mime:" + target.Value}
		default:
			return []string{target.String()}
		}
	default:
		return []string{target.String()}
	}
}

func openTestTargetFromFlags(mime, scheme string, browser, callback bool) (defaults.Target, error) {
	selected := 0
	if strings.TrimSpace(mime) != "" {
		selected++
	}
	if strings.TrimSpace(scheme) != "" {
		selected++
	}
	if browser {
		selected++
	}
	if callback {
		selected++
	}
	if selected == 0 {
		return defaults.Target{}, errors.New("one of --mime, --scheme, --browser, or --callback is required")
	}
	if selected > 1 {
		return defaults.Target{}, errors.New("--mime, --scheme, --browser, and --callback are mutually exclusive")
	}
	if callback {
		callbackScheme := strings.TrimSpace(os.Getenv("DFX_CALLBACK_SCHEME"))
		if callbackScheme == "" {
			return defaults.Target{}, errors.New("--callback requires DFX_CALLBACK_SCHEME")
		}
		return targetFromFlags("", callbackScheme, false)
	}
	return targetFromFlags(mime, scheme, browser)
}

func openTestLaunchSubject(target defaults.Target, rawScheme string, callback bool, path string) (string, error) {
	target = target.Normalized()
	switch target.Kind {
	case defaults.KindMIME:
		path = expandPolicyFilePath(path)
		return path, nil
	case defaults.KindBrowser:
		return "https://example.com/", nil
	case defaults.KindScheme:
		raw := strings.TrimSpace(rawScheme)
		if callback {
			raw = strings.TrimSpace(os.Getenv("DFX_CALLBACK_SCHEME"))
		}
		if raw == "" {
			raw = target.Value + ":"
		}
		if strings.Contains(raw, ":") {
			return raw, nil
		}
		return target.Value + ":", nil
	default:
		return "", fmt.Errorf("unsupported launch target kind %q", target.Kind)
	}
}

func validateOpenTestMimeLaunchPath(path string) (string, int) {
	path = expandPolicyFilePath(path)
	if strings.TrimSpace(path) == "" {
		return "open-test --launch with --mime requires --path", 2
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("open-test --launch with --mime requires --path to an existing file (existing --path file required): %v", err), 1
	}
	if info.IsDir() {
		return fmt.Sprintf("open-test --launch with --mime requires --path to a file, not a directory (not a file): %q", path), 1
	}
	return "", 0
}

func defaultOpenTestLauncher(ctx context.Context, subject string) (string, []string, error) {
	command, args := openTestLauncherCommand(subject)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	path, err := exec.LookPath(command)
	if err != nil {
		return command, args, err
	}
	if err := exec.CommandContext(ctx, path, args...).Run(); err != nil {
		return path, args, err
	}
	return path, args, nil
}

func openTestLauncherCommand(subject string) (string, []string) {
	switch runtime.GOOS {
	case "darwin":
		return "open", []string{subject}
	case "windows":
		return "rundll32", []string{"url.dll,FileProtocolHandler", subject}
	default:
		return "xdg-open", []string{subject}
	}
}

func targetFromFlags(mime, scheme string, browser bool) (defaults.Target, error) {
	mime = strings.TrimSpace(mime)
	scheme = strings.TrimSpace(scheme)
	selected := 0
	if mime != "" {
		selected++
	}
	if scheme != "" {
		selected++
	}
	if browser {
		selected++
	}
	if selected == 0 {
		return defaults.Target{}, errors.New("one of --mime, --scheme, or --browser is required")
	}
	if selected > 1 {
		return defaults.Target{}, errors.New("--mime, --scheme, and --browser are mutually exclusive")
	}
	if mime != "" {
		target := (defaults.Target{Kind: defaults.KindMIME, Value: mime}).Normalized()
		if err := target.Validate(); err != nil {
			return defaults.Target{}, err
		}
		return target, nil
	}
	if browser {
		return defaults.Target{Kind: defaults.KindBrowser, Value: "default"}, nil
	}
	target := (defaults.Target{Kind: defaults.KindScheme, Value: scheme}).Normalized()
	if target.Value == "" {
		return defaults.Target{}, fmt.Errorf("invalid URL scheme %q", scheme)
	}
	if strings.ContainsAny(scheme, " \t\r\n") {
		return defaults.Target{}, fmt.Errorf("invalid URL scheme %q", scheme)
	}
	if err := target.Validate(); err != nil {
		return defaults.Target{}, err
	}
	return target, nil
}

func writeResult(stdout io.Writer, result defaults.SetResult, dryRun bool) {
	for _, op := range result.Operations {
		fmt.Fprintln(stdout, op)
	}
	fmt.Fprintf(stdout, "dry_run: %t\n", dryRun)
	if result.Changed {
		fmt.Fprintln(stdout, "changed: true")
	} else {
		fmt.Fprintln(stdout, "changed: false")
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `dfx manages default application associations.

Usage:
  dfx help
  dfx --help
  dfx -h
  dfx inspect [--verbose] [--json]
  dfx doctor --browser [--json] [--strict]
  dfx doctor --browser --fix [--dry-run] [--json]
  dfx get --browser [--json]
  dfx get --mime text/html [--json]
  dfx get --scheme https [--json]
  dfx get --scheme https://example.com/path [--json]
  dfx open-test --scheme myapp --expected com.example.App [--json]
  dfx open-test --callback --expected com.example.App [--json]
  dfx open-test --callback --expected com.example.App --launch [--json]
  dfx open-test --mime text/html --expected firefox.desktop [--json]
  dfx open-test --mime text/html --path ./sample.html --expected firefox.desktop --launch [--json]
  dfx open-test --scheme myapp://callback --expected com.example.App --launch [--json]
  dfx profile template --app firefox.desktop [--callback-scheme myapp --callback-app myapp.desktop] [--json]
  dfx profile validate [--json] dfx.json
  dfx windows-policy audit --prog-id ChromeHTML [--callback-scheme myapp] [--json]
  dfx windows-policy backup --file ActiveDefaultAssociations.xml [--callback-scheme myapp] [--dry-run] [--json]
  dfx windows-policy bundle --file DefaultAssociations.xml --output ./windows-policy-bundle [--archive windows-policy-bundle.zip] [--policy-path C:\ProgramData\dfx\DefaultAssociations.xml] [--gpo-name "Default App Policy" --link-target OU=Workstations,DC=example,DC=com] [--gpupdate] [--dry-run] [--json]
  dfx windows-policy bundle --delete --output ./windows-policy-removal [--archive windows-policy-removal.zip] [--policy-path C:\ProgramData\dfx\DefaultAssociations.xml] [--gpo-name "Default App Policy"] [--delete-file] [--gpupdate] [--json]
  dfx windows-policy bundle-inspect --path ./windows-policy-bundle [--callback-scheme myapp] [--json]
  dfx windows-policy bundle-inspect --archive windows-policy-bundle.zip [--callback-scheme myapp] [--json]
  dfx windows-policy compile --profile dfx.json --file DefaultAssociations.xml [--callback-scheme myapp] [--resolve-apps] [--suggested --version 2026.05.30] [--dry-run] [--json]
  dfx windows-policy csp --file DefaultAssociations.xml [--syncml] [--json]
  dfx windows-policy csp --profile dfx.json [--resolve-apps] [--suggested --version 2026.05.30] [--syncml] [--json]
  dfx windows-policy csp --delete [--syncml] [--json]
  dfx windows-policy deploy --profile dfx.json --file DefaultAssociations.xml [--destination C:\ProgramData\dfx\DefaultAssociations.xml] [--resolve-apps] [--suggested --version 2026.05.30] [--gpupdate] [--dry-run] [--json]
  dfx windows-policy diff --file DefaultAssociations.xml [--current CurrentAssociations.xml] [--callback-scheme myapp] [--json]
  dfx windows-policy export --file DefaultAssociations.xml [--callback-scheme myapp] [--dry-run] [--json]
  dfx windows-policy gpo --gpo-name "Default App Policy" --policy-path \\fileserver\share\DefaultAssociations.xml [--create --comment text] [--link-target OU=Workstations,DC=example,DC=com --enforced --order 1] [--domain example.com] [--server dc1.example.com] [--what-if] [--json]
 dfx windows-policy gpo-backup (--gpo-name "Default App Policy" | --gpo-guid GUID | --all) --path C:\GPOBackups [--comment text] [--domain example.com] [--server dc1.example.com] [--what-if] [--script] [--output Backup-GPO.ps1] [--dry-run] [--json]
  dfx windows-policy gpo-restore (--gpo-name "Default App Policy" | --gpo-guid GUID) --path C:\GPOBackups\\DefaultAppPolicy\2026-05-30 --what-if [--domain example.com] [--server dc1.example.com] [--script] [--output Restore-GPO.ps1] [--dry-run] [--json]
  dfx windows-policy gpo-report (--gpo-name "Default App Policy" | --gpo-guid GUID | --all) [--format html|xml] [--file GPOReport.html] [--domain example.com] [--server dc1.example.com] [--script] [--output Get-GPOReport.ps1] [--dry-run] [--json]
  dfx windows-policy gpo-status (--gpo-name "Default App Policy" | --gpo-guid GUID) [--domain example.com] [--server dc1.example.com] [--script] [--output Get-GPRegistryValue.ps1] [--dry-run] [--json]
  dfx windows-policy gpresult [--scope computer] [--format summary|verbose|superverbose|html|xml] [--file gpresult.html] [--system host] [--user DOMAIN\User] [--force] [--dry-run] [--json]
  dfx windows-policy import --file DefaultAssociations.xml [--image C:\mount\windows] [--dry-run] [--json]
  dfx windows-policy invoke-refresh [--computer WORKSTATION01] [--target computer|user] [--random-delay 0] [--force] [--logoff] [--boot] [--sync] [--as-job] [--script] [--output Invoke-GPUpdate.ps1] [--dry-run] [--json]
  dfx windows-policy intune --file DefaultAssociations.xml [--name "Windows default apps"] [--json]
  dfx windows-policy intune --profile dfx.json [--resolve-apps] [--suggested --version 2026.05.30] [--json]
  dfx windows-policy list [--image C:\mount\windows] [--json]
  dfx windows-policy lgpo [--policy-path C:\ProgramData\dfx\DefaultAssociations.xml] [--delete] [--json]
  dfx windows-policy merge --file DefaultAssociations.xml --prog-id ChromeHTML --browser [--callback-scheme myapp] [--suggested --version 2026.05.30] [--dry-run] [--json]
  dfx windows-policy normalize --file DefaultAssociations.xml [--output NormalizedAssociations.xml] [--version 2026.05.30] [--dry-run] [--json]
  dfx windows-policy pol [--policy-path C:\ProgramData\dfx\DefaultAssociations.xml] [--output Registry.pol] [--delete] [--dry-run] [--json]
  dfx windows-policy profile --file DefaultAssociations.xml [--json]
  dfx windows-policy registered [--query chrome] [--json]
  dfx windows-policy refresh [--target computer|user] [--force] [--wait 600] [--logoff] [--boot] [--sync] [--dry-run] [--json]
  dfx windows-policy reg [--policy-path C:\ProgramData\dfx\DefaultAssociations.xml] [--delete] [--json]
  dfx windows-policy remove [--image C:\mount\windows] [--dry-run] [--json]
  dfx windows-policy restore --file ActiveDefaultAssociations.xml [--destination C:\ProgramData\dfx\DefaultAssociations.xml] [--gpupdate] [--dry-run] [--json]
  dfx windows-policy script [--file DefaultAssociations.xml] [--destination C:\ProgramData\dfx\DefaultAssociations.xml] [--delete] [--delete-file] [--gpupdate] [--json]
  dfx windows-policy status [--callback-scheme myapp] [--json]
  dfx windows-policy targets [--callback-scheme myapp] [--json]
  dfx windows-policy validate --file DefaultAssociations.xml [--callback-scheme myapp] [--json]
  dfx windows-policy template --prog-id ChromeHTML [--application-name Chrome] [--callback-scheme myapp] [--suggested --version 2026.05.30] [--json]
  dfx windows-policy install --file DefaultAssociations.xml [--destination C:\ProgramData\dfx\DefaultAssociations.xml] [--gpupdate] [--dry-run] [--json]
  dfx windows-policy uninstall [--delete-file] [--gpupdate] [--dry-run] [--json]
  dfx set vivaldi --browser [--dry-run] [--json]
  dfx set --browser --app firefox.desktop [--dry-run] [--json]
  dfx set --mime text/html --app firefox.desktop [--dry-run] [--json]
  dfx set --scheme https --app firefox.desktop [--dry-run] [--json]
  dfx set --scheme https://example.com/path --app firefox.desktop [--dry-run] [--json]
  dfx apply [--dry-run] [--json] dfx.json

  Notes:
  --mime expects a MIME type such as text/html, not a filename extension such as .html.
  --scheme accepts either a raw scheme or a URI and normalizes it before use.
  set accepts either --app <id-or-query> or one positional app query and resolves
  partial app names to platform identifiers where possible.
  --mime, --scheme, --browser, and --callback for open-test are mutually exclusive.
  get/set/open-test require exactly one target selector flag.
  Set DFX_CALLBACK_SCHEME before doctor --browser or open-test --callback to check
  OAuth/deep-link callbacks.
  open-test is a safe handler-resolution preflight unless --launch is explicitly provided.
  open-test --launch executes the platform opener only after resolution and expected-handler checks pass; --path is only required for MIME launches and must point to an existing file. For non-MIME targets, --path is ignored and recorded as launch evidence.
  MIME --path values are expanded before launch with $VAR, ${VAR}, and %VAR%.
  If --expected does not match, launch is skipped and --path is not required for MIME checks.
  profile template emits a valid starter profile; add --json to wrap it with status metadata.
  profile validate checks profile syntax, target normalization, and duplicate/browser-overlap rules without calling platform providers.
  windows-policy validates, generates, or installs enterprise default-association XML without editing UserChoice.
  macOS writes use LaunchServices/duti when available; Windows writes use default-association XML policy, not UserChoice.
  JSON output includes a status object with the intended exit code and dry-run/change metadata where applicable.
  help and --help are plain usage paths and always print to stdout with exit code 0.
`)
}

func jsonArgProvided(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--json" || arg == "-json" || strings.HasPrefix(arg, "--json=") || strings.HasPrefix(arg, "-json=") {
			return true
		}
	}
	return false
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}
