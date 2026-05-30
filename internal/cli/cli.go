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
		return commandError(stdout, stderr, true, "windows-policy requires audit, validate, or template", 2)
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
		return commandError(stdout, stderr, wantsJSON, "windows-policy requires audit, validate, or template", 2)
	}
	switch args[0] {
	case "audit":
		return windowsPolicyAudit(args[1:], stdout, stderr)
	case "validate":
		return windowsPolicyValidate(args[1:], stdout, stderr)
	case "template":
		return windowsPolicyTemplate(args[1:], stdout, stderr)
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
	asJSON := fs.Bool("json", false, "Print template output as JSON")
	if err := fs.Parse(args); err != nil {
		return commandError(stdout, stderr, wantsJSON, err.Error(), 2)
	}
	if fs.NArg() != 0 {
		return commandError(stdout, stderr, *asJSON, "windows-policy template does not accept positional arguments", 2)
	}
	template, err := defaults.WindowsBrowserPolicyXMLTemplate(*progID, *applicationName, *callbackScheme)
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
	windowsPolicyJSONFlags   = jsonFlagScan{valueFlags: flagNames("application-name", "callback-scheme", "file", "prog-id"), boolFlags: flagNames("json")}
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
  dfx windows-policy validate --file DefaultAssociations.xml [--callback-scheme myapp] [--json]
  dfx windows-policy template --prog-id ChromeHTML [--application-name Chrome] [--callback-scheme myapp] [--json]
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
  windows-policy validates or generates enterprise default-association XML without editing UserChoice.
  On macOS and Windows, --fix --dry-run emits the supported remediation plan; unsafe native writes remain disabled.
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
