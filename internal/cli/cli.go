package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/LukasParke/dfx/internal/defaults"
)

type profile struct {
	Defaults []defaults.Association `json:"defaults"`
}

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}

	provider := defaults.CurrentProvider()
	ctx := context.Background()

	switch args[0] {
	case "inspect":
		return inspect(ctx, provider, args[1:], stdout, stderr)
	case "doctor":
		return doctor(ctx, provider, args[1:], stdout, stderr)
	case "get":
		return get(ctx, provider, args[1:], stdout, stderr)
	case "set":
		return set(ctx, provider, args[1:], stdout, stderr)
	case "apply":
		return apply(ctx, provider, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func doctor(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	browser := fs.Bool("browser", false, "Run browser-default diagnostics")
	asJSON := fs.Bool("json", false, "Print doctor output as JSON")
	strict := fs.Bool("strict", false, "Return non-zero when warnings are present")
	fix := fs.Bool("fix", false, "Apply safe automated remediations for the selected scope")
	dryRun := fs.Bool("dry-run", false, "Preview fix operations without applying them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "doctor does not accept positional arguments")
		return 2
	}
	if !*browser {
		fmt.Fprintln(stderr, "doctor currently requires --browser")
		return 2
	}
	if *dryRun && !*fix {
		fmt.Fprintln(stderr, "--dry-run requires --fix")
		return 2
	}

	report, err := provider.Doctor(ctx, defaults.DoctorOptions{Browser: *browser})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	var fixResult defaults.DoctorFixResult
	if *fix {
		fixResult, err = provider.DoctorFix(ctx, defaults.DoctorFixOptions{Browser: *browser, DryRun: *dryRun})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	shouldFail := !report.Healthy || (*strict && len(report.Findings) > 0)
	if *asJSON {
		payload := map[string]any{
			"report": report,
		}
		if *fix {
			payload["fix"] = fixResult
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
		for _, op := range fixResult.Operations {
			fmt.Fprintf(stdout, "fix: %s\n", op)
		}
		fmt.Fprintf(stdout, "fix.changed: %t\n", fixResult.Changed)
	}
	if shouldFail {
		return 1
	}
	return 0
}

func inspect(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verbose := fs.Bool("verbose", false, "Print extended capability details")
	asJSON := fs.Bool("json", false, "Print inspect output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "inspect does not accept positional arguments")
		return 2
	}

	report := provider.Inspect(ctx)
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
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

func get(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mime := fs.String("mime", "", "MIME type to inspect")
	scheme := fs.String("scheme", "", "URL scheme to inspect")
	browser := fs.Bool("browser", false, "Inspect the default browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target, err := targetFromFlags(*mime, *scheme, *browser)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	app, err := provider.Get(ctx, target)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, app)
	return 0
}

func set(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	mime := fs.String("mime", "", "MIME type to update")
	scheme := fs.String("scheme", "", "URL scheme to update")
	browser := fs.Bool("browser", false, "Update all default browser associations")
	app := fs.String("app", "", "Application identifier for the current platform")
	dryRun := fs.Bool("dry-run", false, "Print planned operations without applying them")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target, err := targetFromFlags(*mime, *scheme, *browser)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	association := defaults.Association{Kind: target.Kind, Value: target.Value, App: strings.TrimSpace(*app)}
	if err := association.Validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	result, err := provider.Set(ctx, association, defaults.SetOptions{DryRun: *dryRun})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	writeResult(stdout, result)
	return 0
}

func apply(ctx context.Context, provider defaults.Provider, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "Print planned operations without applying them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "apply requires exactly one profile path")
		return 2
	}

	file, err := os.Open(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer file.Close()

	var cfg profile
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if len(cfg.Defaults) == 0 {
		fmt.Fprintln(stderr, "profile contains no defaults")
		return 2
	}

	for index, association := range cfg.Defaults {
		if err := association.Validate(); err != nil {
			fmt.Fprintf(stderr, "defaults[%d]: %v\n", index, err)
			return 2
		}
		result, err := provider.Set(ctx, association, defaults.SetOptions{DryRun: *dryRun})
		if err != nil {
			fmt.Fprintf(stderr, "defaults[%d]: %v\n", index, err)
			return 1
		}
		writeResult(stdout, result)
	}
	return 0
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
		return defaults.Target{Kind: defaults.KindMIME, Value: mime}, nil
	}
	if browser {
		return defaults.Target{Kind: defaults.KindBrowser, Value: "default"}, nil
	}
	return defaults.Target{Kind: defaults.KindScheme, Value: scheme}, nil
}

func writeResult(stdout io.Writer, result defaults.SetResult) {
	for _, op := range result.Operations {
		fmt.Fprintln(stdout, op)
	}
	if result.Changed {
		fmt.Fprintln(stdout, "changed: true")
	} else {
		fmt.Fprintln(stdout, "changed: false")
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `dfx manages default application associations.

Usage:
  dfx inspect [--verbose] [--json]
  dfx doctor --browser [--json] [--strict]
  dfx doctor --browser --fix [--dry-run] [--json]
  dfx get --browser
  dfx get --mime text/html
  dfx get --scheme https
  dfx set --browser --app firefox.desktop
  dfx set --mime text/html --app firefox.desktop
  dfx set --scheme https --app firefox.desktop
  dfx apply [--dry-run] dfx.json
`)
}
