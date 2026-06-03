package defaults

import (
	"context"
	"fmt"
)

type unsupportedProvider struct {
	platform string
	reason   string
}

func (p unsupportedProvider) Inspect(context.Context) InspectReport {
	return InspectReport{
		Platform: p.platform,
		Provider: "unsupported",
		CanRead:  false,
		CanWrite: false,
		Capabilities: Capabilities{
			CanReadCurrent:        false,
			CanWriteUserDefault:   false,
			CanWriteSystemDefault: false,
			PolicyRestricted:      false,
			SupportsBrowser:       false,
			SupportsScheme:        false,
			SupportsMIME:          false,
			SupportsContentType:   false,
		},
		Notes: []string{p.reason},
	}
}

func (p unsupportedProvider) Get(_ context.Context, target Target) (string, error) {
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return "", err
	}
	return "", unsupportedOperationError(p.platform, p.reason, "get")
}

func (p unsupportedProvider) Doctor(_ context.Context, options DoctorOptions) (DoctorReport, error) {
	if err := validateDoctorOptions(options); err != nil {
		return DoctorReport{}, err
	}
	return DoctorReport{}, unsupportedOperationError(p.platform, p.reason, "doctor")
}

func (p unsupportedProvider) DoctorFix(_ context.Context, options DoctorFixOptions) (DoctorFixResult, error) {
	if err := validateDoctorFixOptions(options); err != nil {
		return DoctorFixResult{}, err
	}
	return DoctorFixResult{}, unsupportedOperationError(p.platform, p.reason, "doctor fix")
}

func validateDoctorOptions(options DoctorOptions) error {
	selected := 0
	if options.Browser {
		selected++
	}
	if options.MIME != "" {
		selected++
	}
	if options.Scheme != "" {
		selected++
	}
	if options.ContentType != "" {
		selected++
	}
	if options.All {
		selected++
	}
	if selected == 0 {
		return fmt.Errorf("doctor requires exactly one scope flag; one of --browser, --mime, --scheme, --content-type, or --all is required")
	}
	if selected > 1 {
		return fmt.Errorf("--browser, --mime, --scheme, --content-type, and --all are mutually exclusive")
	}
	return nil
}

func validateDoctorFixOptions(options DoctorFixOptions) error {
	selected := 0
	if options.Browser {
		selected++
	}
	if options.MIME != "" {
		selected++
	}
	if options.Scheme != "" {
		selected++
	}
	if options.ContentType != "" {
		selected++
	}
	if options.All {
		selected++
	}
	if selected == 0 {
		return fmt.Errorf("doctor fix requires exactly one scope flag; one of --browser, --mime, --scheme, --content-type, or --all is required")
	}
	if selected > 1 {
		return fmt.Errorf("--browser, --mime, --scheme, --content-type, and --all are mutually exclusive")
	}
	return nil
}

func (p unsupportedProvider) Set(_ context.Context, association Association, _ SetOptions) (SetResult, error) {
	association = association.Normalized()
	if err := association.Validate(); err != nil {
		return SetResult{}, err
	}
	return SetResult{}, unsupportedOperationError(p.platform, p.reason, "set")
}

func unsupportedOperationError(platform, reason, operation string) error {
	return fmt.Errorf("%s %s support is unavailable on this host: %s", platform, operation, reason)
}
