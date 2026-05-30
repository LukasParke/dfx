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
	if !options.Browser {
		return DoctorReport{}, fmt.Errorf("doctor currently requires --browser")
	}
	return DoctorReport{}, unsupportedOperationError(p.platform, p.reason, "doctor")
}

func (p unsupportedProvider) DoctorFix(_ context.Context, options DoctorFixOptions) (DoctorFixResult, error) {
	if !options.Browser {
		return DoctorFixResult{}, fmt.Errorf("doctor fix currently requires --browser")
	}
	return DoctorFixResult{}, unsupportedOperationError(p.platform, p.reason, "doctor fix")
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
