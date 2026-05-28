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

func (p unsupportedProvider) Get(context.Context, Target) (string, error) {
	return "", fmt.Errorf("%s default application support is unavailable: %s", p.platform, p.reason)
}

func (p unsupportedProvider) Doctor(context.Context, DoctorOptions) (DoctorReport, error) {
	return DoctorReport{}, fmt.Errorf("%s default application support is unavailable: %s", p.platform, p.reason)
}

func (p unsupportedProvider) DoctorFix(context.Context, DoctorFixOptions) (DoctorFixResult, error) {
	return DoctorFixResult{}, fmt.Errorf("%s default application support is unavailable: %s", p.platform, p.reason)
}

func (p unsupportedProvider) Set(context.Context, Association, SetOptions) (SetResult, error) {
	return SetResult{}, fmt.Errorf("%s default application support is unavailable: %s", p.platform, p.reason)
}
