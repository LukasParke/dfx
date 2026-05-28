//go:build windows

package defaults

import (
	"context"
	"errors"
)

type windowsProvider struct{}

func newWindowsProvider() Provider {
	return windowsProvider{}
}

func (windowsProvider) Inspect(context.Context) InspectReport {
	return InspectReport{
		Platform: "windows",
		Provider: "windows-default-apps",
		CanRead:  false,
		CanWrite: false,
		Capabilities: Capabilities{
			CanReadCurrent:        false,
			CanWriteUserDefault:   false,
			CanWriteSystemDefault: false,
			PolicyRestricted:      true,
			SupportsBrowser:       true,
			SupportsScheme:        true,
			SupportsMIME:          false,
			SupportsContentType:   true,
		},
		Notes: []string{
			"modern Windows protects default app changes with per-user hashes",
			"safe support requires policy-aware integration instead of direct registry writes",
		},
	}
}

func (windowsProvider) Get(context.Context, Target) (string, error) {
	return "", errors.New("Windows get support is not implemented yet")
}

func (windowsProvider) Doctor(context.Context, DoctorOptions) (DoctorReport, error) {
	return DoctorReport{}, errors.New("Windows doctor support is not implemented yet")
}

func (windowsProvider) DoctorFix(context.Context, DoctorFixOptions) (DoctorFixResult, error) {
	return DoctorFixResult{}, errors.New("Windows doctor fix support is not implemented yet")
}

func (windowsProvider) Set(context.Context, Association, SetOptions) (SetResult, error) {
	return SetResult{}, errors.New("Windows set support is not implemented yet")
}
