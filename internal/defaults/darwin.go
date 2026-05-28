//go:build darwin

package defaults

import (
	"context"
	"errors"
)

type darwinProvider struct {
	runner commandRunner
}

func newDarwinProvider() Provider {
	return darwinProvider{runner: execRunner{}}
}

func (p darwinProvider) Inspect(context.Context) InspectReport {
	report := InspectReport{
		Platform: "darwin",
		Provider: "launchservices",
		CanRead:  false,
		CanWrite: false,
		Capabilities: Capabilities{
			CanReadCurrent:        false,
			CanWriteUserDefault:   false,
			CanWriteSystemDefault: false,
			PolicyRestricted:      false,
			SupportsBrowser:       true,
			SupportsScheme:        true,
			SupportsMIME:          false,
			SupportsContentType:   true,
		},
		Notes: []string{
			"macOS LaunchServices does not provide a stable built-in CLI for all default handlers",
		},
	}
	if _, err := p.runner.LookPath("duti"); err == nil {
		report.Provider = "duti"
		report.CanWrite = true
		report.Capabilities.CanWriteUserDefault = true
		report.Notes = append(report.Notes, "duti detected; full adapter support is pending")
	} else {
		report.Notes = append(report.Notes, "install duti to manage default handlers from the CLI")
	}
	return report
}

func (p darwinProvider) Get(context.Context, Target) (string, error) {
	return "", errors.New("macOS get support is not implemented yet")
}

func (p darwinProvider) Doctor(context.Context, DoctorOptions) (DoctorReport, error) {
	return DoctorReport{}, errors.New("macOS doctor support is not implemented yet")
}

func (p darwinProvider) DoctorFix(context.Context, DoctorFixOptions) (DoctorFixResult, error) {
	return DoctorFixResult{}, errors.New("macOS doctor fix support is not implemented yet")
}

func (p darwinProvider) Set(context.Context, Association, SetOptions) (SetResult, error) {
	return SetResult{}, errors.New("macOS set support is not implemented yet")
}
