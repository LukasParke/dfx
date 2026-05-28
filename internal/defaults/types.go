package defaults

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type Kind string

const (
	KindMIME    Kind = "mime"
	KindScheme  Kind = "scheme"
	KindBrowser Kind = "browser"
)

type Target struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
}

func (t Target) Validate() error {
	value := strings.TrimSpace(t.Value)
	if value == "" && t.Kind != KindBrowser {
		return errors.New("target value is required")
	}
	switch t.Kind {
	case KindMIME:
		if !strings.Contains(value, "/") {
			return fmt.Errorf("invalid MIME type %q", t.Value)
		}
	case KindScheme:
		if strings.Contains(value, ":") || strings.Contains(value, "/") {
			return fmt.Errorf("invalid URL scheme %q", t.Value)
		}
	case KindBrowser:
		if value != "" && value != "default" {
			return fmt.Errorf("invalid browser target value %q", t.Value)
		}
	default:
		return fmt.Errorf("unsupported target kind %q", t.Kind)
	}
	return nil
}

func (t Target) String() string {
	return string(t.Kind) + ":" + t.Value
}

type Association struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	App   string `json:"app"`
}

func (a Association) Target() Target {
	return Target{Kind: a.Kind, Value: a.Value}
}

func (a Association) Validate() error {
	if err := a.Target().Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(a.App) == "" {
		return errors.New("app is required")
	}
	return nil
}

type SetOptions struct {
	DryRun bool
}

type SetResult struct {
	Changed    bool
	Operations []string
}

type Capabilities struct {
	CanReadCurrent        bool `json:"can_read_current"`
	CanWriteUserDefault   bool `json:"can_write_user_default"`
	CanWriteSystemDefault bool `json:"can_write_system_default"`
	PolicyRestricted      bool `json:"policy_restricted"`
	SupportsBrowser       bool `json:"supports_browser"`
	SupportsScheme        bool `json:"supports_scheme"`
	SupportsMIME          bool `json:"supports_mime"`
	SupportsContentType   bool `json:"supports_content_type"`
}

type InspectReport struct {
	Platform     string       `json:"platform"`
	Provider     string       `json:"provider"`
	CanRead      bool         `json:"can_read"`
	CanWrite     bool         `json:"can_write"`
	Capabilities Capabilities `json:"capabilities"`
	Notes        []string     `json:"notes,omitempty"`
}

type DoctorOptions struct {
	Browser bool
}

type DoctorFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Summary     string `json:"summary"`
	Details     string `json:"details,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type DoctorReport struct {
	Platform string          `json:"platform"`
	Scope    string          `json:"scope"`
	Healthy  bool            `json:"healthy"`
	Findings []DoctorFinding `json:"findings,omitempty"`
	Notes    []string        `json:"notes,omitempty"`
}

type DoctorFixOptions struct {
	Browser bool
	DryRun  bool
}

type DoctorFixResult struct {
	Changed    bool     `json:"changed"`
	Operations []string `json:"operations,omitempty"`
}

type Provider interface {
	Inspect(context.Context) InspectReport
	Doctor(context.Context, DoctorOptions) (DoctorReport, error)
	DoctorFix(context.Context, DoctorFixOptions) (DoctorFixResult, error)
	Get(context.Context, Target) (string, error)
	Set(context.Context, Association, SetOptions) (SetResult, error)
}
