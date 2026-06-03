package defaults

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type Kind string

const (
	KindMIME        Kind = "mime"
	KindScheme      Kind = "scheme"
	KindBrowser     Kind = "browser"
	KindContentType Kind = "content_type"
)

type Target struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
}

func (t Target) Normalized() Target {
	kind := Kind(strings.ToLower(strings.TrimSpace(string(t.Kind))))
	value := strings.TrimSpace(t.Value)
	switch kind {
	case KindMIME:
		value = strings.ToLower(value)
	case KindBrowser:
		value = strings.ToLower(value)
		if value == "" {
			value = "default"
		}
	case KindScheme:
		value = NormalizeScheme(value)
	case KindContentType:
		value = strings.ToLower(value)
	}
	return Target{Kind: kind, Value: value}
}

func (t Target) Validate() error {
	normalized := t.Normalized()
	value := normalized.Value
	switch normalized.Kind {
	case KindMIME:
		if value == "" {
			return errors.New("target value is required")
		}
		if strings.HasPrefix(value, ".") {
			return fmt.Errorf("file extension %q is not a MIME type; use a MIME type such as application/pdf", t.Value)
		}
		if !validMIMEType(value) {
			return fmt.Errorf("invalid MIME type %q (expected type/subtype, for example text/html)", t.Value)
		}
	case KindScheme:
		if value == "" {
			return errors.New("target value is required")
		}
		if !validURLScheme(value) {
			return fmt.Errorf("invalid URL scheme %q", t.Value)
		}
		return nil
	case KindBrowser:
		if value != "" && value != "default" {
			return fmt.Errorf("invalid browser target value %q", t.Value)
		}
	case KindContentType:
		if value == "" {
			return errors.New("target value is required")
		}
	default:
		return fmt.Errorf("unsupported target kind %q", t.Kind)
	}
	return nil
}

func (t Target) String() string {
	return string(t.Kind) + ":" + t.Value
}

func NormalizeScheme(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "x-scheme-handler/") {
		value = value[len("x-scheme-handler/"):]
	}
	if before, _, ok := strings.Cut(value, "://"); ok {
		value = before
	} else if before, _, ok := strings.Cut(value, ":"); ok {
		value = before
	}
	if before, _, ok := strings.Cut(value, "/"); ok {
		value = before
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return strings.ToLower(value)
}

func validURLScheme(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		if i > 0 && (r == '+' || r == '-' || r == '.') {
			continue
		}
		return false
	}
	return true
}

func validMIMEType(value string) bool {
	typ, subtype, ok := strings.Cut(value, "/")
	if !ok || strings.Contains(subtype, "/") {
		return false
	}
	return validMIMEToken(typ) && validMIMEToken(subtype)
}

func validMIMEToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		switch r {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func normalizeCallbackScheme(raw string) string {
	return NormalizeScheme(raw)
}

type Association struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	App   string `json:"app"`
}

func (a Association) Normalized() Association {
	target := a.Target().Normalized()
	return Association{
		Kind:  target.Kind,
		Value: target.Value,
		App:   strings.TrimSpace(a.App),
	}
}

func (a Association) Target() Target {
	return Target{Kind: a.Kind, Value: a.Value}
}

func (a Association) Validate() error {
	normalized := a.Normalized()
	if err := normalized.Target().Validate(); err != nil {
		return err
	}
	if normalized.App == "" {
		return errors.New("app is required")
	}
	return nil
}

type SetOptions struct {
	DryRun bool
	System bool
}

type SetResult struct {
	Changed    bool     `json:"changed"`
	Operations []string `json:"operations,omitempty"`
}

type AppResolution struct {
	Query      string   `json:"query,omitempty"`
	App        string   `json:"app"`
	Source     string   `json:"source,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
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
	Browser     bool
	MIME        string
	Scheme      string
	ContentType string
	All         bool
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
	Browser     bool
	MIME        string
	Scheme      string
	ContentType string
	All         bool
	DryRun      bool
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

type AppResolver interface {
	ResolveApp(context.Context, string, Target) (AppResolution, error)
}

func ResolveApp(ctx context.Context, provider Provider, query string, target Target) (AppResolution, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return AppResolution{}, errors.New("app is required")
	}
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return AppResolution{}, err
	}
	if resolver, ok := provider.(AppResolver); ok {
		resolution, err := resolver.ResolveApp(ctx, query, target)
		if err != nil {
			return AppResolution{}, err
		}
		resolution.Query = query
		resolution.App = strings.TrimSpace(resolution.App)
		if resolution.App == "" {
			return AppResolution{}, errors.New("app resolver returned an empty app identifier")
		}
		return resolution, nil
	}
	return AppResolution{Query: query, App: query, Source: "literal"}, nil
}

func appendFindingRemediationOperations(ctx context.Context, provider Provider, operations []string) []string {
	report, err := provider.Doctor(ctx, DoctorOptions{Browser: true})
	if err != nil {
		return append(operations, "Diagnostic-specific remediation unavailable: "+err.Error())
	}
	seen := map[string]struct{}{}
	for _, finding := range report.Findings {
		remediation := strings.TrimSpace(finding.Remediation)
		if remediation == "" {
			continue
		}
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id) + "\x00" + strings.ToLower(remediation)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		operations = append(operations, fmt.Sprintf("Remediate %s: %s", id, remediation))
	}
	return operations
}
