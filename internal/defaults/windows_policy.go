package defaults

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

const (
	windowsDefaultAssociationsPolicyRegistryKey   = `HKLM\Software\Policies\Microsoft\Windows\System`
	windowsDefaultAssociationsPolicyRegistryValue = "DefaultAssociationsConfiguration"
	windowsDefaultAssociationsPolicyFileEnv       = "DFX_WINDOWS_DEFAULT_ASSOCIATIONS_FILE"
	windowsDefaultAssociationsPolicyCSPLocURI     = "./Device/Vendor/MSFT/Policy/Config/ApplicationDefaults/DefaultAssociationsConfiguration"
)

func normalizeWindowsPolicyAssociationXMLText(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "\ufeff")
}

type WindowsPolicyAssociation struct {
	Identifier   string `json:"identifier"`
	ProgID       string `json:"prog_id,omitempty"`
	Application  string `json:"application_name,omitempty"`
	SuggestedSet bool   `json:"suggested_set,omitempty"`
	Suggested    bool   `json:"suggested,omitempty"`
}

type WindowsPolicyValidation struct {
	Valid     bool                       `json:"valid"`
	Complete  bool                       `json:"complete"`
	Mandatory bool                       `json:"mandatory"`
	Version   string                     `json:"version,omitempty"`
	Suggested bool                       `json:"suggested,omitempty"`
	Required  []string                   `json:"required"`
	Missing   []string                   `json:"missing,omitempty"`
	Issues    []string                   `json:"issues,omitempty"`
	Records   []WindowsPolicyAssociation `json:"records,omitempty"`
}

type WindowsCapabilityAudit struct {
	Platform        string                         `json:"platform"`
	ProgID          string                         `json:"prog_id"`
	Healthy         bool                           `json:"healthy"`
	HasRegistration bool                           `json:"has_registration"`
	HasCapabilities bool                           `json:"has_capabilities"`
	Command         string                         `json:"command,omitempty"`
	DefaultIcon     string                         `json:"default_icon,omitempty"`
	Targets         []WindowsCapabilityTargetAudit `json:"targets,omitempty"`
	Issues          []string                       `json:"issues,omitempty"`
}

type WindowsCapabilityTargetAudit struct {
	Target   Target `json:"target"`
	Declared bool   `json:"declared"`
	Error    string `json:"error,omitempty"`
}

type WindowsPolicyInstallOptions struct {
	File            string `json:"file"`
	Destination     string `json:"destination,omitempty"`
	CallbackScheme  string `json:"callback_scheme,omitempty"`
	AllowIncomplete bool   `json:"allow_incomplete,omitempty"`
	DryRun          bool   `json:"dry_run,omitempty"`
	RefreshPolicy   bool   `json:"refresh_policy,omitempty"`
}

type WindowsPolicyInstallResult struct {
	Changed                bool                    `json:"changed"`
	Source                 string                  `json:"source"`
	Destination            string                  `json:"destination"`
	Validation             WindowsPolicyValidation `json:"validation"`
	PolicyRefreshRequested bool                    `json:"policy_refresh_requested,omitempty"`
	PolicyRefreshed        bool                    `json:"policy_refreshed,omitempty"`
	RequiresSignIn         bool                    `json:"requires_sign_in,omitempty"`
	Operations             []string                `json:"operations,omitempty"`
}

type WindowsPolicyExportOptions struct {
	File           string `json:"file"`
	CallbackScheme string `json:"callback_scheme,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyExportResult struct {
	Changed     bool                     `json:"changed"`
	Destination string                   `json:"destination"`
	Validation  *WindowsPolicyValidation `json:"validation,omitempty"`
	Operations  []string                 `json:"operations,omitempty"`
}

type WindowsPolicyStatusOptions struct {
	CallbackScheme string `json:"callback_scheme,omitempty"`
}

type WindowsPolicyStatusSource struct {
	RegistryKey   string                   `json:"registry_key"`
	ValueName     string                   `json:"value_name"`
	Value         string                   `json:"value"`
	Path          string                   `json:"path,omitempty"`
	InlineXML     bool                     `json:"inline_xml,omitempty"`
	Readable      bool                     `json:"readable"`
	Validation    *WindowsPolicyValidation `json:"validation,omitempty"`
	Issues        []string                 `json:"issues,omitempty"`
	RequiredValue bool                     `json:"required_value,omitempty"`
}

type WindowsPolicyStatusResult struct {
	Platform   string                      `json:"platform"`
	Configured bool                        `json:"configured"`
	Healthy    bool                        `json:"healthy"`
	Sources    []WindowsPolicyStatusSource `json:"sources,omitempty"`
	Operations []string                    `json:"operations,omitempty"`
}

type WindowsPolicyUninstallOptions struct {
	Destination   string `json:"destination,omitempty"`
	DeleteFile    bool   `json:"delete_file,omitempty"`
	DryRun        bool   `json:"dry_run,omitempty"`
	RefreshPolicy bool   `json:"refresh_policy,omitempty"`
}

type WindowsPolicyUninstallResult struct {
	Changed                bool     `json:"changed"`
	RegistryKey            string   `json:"registry_key"`
	ValueName              string   `json:"value_name"`
	Destination            string   `json:"destination,omitempty"`
	DeletedFile            bool     `json:"deleted_file,omitempty"`
	PolicyRefreshRequested bool     `json:"policy_refresh_requested,omitempty"`
	PolicyRefreshed        bool     `json:"policy_refreshed,omitempty"`
	RequiresSignIn         bool     `json:"requires_sign_in,omitempty"`
	Operations             []string `json:"operations,omitempty"`
}

type WindowsPolicyMergeOptions struct {
	File            string `json:"file"`
	Target          Target `json:"target"`
	ProgID          string `json:"prog_id"`
	ApplicationName string `json:"application_name,omitempty"`
	CallbackScheme  string `json:"callback_scheme,omitempty"`
	Version         string `json:"version,omitempty"`
	Suggested       bool   `json:"suggested,omitempty"`
	DryRun          bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyMergeResult struct {
	Changed     bool                       `json:"changed"`
	File        string                     `json:"file"`
	Target      Target                     `json:"target"`
	ProgID      string                     `json:"prog_id"`
	Version     string                     `json:"version,omitempty"`
	Suggested   bool                       `json:"suggested,omitempty"`
	Identifiers []string                   `json:"identifiers,omitempty"`
	Validation  WindowsPolicyValidation    `json:"validation"`
	Records     []WindowsPolicyAssociation `json:"records,omitempty"`
	XML         string                     `json:"xml,omitempty"`
	Operations  []string                   `json:"operations,omitempty"`
}

type WindowsPolicyCompileOptions struct {
	File           string        `json:"file"`
	Associations   []Association `json:"associations"`
	CallbackScheme string        `json:"callback_scheme,omitempty"`
	Version        string        `json:"version,omitempty"`
	Suggested      bool          `json:"suggested,omitempty"`
	DryRun         bool          `json:"dry_run,omitempty"`
}

type WindowsPolicyAppResolutionOptions struct {
	Associations []Association `json:"associations"`
}

type WindowsPolicyAppResolution struct {
	Query      string      `json:"query"`
	Target     Target      `json:"target"`
	App        string      `json:"app"`
	Source     string      `json:"source,omitempty"`
	Candidates []string    `json:"candidates,omitempty"`
	Original   Association `json:"original"`
	Resolved   Association `json:"resolved"`
}

type WindowsPolicyAppResolutionResult struct {
	Associations []Association                `json:"associations"`
	Resolutions  []WindowsPolicyAppResolution `json:"resolutions,omitempty"`
	Operations   []string                     `json:"operations,omitempty"`
}

type WindowsPolicyCompileResult struct {
	Changed      bool                       `json:"changed"`
	File         string                     `json:"file"`
	Associations []Association              `json:"associations,omitempty"`
	Version      string                     `json:"version,omitempty"`
	Suggested    bool                       `json:"suggested,omitempty"`
	Validation   WindowsPolicyValidation    `json:"validation"`
	Records      []WindowsPolicyAssociation `json:"records,omitempty"`
	XML          string                     `json:"xml,omitempty"`
	Operations   []string                   `json:"operations,omitempty"`
}

type WindowsPolicyDeployOptions struct {
	File            string        `json:"file"`
	Destination     string        `json:"destination,omitempty"`
	Associations    []Association `json:"associations"`
	CallbackScheme  string        `json:"callback_scheme,omitempty"`
	Version         string        `json:"version,omitempty"`
	Suggested       bool          `json:"suggested,omitempty"`
	AllowIncomplete bool          `json:"allow_incomplete,omitempty"`
	DryRun          bool          `json:"dry_run,omitempty"`
	RefreshPolicy   bool          `json:"refresh_policy,omitempty"`
}

type WindowsPolicyDeployResult struct {
	Changed    bool                       `json:"changed"`
	Compile    WindowsPolicyCompileResult `json:"compile"`
	Install    WindowsPolicyInstallResult `json:"install"`
	Operations []string                   `json:"operations,omitempty"`
}

type WindowsPolicyDiffOptions struct {
	File           string `json:"file"`
	CurrentFile    string `json:"current_file,omitempty"`
	CallbackScheme string `json:"callback_scheme,omitempty"`
}

type WindowsPolicyDiffEntry struct {
	Target        string `json:"target"`
	CurrentProgID string `json:"current_prog_id,omitempty"`
	DesiredProgID string `json:"desired_prog_id,omitempty"`
	Status        string `json:"status"`
}

type WindowsPolicyDiffResult struct {
	Equal             bool                     `json:"equal"`
	DesiredSource     string                   `json:"desired_source"`
	CurrentSource     string                   `json:"current_source"`
	DesiredValidation WindowsPolicyValidation  `json:"desired_validation"`
	CurrentValidation WindowsPolicyValidation  `json:"current_validation"`
	Entries           []WindowsPolicyDiffEntry `json:"entries,omitempty"`
	Operations        []string                 `json:"operations,omitempty"`
}

type WindowsPolicyBundleOptions struct {
	File           string                  `json:"file,omitempty"`
	Associations   []Association           `json:"associations,omitempty"`
	CallbackScheme string                  `json:"callback_scheme,omitempty"`
	Version        string                  `json:"version,omitempty"`
	Suggested      bool                    `json:"suggested,omitempty"`
	Output         string                  `json:"output"`
	Archive        string                  `json:"archive,omitempty"`
	PolicyPath     string                  `json:"policy_path,omitempty"`
	RefreshPolicy  bool                    `json:"refresh_policy,omitempty"`
	Delete         bool                    `json:"delete,omitempty"`
	DeleteFile     bool                    `json:"delete_file,omitempty"`
	DryRun         bool                    `json:"dry_run,omitempty"`
	GPO            WindowsPolicyGPOOptions `json:"gpo,omitempty"`
}

type WindowsPolicyBundleFile struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Bytes       int    `json:"bytes"`
	Description string `json:"description,omitempty"`
}

type WindowsPolicyBundleResult struct {
	Source       string                    `json:"source"`
	Output       string                    `json:"output"`
	Archive      string                    `json:"archive,omitempty"`
	PolicyPath   string                    `json:"policy_path"`
	Delete       bool                      `json:"delete,omitempty"`
	DeleteFile   bool                      `json:"delete_file,omitempty"`
	DryRun       bool                      `json:"dry_run,omitempty"`
	Changed      bool                      `json:"changed"`
	Validation   WindowsPolicyValidation   `json:"validation"`
	Associations []Association             `json:"associations,omitempty"`
	Files        []WindowsPolicyBundleFile `json:"files,omitempty"`
	Operations   []string                  `json:"operations,omitempty"`
}

type WindowsPolicyBundleInspectOptions struct {
	Path           string `json:"path,omitempty"`
	Archive        string `json:"archive,omitempty"`
	CallbackScheme string `json:"callback_scheme,omitempty"`
}

type WindowsPolicyBundleInspectFile struct {
	Path     string `json:"path"`
	Type     string `json:"type,omitempty"`
	Expected bool   `json:"expected,omitempty"`
	Present  bool   `json:"present"`
	Bytes    int    `json:"bytes,omitempty"`
}

type WindowsPolicyBundleInspectResult struct {
	Source          string                           `json:"source"`
	Archive         bool                             `json:"archive,omitempty"`
	Kind            string                           `json:"kind,omitempty"`
	Valid           bool                             `json:"valid"`
	Complete        bool                             `json:"complete"`
	ManifestPresent bool                             `json:"manifest_present"`
	ManifestType    string                           `json:"manifest_type,omitempty"`
	Validation      *WindowsPolicyValidation         `json:"validation,omitempty"`
	Files           []WindowsPolicyBundleInspectFile `json:"files,omitempty"`
	Missing         []string                         `json:"missing,omitempty"`
	Issues          []string                         `json:"issues,omitempty"`
	Operations      []string                         `json:"operations,omitempty"`
}

type WindowsPolicyCSPOptions struct {
	File           string        `json:"file"`
	Associations   []Association `json:"associations,omitempty"`
	CallbackScheme string        `json:"callback_scheme,omitempty"`
	Version        string        `json:"version,omitempty"`
	Suggested      bool          `json:"suggested,omitempty"`
	LocURI         string        `json:"loc_uri,omitempty"`
	CmdID          string        `json:"cmd_id,omitempty"`
	SyncML         bool          `json:"syncml,omitempty"`
	Delete         bool          `json:"delete,omitempty"`
}

type WindowsPolicyCSPResult struct {
	Source       string                  `json:"source"`
	Associations []Association           `json:"associations,omitempty"`
	LocURI       string                  `json:"loc_uri"`
	Command      string                  `json:"command"`
	Version      string                  `json:"version,omitempty"`
	Suggested    bool                    `json:"suggested,omitempty"`
	Format       string                  `json:"format"`
	Type         string                  `json:"type"`
	Data         string                  `json:"data"`
	SyncML       string                  `json:"syncml,omitempty"`
	Validation   WindowsPolicyValidation `json:"validation"`
	Operations   []string                `json:"operations,omitempty"`
}

type WindowsPolicyIntuneOptions struct {
	File           string        `json:"file,omitempty"`
	Associations   []Association `json:"associations,omitempty"`
	CallbackScheme string        `json:"callback_scheme,omitempty"`
	Version        string        `json:"version,omitempty"`
	Suggested      bool          `json:"suggested,omitempty"`
	Name           string        `json:"name,omitempty"`
	Description    string        `json:"description,omitempty"`
}

type WindowsPolicyIntuneResult struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	OMAURI      string                 `json:"oma_uri"`
	DataType    string                 `json:"data_type"`
	Value       string                 `json:"value"`
	CSP         WindowsPolicyCSPResult `json:"csp"`
	Operations  []string               `json:"operations,omitempty"`
}

type WindowsPolicyDISMOptions struct {
	File   string `json:"file,omitempty"`
	Image  string `json:"image,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyDISMResult struct {
	Changed    bool     `json:"changed"`
	Mode       string   `json:"mode"`
	File       string   `json:"file,omitempty"`
	Image      string   `json:"image,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type WindowsPolicyGPResultOptions struct {
	Scope  string `json:"scope,omitempty"`
	Format string `json:"format,omitempty"`
	File   string `json:"file,omitempty"`
	System string `json:"system,omitempty"`
	User   string `json:"user,omitempty"`
	Force  bool   `json:"force,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyGPResultResult struct {
	Changed    bool     `json:"changed"`
	Scope      string   `json:"scope"`
	Format     string   `json:"format"`
	File       string   `json:"file,omitempty"`
	System     string   `json:"system,omitempty"`
	User       string   `json:"user,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type WindowsPolicyGPUpdateOptions struct {
	Target string `json:"target,omitempty"`
	Force  bool   `json:"force,omitempty"`
	Wait   string `json:"wait,omitempty"`
	Logoff bool   `json:"logoff,omitempty"`
	Boot   bool   `json:"boot,omitempty"`
	Sync   bool   `json:"sync,omitempty"`
	DryRun bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyGPUpdateResult struct {
	Changed    bool     `json:"changed"`
	Target     string   `json:"target,omitempty"`
	Force      bool     `json:"force,omitempty"`
	Wait       string   `json:"wait,omitempty"`
	Logoff     bool     `json:"logoff,omitempty"`
	Boot       bool     `json:"boot,omitempty"`
	Sync       bool     `json:"sync,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type WindowsPolicyInvokeGPUpdateOptions struct {
	Computer    string `json:"computer,omitempty"`
	Target      string `json:"target,omitempty"`
	RandomDelay string `json:"random_delay,omitempty"`
	Force       bool   `json:"force,omitempty"`
	Logoff      bool   `json:"logoff,omitempty"`
	Boot        bool   `json:"boot,omitempty"`
	Sync        bool   `json:"sync,omitempty"`
	AsJob       bool   `json:"as_job,omitempty"`
	Script      bool   `json:"script,omitempty"`
	Output      string `json:"output,omitempty"`
	DryRun      bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyInvokeGPUpdateResult struct {
	Changed     bool     `json:"changed"`
	Computer    string   `json:"computer,omitempty"`
	Target      string   `json:"target,omitempty"`
	RandomDelay string   `json:"random_delay,omitempty"`
	Force       bool     `json:"force,omitempty"`
	Logoff      bool     `json:"logoff,omitempty"`
	Boot        bool     `json:"boot,omitempty"`
	Sync        bool     `json:"sync,omitempty"`
	AsJob       bool     `json:"as_job,omitempty"`
	Script      string   `json:"script,omitempty"`
	OutputFile  string   `json:"output_file,omitempty"`
	Command     []string `json:"command,omitempty"`
	Output      string   `json:"output,omitempty"`
	Operations  []string `json:"operations,omitempty"`
}

type WindowsPolicyGPOReportOptions struct {
	GPOName    string `json:"gpo_name,omitempty"`
	GPOGUID    string `json:"gpo_guid,omitempty"`
	All        bool   `json:"all,omitempty"`
	ReportType string `json:"report_type,omitempty"`
	File       string `json:"file,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Server     string `json:"server,omitempty"`
	Script     bool   `json:"script,omitempty"`
	Output     string `json:"output,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyGPOReportResult struct {
	Changed    bool     `json:"changed"`
	GPOName    string   `json:"gpo_name,omitempty"`
	GPOGUID    string   `json:"gpo_guid,omitempty"`
	All        bool     `json:"all,omitempty"`
	ReportType string   `json:"report_type"`
	File       string   `json:"file,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	Server     string   `json:"server,omitempty"`
	Script     string   `json:"script,omitempty"`
	OutputFile string   `json:"output_file,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type WindowsPolicyGPOStatusOptions struct {
	GPOName string `json:"gpo_name,omitempty"`
	GPOGUID string `json:"gpo_guid,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Server  string `json:"server,omitempty"`
	Script  bool   `json:"script,omitempty"`
	Output  string `json:"output,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyGPOStatusResult struct {
	Changed     bool     `json:"changed"`
	GPOName     string   `json:"gpo_name,omitempty"`
	GPOGUID     string   `json:"gpo_guid,omitempty"`
	RegistryKey string   `json:"registry_key"`
	ValueName   string   `json:"value_name"`
	Domain      string   `json:"domain,omitempty"`
	Server      string   `json:"server,omitempty"`
	Script      string   `json:"script,omitempty"`
	OutputFile  string   `json:"output_file,omitempty"`
	Command     []string `json:"command,omitempty"`
	Output      string   `json:"output,omitempty"`
	Operations  []string `json:"operations,omitempty"`
}

type WindowsPolicyGPORestoreOptions struct {
	GPOName string `json:"gpo_name,omitempty"`
	GPOGUID string `json:"gpo_guid,omitempty"`
	Path    string `json:"path"`
	Domain  string `json:"domain,omitempty"`
	Server  string `json:"server,omitempty"`
	WhatIf  bool   `json:"what_if,omitempty"`
	Script  bool   `json:"script,omitempty"`
	Output  string `json:"output,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyGPORestoreResult struct {
	Changed    bool     `json:"changed"`
	GPOName    string   `json:"gpo_name,omitempty"`
	GPOGUID    string   `json:"gpo_guid,omitempty"`
	Path       string   `json:"path"`
	Domain     string   `json:"domain,omitempty"`
	Server     string   `json:"server,omitempty"`
	WhatIf     bool     `json:"what_if,omitempty"`
	Script     string   `json:"script,omitempty"`
	OutputFile string   `json:"output_file,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type WindowsPolicyGPOBackupOptions struct {
	GPOName string `json:"gpo_name,omitempty"`
	GPOGUID string `json:"gpo_guid,omitempty"`
	All     bool   `json:"all,omitempty"`
	Path    string `json:"path"`
	Comment string `json:"comment,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Server  string `json:"server,omitempty"`
	WhatIf  bool   `json:"what_if,omitempty"`
	Script  bool   `json:"script,omitempty"`
	Output  string `json:"output,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyGPOBackupResult struct {
	Changed    bool     `json:"changed"`
	GPOName    string   `json:"gpo_name,omitempty"`
	GPOGUID    string   `json:"gpo_guid,omitempty"`
	All        bool     `json:"all,omitempty"`
	Path       string   `json:"path"`
	Comment    string   `json:"comment,omitempty"`
	Domain     string   `json:"domain,omitempty"`
	Server     string   `json:"server,omitempty"`
	WhatIf     bool     `json:"what_if,omitempty"`
	Script     string   `json:"script,omitempty"`
	OutputFile string   `json:"output_file,omitempty"`
	Command    []string `json:"command,omitempty"`
	Output     string   `json:"output,omitempty"`
	Operations []string `json:"operations,omitempty"`
}

type WindowsPolicyBackupOptions struct {
	File           string `json:"file"`
	CallbackScheme string `json:"callback_scheme,omitempty"`
	DryRun         bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyBackupResult struct {
	Changed     bool                    `json:"changed"`
	Source      string                  `json:"source"`
	Destination string                  `json:"destination"`
	Validation  WindowsPolicyValidation `json:"validation"`
	Operations  []string                `json:"operations,omitempty"`
}

type WindowsPolicyRegistryFileOptions struct {
	PolicyPath string `json:"policy_path,omitempty"`
	Delete     bool   `json:"delete,omitempty"`
}

type WindowsPolicyRegistryFileResult struct {
	RegistryKey string   `json:"registry_key"`
	ValueName   string   `json:"value_name"`
	PolicyPath  string   `json:"policy_path,omitempty"`
	Delete      bool     `json:"delete,omitempty"`
	Content     string   `json:"content"`
	Operations  []string `json:"operations,omitempty"`
}

type WindowsPolicyLGPOTextOptions struct {
	PolicyPath string `json:"policy_path,omitempty"`
	Delete     bool   `json:"delete,omitempty"`
}

type WindowsPolicyLGPOTextResult struct {
	Configuration string   `json:"configuration"`
	RegistryKey   string   `json:"registry_key"`
	ValueName     string   `json:"value_name"`
	PolicyPath    string   `json:"policy_path,omitempty"`
	Delete        bool     `json:"delete,omitempty"`
	Content       string   `json:"content"`
	Operations    []string `json:"operations,omitempty"`
}

type WindowsPolicyRegistryPOLOptions struct {
	PolicyPath string `json:"policy_path,omitempty"`
	Output     string `json:"output,omitempty"`
	Delete     bool   `json:"delete,omitempty"`
	DryRun     bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyRegistryPOLResult struct {
	Scope         string   `json:"scope"`
	RegistryKey   string   `json:"registry_key"`
	ValueName     string   `json:"value_name"`
	PolicyPath    string   `json:"policy_path,omitempty"`
	Output        string   `json:"output,omitempty"`
	Delete        bool     `json:"delete,omitempty"`
	DryRun        bool     `json:"dry_run,omitempty"`
	Changed       bool     `json:"changed"`
	Bytes         int      `json:"bytes"`
	ContentBase64 string   `json:"content_base64"`
	Operations    []string `json:"operations,omitempty"`
}

type WindowsPolicyGPOOptions struct {
	GPOName      string `json:"gpo_name,omitempty"`
	GPOGUID      string `json:"gpo_guid,omitempty"`
	PolicyPath   string `json:"policy_path,omitempty"`
	Domain       string `json:"domain,omitempty"`
	Server       string `json:"server,omitempty"`
	Create       bool   `json:"create,omitempty"`
	Comment      string `json:"comment,omitempty"`
	LinkTarget   string `json:"link_target,omitempty"`
	LinkDisabled bool   `json:"link_disabled,omitempty"`
	Enforced     bool   `json:"enforced,omitempty"`
	Order        int    `json:"order,omitempty"`
	Delete       bool   `json:"delete,omitempty"`
	WhatIf       bool   `json:"what_if,omitempty"`
}

type WindowsPolicyGPOResult struct {
	GPOName      string   `json:"gpo_name,omitempty"`
	GPOGUID      string   `json:"gpo_guid,omitempty"`
	RegistryKey  string   `json:"registry_key"`
	ValueName    string   `json:"value_name"`
	PolicyPath   string   `json:"policy_path,omitempty"`
	Domain       string   `json:"domain,omitempty"`
	Server       string   `json:"server,omitempty"`
	Create       bool     `json:"create,omitempty"`
	Comment      string   `json:"comment,omitempty"`
	LinkTarget   string   `json:"link_target,omitempty"`
	LinkDisabled bool     `json:"link_disabled,omitempty"`
	Enforced     bool     `json:"enforced,omitempty"`
	Order        int      `json:"order,omitempty"`
	Delete       bool     `json:"delete,omitempty"`
	WhatIf       bool     `json:"what_if,omitempty"`
	Command      string   `json:"command"`
	Content      string   `json:"content"`
	Operations   []string `json:"operations,omitempty"`
}

type WindowsPolicyScriptOptions struct {
	File           string `json:"file,omitempty"`
	Destination    string `json:"destination,omitempty"`
	CallbackScheme string `json:"callback_scheme,omitempty"`
	Delete         bool   `json:"delete,omitempty"`
	DeleteFile     bool   `json:"delete_file,omitempty"`
	RefreshPolicy  bool   `json:"refresh_policy,omitempty"`
}

type WindowsPolicyScriptResult struct {
	Source      string                   `json:"source,omitempty"`
	Destination string                   `json:"destination,omitempty"`
	Delete      bool                     `json:"delete,omitempty"`
	DeleteFile  bool                     `json:"delete_file,omitempty"`
	GPUpdate    bool                     `json:"gpupdate,omitempty"`
	Validation  *WindowsPolicyValidation `json:"validation,omitempty"`
	Content     string                   `json:"content"`
	Operations  []string                 `json:"operations,omitempty"`
}

type WindowsPolicyNormalizeOptions struct {
	File    string `json:"file"`
	Output  string `json:"output,omitempty"`
	Version string `json:"version,omitempty"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

type WindowsPolicyNormalizeResult struct {
	Changed     bool                    `json:"changed"`
	Source      string                  `json:"source"`
	Destination string                  `json:"destination"`
	Version     string                  `json:"version,omitempty"`
	Validation  WindowsPolicyValidation `json:"validation"`
	XML         string                  `json:"xml,omitempty"`
	Operations  []string                `json:"operations,omitempty"`
}

type WindowsPolicyProfileResult struct {
	Validation   WindowsPolicyValidation `json:"validation"`
	Associations []Association           `json:"associations"`
	Operations   []string                `json:"operations,omitempty"`
}

type WindowsRegisteredApplicationsOptions struct {
	Query string `json:"query,omitempty"`
}

type WindowsRegisteredApplicationAssociation struct {
	Kind       string   `json:"kind"`
	Identifier string   `json:"identifier"`
	ProgID     string   `json:"prog_id"`
	Targets    []string `json:"targets,omitempty"`
}

type WindowsRegisteredApplication struct {
	Scope            string                                    `json:"scope"`
	Name             string                                    `json:"name"`
	ApplicationName  string                                    `json:"application_name,omitempty"`
	Description      string                                    `json:"description,omitempty"`
	CapabilitiesPath string                                    `json:"capabilities_path"`
	CapabilitiesKey  string                                    `json:"capabilities_key"`
	Associations     []WindowsRegisteredApplicationAssociation `json:"associations,omitempty"`
	BrowserCandidate bool                                      `json:"browser_candidate,omitempty"`
	Issues           []string                                  `json:"issues,omitempty"`
}

type WindowsRegisteredApplicationsResult struct {
	Platform     string                         `json:"platform"`
	Query        string                         `json:"query,omitempty"`
	Applications []WindowsRegisteredApplication `json:"applications,omitempty"`
	Operations   []string                       `json:"operations,omitempty"`
}

type windowsDefaultAssociationPolicyRegistrySource struct {
	key               string
	valueNames        []string
	requireValueMatch bool
}

func ValidateWindowsPolicyXML(content []byte, callbackScheme string) WindowsPolicyValidation {
	required, callbackIssues := windowsPolicyRequiredTargets(callbackScheme)
	records, issues := parseWindowsPolicyXML(content)
	issues = append(issues, callbackIssues...)
	issues = append(issues, windowsPolicyRecordIssues(records)...)
	missing, mandatory := windowsPolicyCoverage(required, records)
	issues = dedupeSortedStrings(issues)
	return WindowsPolicyValidation{
		Valid:     len(issues) == 0,
		Complete:  len(missing) == 0,
		Mandatory: mandatory,
		Version:   windowsPolicyVersionFromXML(content),
		Suggested: windowsPolicyRecordsSuggested(records),
		Required:  required,
		Missing:   missing,
		Issues:    issues,
		Records:   records,
	}
}

func WindowsBrowserCapabilityAuditTargets(callbackScheme string) []Target {
	targets := []Target{
		{Kind: KindScheme, Value: "http"},
		{Kind: KindScheme, Value: "https"},
		{Kind: KindMIME, Value: "text/html"},
		{Kind: KindMIME, Value: "application/xhtml+xml"},
	}
	callback := NormalizeScheme(callbackScheme)
	if callback == "" || callback == "http" || callback == "https" {
		return targets
	}
	if !validURLScheme(callback) {
		return targets
	}
	return append(targets, Target{Kind: KindScheme, Value: callback})
}

func WindowsPolicyRequiredTargets(callbackScheme string) []string {
	targets, _ := windowsPolicyRequiredTargets(callbackScheme)
	return targets
}

func windowsPolicyRequiredTargets(callbackScheme string) ([]string, []string) {
	targets := []string{"http", "https", "text/html", "application/xhtml+xml"}
	callback := NormalizeScheme(callbackScheme)
	if callback == "" {
		return targets, nil
	}
	if !validURLScheme(callback) {
		return targets, []string{fmt.Sprintf("invalid callback scheme %q", callbackScheme)}
	}
	for _, target := range targets {
		if target == callback {
			return targets, nil
		}
	}
	return append(targets, callback), nil
}

func InstallWindowsDefaultAssociationsPolicy(ctx context.Context, options WindowsPolicyInstallOptions) (WindowsPolicyInstallResult, error) {
	return installWindowsDefaultAssociationsPolicy(ctx, execRunner{}, options)
}

func ExportWindowsDefaultAssociationsPolicy(ctx context.Context, options WindowsPolicyExportOptions) (WindowsPolicyExportResult, error) {
	return exportWindowsDefaultAssociationsPolicy(ctx, execRunner{}, options)
}

func MergeWindowsDefaultAssociationsPolicyXML(options WindowsPolicyMergeOptions) (WindowsPolicyMergeResult, error) {
	return mergeWindowsDefaultAssociationsPolicyXML(options)
}

func CompileWindowsDefaultAssociationsPolicyXML(options WindowsPolicyCompileOptions) (WindowsPolicyCompileResult, error) {
	return compileWindowsDefaultAssociationsPolicyXML(options)
}

func ResolveWindowsPolicyAssociations(ctx context.Context, options WindowsPolicyAppResolutionOptions) (WindowsPolicyAppResolutionResult, error) {
	return resolveWindowsPolicyAssociations(ctx, execRunner{}, options)
}

func DeployWindowsDefaultAssociationsPolicy(ctx context.Context, options WindowsPolicyDeployOptions) (WindowsPolicyDeployResult, error) {
	return deployWindowsDefaultAssociationsPolicy(ctx, execRunner{}, options)
}

func DiffWindowsDefaultAssociationsPolicy(ctx context.Context, options WindowsPolicyDiffOptions) (WindowsPolicyDiffResult, error) {
	return diffWindowsDefaultAssociationsPolicy(ctx, execRunner{}, options)
}

func BundleWindowsDefaultAssociationsPolicy(options WindowsPolicyBundleOptions) (WindowsPolicyBundleResult, error) {
	return bundleWindowsDefaultAssociationsPolicy(options)
}

func InspectWindowsDefaultAssociationsPolicyBundle(options WindowsPolicyBundleInspectOptions) (WindowsPolicyBundleInspectResult, error) {
	return inspectWindowsDefaultAssociationsPolicyBundle(options)
}

func WindowsDefaultAssociationsPolicyCSP(options WindowsPolicyCSPOptions) (WindowsPolicyCSPResult, error) {
	return windowsDefaultAssociationsPolicyCSP(options)
}

func WindowsDefaultAssociationsPolicyIntune(options WindowsPolicyIntuneOptions) (WindowsPolicyIntuneResult, error) {
	return windowsDefaultAssociationsPolicyIntune(options)
}

func ImportWindowsDefaultAssociationsWithDISM(ctx context.Context, options WindowsPolicyDISMOptions) (WindowsPolicyDISMResult, error) {
	return windowsDefaultAssociationsDISM(ctx, execRunner{}, "import", options)
}

func ListWindowsDefaultAssociationsWithDISM(ctx context.Context, options WindowsPolicyDISMOptions) (WindowsPolicyDISMResult, error) {
	return windowsDefaultAssociationsDISM(ctx, execRunner{}, "list", options)
}

func RemoveWindowsDefaultAssociationsWithDISM(ctx context.Context, options WindowsPolicyDISMOptions) (WindowsPolicyDISMResult, error) {
	return windowsDefaultAssociationsDISM(ctx, execRunner{}, "remove", options)
}

func WindowsDefaultAssociationsPolicyGPResult(ctx context.Context, options WindowsPolicyGPResultOptions) (WindowsPolicyGPResultResult, error) {
	return windowsDefaultAssociationsPolicyGPResult(ctx, execRunner{}, options)
}

func RefreshWindowsDefaultAssociationsGroupPolicy(ctx context.Context, options WindowsPolicyGPUpdateOptions) (WindowsPolicyGPUpdateResult, error) {
	return refreshWindowsDefaultAssociationsGroupPolicy(ctx, execRunner{}, options)
}

func InvokeWindowsDefaultAssociationsGroupPolicyRefresh(ctx context.Context, options WindowsPolicyInvokeGPUpdateOptions) (WindowsPolicyInvokeGPUpdateResult, error) {
	return invokeWindowsDefaultAssociationsGroupPolicyRefresh(ctx, execRunner{}, options)
}

func WindowsDefaultAssociationsPolicyGPOReport(ctx context.Context, options WindowsPolicyGPOReportOptions) (WindowsPolicyGPOReportResult, error) {
	return windowsDefaultAssociationsPolicyGPOReport(ctx, execRunner{}, options)
}

func WindowsDefaultAssociationsPolicyGPOStatus(ctx context.Context, options WindowsPolicyGPOStatusOptions) (WindowsPolicyGPOStatusResult, error) {
	return windowsDefaultAssociationsPolicyGPOStatus(ctx, execRunner{}, options)
}

func RestoreWindowsDefaultAssociationsPolicyGPO(ctx context.Context, options WindowsPolicyGPORestoreOptions) (WindowsPolicyGPORestoreResult, error) {
	return restoreWindowsDefaultAssociationsPolicyGPO(ctx, execRunner{}, options)
}

func BackupWindowsDefaultAssociationsPolicyGPO(ctx context.Context, options WindowsPolicyGPOBackupOptions) (WindowsPolicyGPOBackupResult, error) {
	return backupWindowsDefaultAssociationsPolicyGPO(ctx, execRunner{}, options)
}

func BackupWindowsDefaultAssociationsPolicy(ctx context.Context, options WindowsPolicyBackupOptions) (WindowsPolicyBackupResult, error) {
	return backupWindowsDefaultAssociationsPolicy(ctx, execRunner{}, options)
}

func WindowsDefaultAssociationsPolicyRegistryFile(options WindowsPolicyRegistryFileOptions) (WindowsPolicyRegistryFileResult, error) {
	return windowsDefaultAssociationsPolicyRegistryFile(options)
}

func WindowsDefaultAssociationsPolicyLGPOText(options WindowsPolicyLGPOTextOptions) (WindowsPolicyLGPOTextResult, error) {
	return windowsDefaultAssociationsPolicyLGPOText(options)
}

func WindowsDefaultAssociationsPolicyRegistryPOL(options WindowsPolicyRegistryPOLOptions) (WindowsPolicyRegistryPOLResult, error) {
	return windowsDefaultAssociationsPolicyRegistryPOL(options)
}

func WindowsDefaultAssociationsPolicyGPO(options WindowsPolicyGPOOptions) (WindowsPolicyGPOResult, error) {
	return windowsDefaultAssociationsPolicyGPO(options)
}

func WindowsDefaultAssociationsPolicyScript(options WindowsPolicyScriptOptions) (WindowsPolicyScriptResult, error) {
	return windowsDefaultAssociationsPolicyScript(options)
}

func NormalizeWindowsDefaultAssociationsPolicyXML(options WindowsPolicyNormalizeOptions) (WindowsPolicyNormalizeResult, error) {
	return normalizeWindowsDefaultAssociationsPolicyXML(options)
}

func WindowsPolicyProfileFromXML(content []byte) (WindowsPolicyProfileResult, error) {
	return windowsPolicyProfileFromXML(content)
}

func ListWindowsRegisteredApplications(ctx context.Context, options WindowsRegisteredApplicationsOptions) (WindowsRegisteredApplicationsResult, error) {
	return listWindowsRegisteredApplications(ctx, execRunner{}, options)
}

func WindowsDefaultAssociationsPolicyStatus(ctx context.Context, options WindowsPolicyStatusOptions) (WindowsPolicyStatusResult, error) {
	return windowsDefaultAssociationsPolicyStatus(ctx, execRunner{}, options)
}

func UninstallWindowsDefaultAssociationsPolicy(ctx context.Context, options WindowsPolicyUninstallOptions) (WindowsPolicyUninstallResult, error) {
	return uninstallWindowsDefaultAssociationsPolicy(ctx, execRunner{}, options)
}

func windowsDefaultAssociationsPolicyStatus(ctx context.Context, runner commandRunner, options WindowsPolicyStatusOptions) (WindowsPolicyStatusResult, error) {
	result := WindowsPolicyStatusResult{
		Platform: "windows",
		Operations: []string{
			"Query Windows default-association policy registry values",
		},
	}
	if _, err := runner.LookPath("reg"); err != nil {
		return result, fmt.Errorf("Windows registry policy tooling is unavailable: %w", err)
	}
	for _, source := range windowsDefaultAssociationPolicyRegistrySources() {
		values, err := windowsPolicyReadRegValues(ctx, runner, source.key)
		if err != nil {
			continue
		}
		for _, valueName := range source.valueNames {
			value := strings.TrimSpace(values[valueName])
			if value == "" {
				continue
			}
			status := WindowsPolicyStatusSource{
				RegistryKey:   source.key,
				ValueName:     valueName,
				Value:         value,
				RequiredValue: source.requireValueMatch,
			}
			raw := normalizeWindowsPolicyAssociationXMLText(value)
			if strings.HasPrefix(raw, "<") {
				status.InlineXML = true
				status.Readable = true
				validation := ValidateWindowsPolicyXML([]byte(raw), options.CallbackScheme)
				status.Validation = &validation
			} else {
				status.Path = firstWindowsPolicyPathValue(value)
				if expanded := expandWindowsPolicyPath(status.Path); expanded != "" {
					status.Path = expanded
				}
				if status.Path == "" {
					status.Issues = append(status.Issues, "policy value does not contain a readable XML path")
				} else {
					content, err := os.ReadFile(status.Path)
					if err != nil {
						status.Issues = append(status.Issues, "policy XML is not readable: "+err.Error())
					} else {
						status.Readable = true
						validation := ValidateWindowsPolicyXML(content, options.CallbackScheme)
						status.Validation = &validation
					}
				}
			}
			result.Configured = true
			result.Sources = append(result.Sources, status)
		}
	}
	result.Healthy = windowsPolicyStatusHealthy(result)
	if !result.Configured {
		result.Operations = append(result.Operations, "No Windows default-association policy values were found")
	} else if result.Healthy {
		result.Operations = append(result.Operations, "Windows default-association policy is configured and validates cleanly")
	} else {
		result.Operations = append(result.Operations, "Windows default-association policy is configured but has validation or readability issues")
	}
	return result, nil
}

func uninstallWindowsDefaultAssociationsPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyUninstallOptions) (WindowsPolicyUninstallResult, error) {
	result := WindowsPolicyUninstallResult{
		RegistryKey:            windowsDefaultAssociationsPolicyRegistryKey,
		ValueName:              windowsDefaultAssociationsPolicyRegistryValue,
		PolicyRefreshRequested: options.RefreshPolicy,
		Operations: []string{
			fmt.Sprintf("Remove %s/%s", windowsDefaultAssociationsPolicyRegistryKey, windowsDefaultAssociationsPolicyRegistryValue),
		},
	}
	if _, err := runner.LookPath("reg"); err != nil {
		return result, fmt.Errorf("Windows registry policy tooling is unavailable: %w", err)
	}
	values, valuesErr := windowsPolicyReadRegValues(ctx, runner, windowsDefaultAssociationsPolicyRegistryKey)
	configuredValue := ""
	if valuesErr == nil {
		configuredValue = strings.TrimSpace(values[windowsDefaultAssociationsPolicyRegistryValue])
	}
	configured := configuredValue != ""
	if destination := expandWindowsPolicyPath(options.Destination); destination != "" {
		result.Destination = destination
	} else if configured {
		if configuredPath := firstWindowsPolicyPathValue(configuredValue); configuredPath != "" {
			result.Destination = expandWindowsPolicyPath(configuredPath)
		}
	}

	if options.DryRun {
		if configured {
			result.Operations = append(result.Operations, fmt.Sprintf("Would delete registry value %s/%s", result.RegistryKey, result.ValueName))
		} else {
			result.Operations = append(result.Operations, fmt.Sprintf("Registry value already absent: %s/%s", result.RegistryKey, result.ValueName))
		}
		if options.DeleteFile {
			if result.Destination == "" {
				result.Operations = append(result.Operations, "Would delete policy XML file, but no destination path is configured")
			} else {
				result.Operations = append(result.Operations, "Would delete policy XML file: "+result.Destination)
			}
		}
		if options.RefreshPolicy {
			result.Operations = append(result.Operations, "Would run gpupdate /target:computer /force")
		}
		result.RequiresSignIn = true
		return result, nil
	}

	if !configured {
		result.Operations = append(result.Operations, fmt.Sprintf("Registry value already absent: %s/%s", result.RegistryKey, result.ValueName))
		return result, nil
	}
	if _, err := runner.Run(ctx, "reg", "delete", result.RegistryKey, "/v", result.ValueName, "/f"); err != nil {
		return result, fmt.Errorf("delete Windows default-associations machine policy value: %w", err)
	}
	result.Changed = true
	result.RequiresSignIn = true
	result.Operations = append(result.Operations, fmt.Sprintf("Deleted registry value %s/%s", result.RegistryKey, result.ValueName))

	if options.DeleteFile {
		if result.Destination == "" {
			result.Operations = append(result.Operations, "Skipped policy XML deletion because no destination path is configured")
		} else if err := os.Remove(result.Destination); err != nil {
			if !os.IsNotExist(err) {
				return result, fmt.Errorf("delete Windows default-associations policy XML: %w", err)
			}
			result.Operations = append(result.Operations, "Policy XML file was already absent: "+result.Destination)
		} else {
			result.DeletedFile = true
			result.Operations = append(result.Operations, "Deleted policy XML file: "+result.Destination)
		}
	}

	if options.RefreshPolicy {
		if _, err := runner.LookPath("gpupdate"); err != nil {
			return result, fmt.Errorf("Windows policy value was removed, but gpupdate is unavailable: %w", err)
		}
		if _, err := runner.Run(ctx, "gpupdate", "/target:computer", "/force"); err != nil {
			return result, fmt.Errorf("Windows policy value was removed, but gpupdate failed: %w", err)
		}
		result.PolicyRefreshed = true
		result.Operations = append(result.Operations, "Ran gpupdate /target:computer /force")
	}
	result.Operations = append(result.Operations, "Windows may require sign-out/sign-in before default-association policy removal is observable")
	return result, nil
}

func mergeWindowsDefaultAssociationsPolicyXML(options WindowsPolicyMergeOptions) (WindowsPolicyMergeResult, error) {
	file := expandWindowsPolicyPath(options.File)
	target := options.Target.Normalized()
	progID := strings.TrimSpace(options.ProgID)
	applicationName := strings.TrimSpace(options.ApplicationName)
	version := strings.TrimSpace(options.Version)
	if applicationName == "" {
		applicationName = progID
	}
	result := WindowsPolicyMergeResult{
		File:      file,
		Target:    target,
		ProgID:    progID,
		Version:   version,
		Suggested: options.Suggested,
		Operations: []string{
			"Merge Windows default-association policy XML: " + file,
		},
	}
	if file == "" {
		return result, fmt.Errorf("policy file is required")
	}
	if err := target.Validate(); err != nil {
		return result, err
	}
	if progID == "" {
		return result, fmt.Errorf("prog id is required")
	}

	records := []WindowsPolicyAssociation{}
	if content, err := os.ReadFile(file); err == nil && len(strings.TrimSpace(string(content))) > 0 {
		parsed, issues := parseWindowsPolicyXML(content)
		if len(issues) > 0 {
			return result, fmt.Errorf("existing Windows default-association policy XML is invalid: %s", strings.Join(issues, "; "))
		}
		records = parsed
		result.Operations = append(result.Operations, "Read existing policy XML")
	} else if err != nil && !os.IsNotExist(err) {
		return result, fmt.Errorf("read Windows default-association policy XML: %w", err)
	} else {
		result.Operations = append(result.Operations, "Start new policy XML")
	}

	identifiers, err := windowsPolicyIdentifiersForTarget(target, options.CallbackScheme)
	if err != nil {
		return result, err
	}
	result.Identifiers = identifiers
	records = mergeWindowsPolicyAssociations(records, identifiers, progID, applicationName, options.Suggested)
	xmlText := windowsPolicyXMLFromAssociationsWithVersion(records, version)
	validation := ValidateWindowsPolicyXML([]byte(xmlText), options.CallbackScheme)
	result.Validation = validation
	result.Records = records
	result.XML = xmlText
	result.Operations = append(result.Operations, fmt.Sprintf("Merged %s -> %s", strings.Join(identifiers, ", "), progID))
	if version != "" {
		result.Operations = append(result.Operations, "Set DefaultAssociations Version="+version)
	}
	if options.Suggested {
		result.Operations = append(result.Operations, "Marked merged associations as Suggested=true")
	}
	result.Operations = append(result.Operations, fmt.Sprintf("Validate merged policy XML: valid=%t complete=%t mandatory=%t", validation.Valid, validation.Complete, validation.Mandatory))
	if !validation.Valid {
		return result, fmt.Errorf("merged Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
	}
	if options.DryRun {
		result.Operations = append(result.Operations, "Would write merged policy XML to "+file)
		return result, nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return result, fmt.Errorf("create Windows policy XML directory: %w", err)
	}
	if err := os.WriteFile(file, []byte(xmlText), 0o644); err != nil {
		return result, fmt.Errorf("write Windows policy XML: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Wrote merged policy XML to "+file)
	return result, nil
}

func compileWindowsDefaultAssociationsPolicyXML(options WindowsPolicyCompileOptions) (WindowsPolicyCompileResult, error) {
	file := expandWindowsPolicyPath(options.File)
	version := strings.TrimSpace(options.Version)
	result := WindowsPolicyCompileResult{
		File:      file,
		Version:   version,
		Suggested: options.Suggested,
		Operations: []string{
			"Compile Windows default-association policy XML from profile: " + file,
		},
	}
	if file == "" {
		return result, fmt.Errorf("policy file is required")
	}
	if len(options.Associations) == 0 {
		return result, fmt.Errorf("profile contains no defaults")
	}

	records := []WindowsPolicyAssociation{}
	for index, association := range options.Associations {
		association = association.Normalized()
		if err := association.Validate(); err != nil {
			return result, fmt.Errorf("defaults[%d]: %w", index, err)
		}
		identifiers, err := windowsPolicyIdentifiersForTarget(association.Target(), "")
		if err != nil {
			return result, fmt.Errorf("defaults[%d]: %w", index, err)
		}
		records = mergeWindowsPolicyAssociations(records, identifiers, association.App, association.App, options.Suggested)
		result.Associations = append(result.Associations, association)
		result.Operations = append(result.Operations, fmt.Sprintf("Compile defaults[%d] %s -> %s as %s", index, association.Target().String(), association.App, strings.Join(identifiers, ", ")))
	}

	xmlText := windowsPolicyXMLFromAssociationsWithVersion(records, version)
	validation := ValidateWindowsPolicyXML([]byte(xmlText), options.CallbackScheme)
	result.Validation = validation
	result.Records = records
	result.XML = xmlText
	if version != "" {
		result.Operations = append(result.Operations, "Set DefaultAssociations Version="+version)
	}
	if options.Suggested {
		result.Operations = append(result.Operations, "Marked compiled associations as Suggested=true")
	}
	result.Operations = append(result.Operations, fmt.Sprintf("Validate compiled policy XML: valid=%t complete=%t mandatory=%t", validation.Valid, validation.Complete, validation.Mandatory))
	if !validation.Valid {
		return result, fmt.Errorf("compiled Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
	}
	if options.DryRun {
		result.Operations = append(result.Operations, "Would write compiled policy XML to "+file)
		return result, nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return result, fmt.Errorf("create Windows policy XML directory: %w", err)
	}
	if err := os.WriteFile(file, []byte(xmlText), 0o644); err != nil {
		return result, fmt.Errorf("write Windows policy XML: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Wrote compiled policy XML to "+file)
	return result, nil
}

func deployWindowsDefaultAssociationsPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyDeployOptions) (WindowsPolicyDeployResult, error) {
	result := WindowsPolicyDeployResult{
		Operations: []string{
			"Compile and install Windows default-association policy from profile",
		},
	}
	compile, err := compileWindowsDefaultAssociationsPolicyXML(WindowsPolicyCompileOptions{
		File:           options.File,
		Associations:   options.Associations,
		CallbackScheme: options.CallbackScheme,
		Version:        options.Version,
		Suggested:      options.Suggested,
		DryRun:         options.DryRun,
	})
	result.Compile = compile
	result.Operations = append(result.Operations, compile.Operations...)
	if err != nil {
		return result, err
	}
	if !compile.Validation.Complete && !options.AllowIncomplete {
		return result, fmt.Errorf("compiled Windows default-association policy XML is incomplete: missing %s", strings.Join(compile.Validation.Missing, ", "))
	}
	destination := expandWindowsPolicyPath(options.Destination)
	if destination == "" {
		destination = windowsDefaultAssociationsPolicyDefaultPath()
	}
	if options.DryRun {
		install := WindowsPolicyInstallResult{
			Source:                 compile.File,
			Destination:            destination,
			Validation:             compile.Validation,
			PolicyRefreshRequested: options.RefreshPolicy,
			RequiresSignIn:         true,
			Operations: []string{
				"Would install compiled Windows default-association policy XML",
				fmt.Sprintf("Would configure %s/%s=%s", windowsDefaultAssociationsPolicyRegistryKey, windowsDefaultAssociationsPolicyRegistryValue, destination),
			},
		}
		if !sameWindowsPolicyPath(compile.File, destination) {
			install.Operations = append(install.Operations, "Would copy compiled policy XML to "+destination)
		}
		if options.RefreshPolicy {
			install.Operations = append(install.Operations, "Would run gpupdate /target:computer /force")
		}
		result.Install = install
		result.Operations = append(result.Operations, install.Operations...)
		return result, nil
	}
	install, err := installWindowsDefaultAssociationsPolicy(ctx, runner, WindowsPolicyInstallOptions{
		File:            compile.File,
		Destination:     options.Destination,
		CallbackScheme:  options.CallbackScheme,
		AllowIncomplete: options.AllowIncomplete,
		RefreshPolicy:   options.RefreshPolicy,
	})
	result.Install = install
	result.Changed = compile.Changed || install.Changed
	result.Operations = append(result.Operations, install.Operations...)
	return result, err
}

func diffWindowsDefaultAssociationsPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyDiffOptions) (WindowsPolicyDiffResult, error) {
	desiredSource := expandWindowsPolicyPath(options.File)
	currentSource := expandWindowsPolicyPath(options.CurrentFile)
	result := WindowsPolicyDiffResult{
		DesiredSource: desiredSource,
		CurrentSource: currentSource,
		Operations: []string{
			"Compare Windows default-association policy targets",
		},
	}
	if desiredSource == "" {
		return result, fmt.Errorf("desired policy file is required")
	}
	desiredContent, err := os.ReadFile(desiredSource)
	if err != nil {
		return result, fmt.Errorf("read desired Windows default-association policy XML: %w", err)
	}
	result.Operations = append(result.Operations, "Read desired policy XML: "+desiredSource)
	if currentSource != "" {
		currentContent, err := os.ReadFile(currentSource)
		if err != nil {
			return result, fmt.Errorf("read current Windows default-association policy XML: %w", err)
		}
		result.Operations = append(result.Operations, "Read current policy XML: "+currentSource)
		return diffWindowsPolicyXMLContent(result, desiredContent, currentContent, options.CallbackScheme)
	}
	currentContent, source, err := currentWindowsPolicyXMLContent(ctx, runner)
	if err != nil {
		return result, err
	}
	result.CurrentSource = source
	result.Operations = append(result.Operations, "Read active policy XML: "+source)
	return diffWindowsPolicyXMLContent(result, desiredContent, currentContent, options.CallbackScheme)
}

func bundleWindowsDefaultAssociationsPolicy(options WindowsPolicyBundleOptions) (WindowsPolicyBundleResult, error) {
	source := expandWindowsPolicyPath(options.File)
	output := expandWindowsPolicyPath(options.Output)
	archivePath := expandWindowsPolicyPath(options.Archive)
	policyPath := expandWindowsPolicyPath(options.PolicyPath)
	if policyPath == "" {
		policyPath = windowsDefaultAssociationsPolicyDefaultPath()
	}
	result := WindowsPolicyBundleResult{
		Source:     source,
		Output:     output,
		Archive:    archivePath,
		PolicyPath: policyPath,
		Delete:     options.Delete,
		DeleteFile: options.DeleteFile,
		DryRun:     options.DryRun,
		Operations: []string{
			"Generate Windows default-association deployment bundle",
		},
	}
	if output == "" {
		return result, fmt.Errorf("bundle output directory is required")
	}
	if options.Delete {
		result.Source = "removal"
		result.Validation = WindowsPolicyValidation{Valid: true, Complete: true}
		result.Operations = []string{
			"Generate Windows default-association removal bundle",
		}
		if source != "" || len(options.Associations) > 0 {
			return result, fmt.Errorf("removal bundle does not accept policy file or profile associations")
		}
	} else if source != "" && len(options.Associations) > 0 {
		return result, fmt.Errorf("policy file and profile associations are mutually exclusive")
	}
	var xmlContent []byte
	if options.Delete {
		// No XML payload is required for removal artifacts.
	} else if source != "" {
		var err error
		xmlContent, err = os.ReadFile(source)
		if err != nil {
			return result, fmt.Errorf("read Windows default-association policy XML: %w", err)
		}
		result.Operations = append(result.Operations, "Read policy XML: "+source)
	} else {
		if len(options.Associations) == 0 {
			return result, fmt.Errorf("policy file or profile associations are required")
		}
		result.Source = "profile"
		records := []WindowsPolicyAssociation{}
		for index, association := range options.Associations {
			association = association.Normalized()
			if err := association.Validate(); err != nil {
				return result, fmt.Errorf("defaults[%d]: %w", index, err)
			}
			identifiers, err := windowsPolicyIdentifiersForTarget(association.Target(), "")
			if err != nil {
				return result, fmt.Errorf("defaults[%d]: %w", index, err)
			}
			records = mergeWindowsPolicyAssociations(records, identifiers, association.App, association.App, options.Suggested)
			result.Associations = append(result.Associations, association)
			result.Operations = append(result.Operations, fmt.Sprintf("Compile defaults[%d] %s -> %s as %s", index, association.Target().String(), association.App, strings.Join(identifiers, ", ")))
		}
		xmlContent = []byte(windowsPolicyXMLFromAssociationsWithVersion(records, options.Version))
		result.Operations = append(result.Operations, "Compiled profile associations into bundled policy XML")
	}
	if !options.Delete {
		result.Validation = ValidateWindowsPolicyXML(xmlContent, options.CallbackScheme)
		result.Operations = append(result.Operations, fmt.Sprintf("Validate policy XML: valid=%t complete=%t mandatory=%t", result.Validation.Valid, result.Validation.Complete, result.Validation.Mandatory))
		if !result.Validation.Valid {
			return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(result.Validation.Issues, "; "))
		}
	}
	if !options.DryRun {
		if err := os.MkdirAll(output, 0o755); err != nil {
			return result, fmt.Errorf("create Windows policy bundle directory: %w", err)
		}
	}
	bundleContents := map[string][]byte{}
	addFile := func(name string, typ string, description string, content []byte) error {
		bundleContents[name] = append([]byte(nil), content...)
		result.Files = append(result.Files, WindowsPolicyBundleFile{
			Path:        name,
			Type:        typ,
			Bytes:       len(content),
			Description: description,
		})
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write bundle file: "+name)
			return nil
		}
		if err := os.WriteFile(filepath.Join(output, name), content, 0o644); err != nil {
			return fmt.Errorf("write Windows policy bundle file %s: %w", name, err)
		}
		result.Operations = append(result.Operations, "Wrote bundle file: "+name)
		return nil
	}
	if options.Delete {
		reg, err := windowsDefaultAssociationsPolicyRegistryFile(WindowsPolicyRegistryFileOptions{Delete: true})
		if err != nil {
			return result, err
		}
		if err := addFile("Remove-DefaultAssociations.reg", "reg", "Offline registry artifact that removes the machine policy pointer", []byte(reg.Content)); err != nil {
			return result, err
		}
		lgpo, err := windowsDefaultAssociationsPolicyLGPOText(WindowsPolicyLGPOTextOptions{Delete: true})
		if err != nil {
			return result, err
		}
		if err := addFile("Remove-DefaultAssociations.lgpo.txt", "lgpo-text", "LGPO text artifact that removes the local Group Policy value", []byte(lgpo.Content)); err != nil {
			return result, err
		}
		pol, err := windowsDefaultAssociationsPolicyRegistryPOL(WindowsPolicyRegistryPOLOptions{Delete: true})
		if err != nil {
			return result, err
		}
		polContent, err := base64.StdEncoding.DecodeString(pol.ContentBase64)
		if err != nil {
			return result, fmt.Errorf("decode removal Registry.pol artifact: %w", err)
		}
		if err := addFile("Registry.pol", "registry-pol", "Machine Registry.pol artifact that removes the policy pointer", polContent); err != nil {
			return result, err
		}
		csp, err := windowsDefaultAssociationsPolicyCSP(WindowsPolicyCSPOptions{Delete: true, SyncML: true})
		if err != nil {
			return result, err
		}
		if err := addFile("ApplicationDefaults.delete.syncml.xml", "syncml", "ApplicationDefaults CSP SyncML Delete payload", []byte(csp.SyncML)); err != nil {
			return result, err
		}
		if err := addFile("Remove-DefaultAssociations.ps1", "powershell", "Local removal script for the policy pointer", []byte(windowsPolicyBundleRemoveScript(policyPath, options.RefreshPolicy, options.DeleteFile))); err != nil {
			return result, err
		}
		if windowsPolicyBundleHasGPOOptions(options.GPO) {
			gpoOptions := options.GPO
			gpoOptions.Delete = true
			gpoOptions.PolicyPath = ""
			gpo, err := windowsDefaultAssociationsPolicyGPO(gpoOptions)
			if err != nil {
				return result, err
			}
			if err := addFile("Remove-DomainGPO.ps1", "powershell", "Domain GPO script that disables the policy value", []byte(gpo.Content)); err != nil {
				return result, err
			}
		}
		readme := windowsPolicyBundleReadme(policyPath, options.RefreshPolicy, windowsPolicyBundleHasGPOOptions(options.GPO), true, options.DeleteFile)
		if err := addFile("README.txt", "text", "Operator notes for the Windows policy removal bundle", []byte(readme)); err != nil {
			return result, err
		}
		manifest := struct {
			Type       string                    `json:"type"`
			Source     string                    `json:"source"`
			PolicyPath string                    `json:"policy_path"`
			DeleteFile bool                      `json:"delete_file,omitempty"`
			Validation WindowsPolicyValidation   `json:"validation"`
			Files      []WindowsPolicyBundleFile `json:"files"`
			Operations []string                  `json:"operations"`
		}{
			Type:       "dfx.windows-policy.removal-bundle",
			Source:     result.Source,
			PolicyPath: result.PolicyPath,
			DeleteFile: result.DeleteFile,
			Validation: result.Validation,
			Files:      result.Files,
			Operations: result.Operations,
		}
		manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			return result, fmt.Errorf("encode Windows policy removal bundle manifest: %w", err)
		}
		if err := addFile("manifest.json", "json", "Machine-readable removal bundle manifest", append(manifestJSON, '\n')); err != nil {
			return result, err
		}
		if archivePath != "" {
			if options.DryRun {
				result.Operations = append(result.Operations, "Would write bundle archive: "+archivePath)
			} else {
				if err := windowsPolicyWriteBundleArchive(archivePath, bundleContents); err != nil {
					return result, err
				}
				result.Operations = append(result.Operations, "Wrote bundle archive: "+archivePath)
			}
		}
		if !options.DryRun {
			result.Changed = true
		}
		return result, nil
	}
	if err := addFile("DefaultAssociations.xml", "xml", "Reviewed Windows default-association policy XML", xmlContent); err != nil {
		return result, err
	}
	reg, err := windowsDefaultAssociationsPolicyRegistryFile(WindowsPolicyRegistryFileOptions{PolicyPath: policyPath})
	if err != nil {
		return result, err
	}
	if err := addFile("DefaultAssociations.reg", "reg", "Offline registry artifact for the machine policy pointer", []byte(reg.Content)); err != nil {
		return result, err
	}
	lgpo, err := windowsDefaultAssociationsPolicyLGPOText(WindowsPolicyLGPOTextOptions{PolicyPath: policyPath})
	if err != nil {
		return result, err
	}
	if err := addFile("DefaultAssociations.lgpo.txt", "lgpo-text", "LGPO text artifact for local Group Policy tooling", []byte(lgpo.Content)); err != nil {
		return result, err
	}
	pol, err := windowsDefaultAssociationsPolicyRegistryPOL(WindowsPolicyRegistryPOLOptions{PolicyPath: policyPath})
	if err != nil {
		return result, err
	}
	polContent, err := base64.StdEncoding.DecodeString(pol.ContentBase64)
	if err != nil {
		return result, fmt.Errorf("decode Registry.pol artifact: %w", err)
	}
	if err := addFile("Registry.pol", "registry-pol", "Machine Registry.pol artifact for Group Policy packaging", polContent); err != nil {
		return result, err
	}
	cspOptions := WindowsPolicyCSPOptions{
		File:           source,
		Associations:   options.Associations,
		CallbackScheme: options.CallbackScheme,
		Version:        options.Version,
		Suggested:      options.Suggested,
		SyncML:         true,
	}
	csp, err := windowsDefaultAssociationsPolicyCSP(cspOptions)
	if err != nil {
		return result, err
	}
	if err := addFile("ApplicationDefaults.syncml.xml", "syncml", "ApplicationDefaults CSP SyncML Replace payload", []byte(csp.SyncML)); err != nil {
		return result, err
	}
	intune, err := windowsDefaultAssociationsPolicyIntune(WindowsPolicyIntuneOptions{
		File:           source,
		Associations:   options.Associations,
		CallbackScheme: options.CallbackScheme,
		Version:        options.Version,
		Suggested:      options.Suggested,
	})
	if err != nil {
		return result, err
	}
	intuneJSON, err := json.MarshalIndent(intune, "", "  ")
	if err != nil {
		return result, fmt.Errorf("encode Intune bundle artifact: %w", err)
	}
	if err := addFile("Intune-CustomOMA.json", "json", "Intune custom OMA-URI setting fields", append(intuneJSON, '\n')); err != nil {
		return result, err
	}
	if err := addFile("Deploy-DefaultAssociations.ps1", "powershell", "Local deployment script for the bundled XML and policy pointer", []byte(windowsPolicyBundleDeployScript(policyPath, options.RefreshPolicy))); err != nil {
		return result, err
	}
	if windowsPolicyBundleHasGPOOptions(options.GPO) {
		gpoOptions := options.GPO
		if gpoOptions.PolicyPath == "" {
			gpoOptions.PolicyPath = policyPath
		}
		gpo, err := windowsDefaultAssociationsPolicyGPO(gpoOptions)
		if err != nil {
			return result, err
		}
		if err := addFile("DomainGPO.ps1", "powershell", "Domain GPO create/configure/link script", []byte(gpo.Content)); err != nil {
			return result, err
		}
	}
	readme := windowsPolicyBundleReadme(policyPath, options.RefreshPolicy, windowsPolicyBundleHasGPOOptions(options.GPO), false, false)
	if err := addFile("README.txt", "text", "Operator notes for the Windows policy bundle", []byte(readme)); err != nil {
		return result, err
	}
	manifest := struct {
		Type       string                    `json:"type"`
		Source     string                    `json:"source"`
		PolicyPath string                    `json:"policy_path"`
		Validation WindowsPolicyValidation   `json:"validation"`
		Files      []WindowsPolicyBundleFile `json:"files"`
		Operations []string                  `json:"operations"`
	}{
		Type:       "dfx.windows-policy.bundle",
		Source:     result.Source,
		PolicyPath: result.PolicyPath,
		Validation: result.Validation,
		Files:      result.Files,
		Operations: result.Operations,
	}
	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return result, fmt.Errorf("encode Windows policy bundle manifest: %w", err)
	}
	if err := addFile("manifest.json", "json", "Machine-readable bundle manifest", append(manifestJSON, '\n')); err != nil {
		return result, err
	}
	if archivePath != "" {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write bundle archive: "+archivePath)
		} else {
			if err := windowsPolicyWriteBundleArchive(archivePath, bundleContents); err != nil {
				return result, err
			}
			result.Operations = append(result.Operations, "Wrote bundle archive: "+archivePath)
		}
	}
	if !options.DryRun {
		result.Changed = true
	}
	return result, nil
}

func inspectWindowsDefaultAssociationsPolicyBundle(options WindowsPolicyBundleInspectOptions) (WindowsPolicyBundleInspectResult, error) {
	path := expandWindowsPolicyPath(options.Path)
	archivePath := expandWindowsPolicyPath(options.Archive)
	result := WindowsPolicyBundleInspectResult{
		Source: path,
		Operations: []string{
			"Inspect Windows default-association policy bundle",
		},
	}
	if path != "" && archivePath != "" {
		result.Issues = append(result.Issues, "bundle path and archive are mutually exclusive")
		return result, fmt.Errorf("bundle path and archive are mutually exclusive")
	}
	if path == "" && archivePath == "" {
		result.Issues = append(result.Issues, "bundle path or archive is required")
		return result, fmt.Errorf("bundle path or archive is required")
	}
	files := map[string][]byte{}
	if archivePath != "" {
		result.Source = archivePath
		result.Archive = true
		reader, err := zip.OpenReader(archivePath)
		if err != nil {
			result.Issues = append(result.Issues, "archive could not be opened")
			return result, fmt.Errorf("open Windows policy bundle archive: %w", err)
		}
		defer reader.Close()
		for _, entry := range reader.File {
			if entry.FileInfo().IsDir() {
				continue
			}
			name := filepath.ToSlash(strings.TrimSpace(entry.Name))
			if name == "" {
				continue
			}
			content, err := windowsPolicyReadZipFile(entry)
			if err != nil {
				result.Issues = append(result.Issues, "archive entry could not be read: "+name)
				return result, err
			}
			files[name] = content
		}
		result.Operations = append(result.Operations, "Read bundle archive: "+archivePath)
	} else {
		entries, err := os.ReadDir(path)
		if err != nil {
			result.Issues = append(result.Issues, "bundle directory could not be read")
			return result, fmt.Errorf("read Windows policy bundle directory: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			content, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				result.Issues = append(result.Issues, "bundle file could not be read: "+name)
				return result, fmt.Errorf("read Windows policy bundle file %s: %w", name, err)
			}
			files[name] = content
		}
		result.Operations = append(result.Operations, "Read bundle directory: "+path)
	}
	if manifest, ok := files["manifest.json"]; ok {
		result.ManifestPresent = true
		var parsed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(manifest, &parsed); err != nil {
			result.Issues = append(result.Issues, "manifest.json is not valid JSON")
		} else {
			result.ManifestType = strings.TrimSpace(parsed.Type)
			switch result.ManifestType {
			case "dfx.windows-policy.bundle":
				result.Kind = "deployment"
			case "dfx.windows-policy.removal-bundle":
				result.Kind = "removal"
			default:
				result.Issues = append(result.Issues, "manifest.json has an unknown bundle type")
			}
		}
	} else {
		result.Issues = append(result.Issues, "manifest.json is missing")
	}
	if result.Kind == "" {
		if _, ok := files["DefaultAssociations.xml"]; ok {
			result.Kind = "deployment"
			result.Operations = append(result.Operations, "Inferred deployment bundle from DefaultAssociations.xml")
		} else if _, ok := files["Remove-DefaultAssociations.ps1"]; ok {
			result.Kind = "removal"
			result.Operations = append(result.Operations, "Inferred removal bundle from Remove-DefaultAssociations.ps1")
		}
	}
	expected := windowsPolicyBundleExpectedFiles(result.Kind)
	for _, expectedFile := range expected {
		content, present := files[expectedFile.Path]
		entry := expectedFile
		entry.Present = present
		if present {
			entry.Bytes = len(content)
		} else {
			result.Missing = append(result.Missing, expectedFile.Path)
		}
		result.Files = append(result.Files, entry)
	}
	for name, content := range files {
		if windowsPolicyBundleExpectedFileIndex(expected, name) >= 0 {
			continue
		}
		result.Files = append(result.Files, WindowsPolicyBundleInspectFile{Path: name, Present: true, Bytes: len(content)})
	}
	sort.Slice(result.Files, func(i, j int) bool {
		return result.Files[i].Path < result.Files[j].Path
	})
	if result.Kind == "deployment" {
		if xmlContent, ok := files["DefaultAssociations.xml"]; ok {
			validation := ValidateWindowsPolicyXML(xmlContent, options.CallbackScheme)
			result.Validation = &validation
			if !validation.Valid {
				result.Issues = append(result.Issues, validation.Issues...)
			}
		}
	}
	if result.Kind == "" {
		result.Issues = append(result.Issues, "bundle type could not be determined")
	}
	result.Complete = len(result.Missing) == 0 && result.Kind != ""
	result.Valid = result.Complete && len(result.Issues) == 0
	return result, nil
}

func windowsDefaultAssociationsPolicyCSP(options WindowsPolicyCSPOptions) (WindowsPolicyCSPResult, error) {
	source := expandWindowsPolicyPath(options.File)
	locURI := strings.TrimSpace(options.LocURI)
	if locURI == "" {
		locURI = windowsDefaultAssociationsPolicyCSPLocURI
	}
	cmdID := strings.TrimSpace(options.CmdID)
	if cmdID == "" {
		cmdID = "101"
	}
	result := WindowsPolicyCSPResult{
		Source:    source,
		LocURI:    locURI,
		Command:   "Replace",
		Version:   strings.TrimSpace(options.Version),
		Suggested: options.Suggested,
		Format:    "chr",
		Type:      "text/plain",
		Operations: []string{
			"Generate Windows ApplicationDefaults CSP payload",
		},
	}
	if options.Delete {
		result.Command = "Delete"
		result.Validation = WindowsPolicyValidation{Valid: true, Complete: true}
		result.Operations = append(result.Operations, "Generate CSP Delete payload for ApplicationDefaults")
		if options.SyncML {
			result.SyncML = windowsPolicyDeleteSyncML(cmdID, locURI)
			result.Operations = append(result.Operations, "Generated SyncML Delete payload")
		}
		return result, nil
	}
	var content []byte
	if source != "" {
		var err error
		content, err = os.ReadFile(source)
		if err != nil {
			return result, fmt.Errorf("read Windows default-association policy XML: %w", err)
		}
		result.Operations = append(result.Operations, "Read policy XML: "+source)
	} else {
		if len(options.Associations) == 0 {
			return result, fmt.Errorf("policy file or profile associations are required")
		}
		result.Source = "profile"
		records := []WindowsPolicyAssociation{}
		for index, association := range options.Associations {
			association = association.Normalized()
			if err := association.Validate(); err != nil {
				return result, fmt.Errorf("defaults[%d]: %w", index, err)
			}
			identifiers, err := windowsPolicyIdentifiersForTarget(association.Target(), "")
			if err != nil {
				return result, fmt.Errorf("defaults[%d]: %w", index, err)
			}
			records = mergeWindowsPolicyAssociations(records, identifiers, association.App, association.App, options.Suggested)
			result.Associations = append(result.Associations, association)
			result.Operations = append(result.Operations, fmt.Sprintf("Compile defaults[%d] %s -> %s as %s", index, association.Target().String(), association.App, strings.Join(identifiers, ", ")))
		}
		content = []byte(windowsPolicyXMLFromAssociationsWithVersion(records, options.Version))
		result.Operations = append(result.Operations, "Compiled profile associations into policy XML for CSP payload")
	}
	validation := ValidateWindowsPolicyXML(content, options.CallbackScheme)
	result.Validation = validation
	result.Operations = append(result.Operations, fmt.Sprintf("Validate policy XML: valid=%t complete=%t mandatory=%t", validation.Valid, validation.Complete, validation.Mandatory))
	if !validation.Valid {
		return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
	}
	result.Data = base64.StdEncoding.EncodeToString(content)
	result.Operations = append(result.Operations, "Base64-encoded policy XML for ApplicationDefaults CSP")
	if options.SyncML {
		result.SyncML = windowsPolicySyncML(cmdID, locURI, result.Format, result.Type, result.Data)
		result.Operations = append(result.Operations, "Generated SyncML Replace payload")
	}
	return result, nil
}

func windowsDefaultAssociationsPolicyIntune(options WindowsPolicyIntuneOptions) (WindowsPolicyIntuneResult, error) {
	name := strings.TrimSpace(options.Name)
	if name == "" {
		name = "Windows default app associations"
	}
	description := strings.TrimSpace(options.Description)
	if description == "" {
		description = "Applies default file type and protocol associations with the Windows ApplicationDefaults CSP."
	}
	csp, err := windowsDefaultAssociationsPolicyCSP(WindowsPolicyCSPOptions{
		File:           options.File,
		Associations:   options.Associations,
		CallbackScheme: options.CallbackScheme,
		Version:        options.Version,
		Suggested:      options.Suggested,
	})
	result := WindowsPolicyIntuneResult{
		Name:        name,
		Description: description,
		OMAURI:      csp.LocURI,
		DataType:    "String",
		Value:       csp.Data,
		CSP:         csp,
		Operations: []string{
			"Generate Intune custom OMA-URI setting for ApplicationDefaults CSP",
		},
	}
	result.Operations = append(result.Operations, csp.Operations...)
	if csp.Data != "" {
		result.Operations = append(result.Operations, "Use generated base64 XML value in the Intune custom profile")
	}
	return result, err
}

func windowsDefaultAssociationsDISM(ctx context.Context, runner commandRunner, mode string, options WindowsPolicyDISMOptions) (WindowsPolicyDISMResult, error) {
	file := expandWindowsPolicyPath(options.File)
	image := expandWindowsPolicyPath(options.Image)
	result := WindowsPolicyDISMResult{
		Mode:  mode,
		File:  file,
		Image: image,
		Operations: []string{
			"Prepare DISM default-association " + mode,
		},
	}
	if image != "" {
		result.Command = append(result.Command, "dism", "/Image:"+image)
	} else {
		result.Command = append(result.Command, "dism", "/Online")
	}
	switch mode {
	case "import":
		if file == "" {
			return result, fmt.Errorf("policy XML file is required")
		}
		content, err := os.ReadFile(file)
		if err != nil {
			return result, fmt.Errorf("read Windows default-association policy XML: %w", err)
		}
		validation := ValidateWindowsPolicyXML(content, "")
		result.Operations = append(result.Operations, fmt.Sprintf("Validate policy XML before DISM import: valid=%t complete=%t", validation.Valid, validation.Complete))
		if !validation.Valid {
			return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
		}
		result.Command = append(result.Command, "/Import-DefaultAppAssociations:"+file)
	case "list":
		result.Command = append(result.Command, "/Get-DefaultAppAssociations")
	case "remove":
		result.Command = append(result.Command, "/Remove-DefaultAppAssociations")
	default:
		return result, fmt.Errorf("unsupported DISM default-association mode %q", mode)
	}
	result.Operations = append(result.Operations, "DISM command: "+strings.Join(result.Command, " "))
	if options.DryRun {
		result.Operations = append(result.Operations, "Would run DISM command")
		return result, nil
	}
	if _, err := runner.LookPath("dism"); err != nil {
		return result, fmt.Errorf("Windows DISM tooling is unavailable: %w", err)
	}
	output, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = output
	if err != nil {
		return result, err
	}
	result.Changed = mode == "import" || mode == "remove"
	switch mode {
	case "import":
		result.Operations = append(result.Operations, "Imported default associations into the Windows image/default-user association store")
		result.Operations = append(result.Operations, "DISM imported associations are applied for users during first logon, not by rewriting existing per-user UserChoice values")
	case "remove":
		result.Operations = append(result.Operations, "Removed default associations from the Windows image/default-user association store")
	case "list":
		result.Operations = append(result.Operations, "Listed default associations from the Windows image/default-user association store")
	}
	return result, nil
}

func windowsDefaultAssociationsPolicyGPResult(ctx context.Context, runner commandRunner, options WindowsPolicyGPResultOptions) (WindowsPolicyGPResultResult, error) {
	scope := strings.ToLower(strings.TrimSpace(options.Scope))
	if scope == "" {
		scope = "computer"
	}
	format := strings.ToLower(strings.TrimSpace(options.Format))
	if format == "" {
		format = "summary"
	}
	file := expandWindowsPolicyPath(options.File)
	result := WindowsPolicyGPResultResult{
		Scope:  scope,
		Format: format,
		File:   file,
		System: strings.TrimSpace(options.System),
		User:   strings.TrimSpace(options.User),
		Operations: []string{
			"Prepare gpresult Group Policy evidence command",
		},
	}
	switch scope {
	case "computer", "user":
	default:
		return result, fmt.Errorf("gpresult scope must be computer or user")
	}
	result.Command = append(result.Command, "gpresult")
	if result.System != "" {
		result.Command = append(result.Command, "/s", result.System)
	}
	if result.User != "" {
		result.Command = append(result.Command, "/user", result.User)
	}
	result.Command = append(result.Command, "/scope", scope)
	switch format {
	case "summary":
		result.Command = append(result.Command, "/r")
	case "verbose":
		result.Command = append(result.Command, "/v")
	case "superverbose":
		result.Command = append(result.Command, "/z")
	case "html":
		if file == "" {
			return result, fmt.Errorf("gpresult html format requires --file")
		}
		result.Command = append(result.Command, "/h", file)
	case "xml":
		if file == "" {
			return result, fmt.Errorf("gpresult xml format requires --file")
		}
		result.Command = append(result.Command, "/x", file)
	default:
		return result, fmt.Errorf("unsupported gpresult format %q", format)
	}
	if options.Force {
		switch format {
		case "html", "xml":
			result.Command = append(result.Command, "/f")
		default:
			result.Operations = append(result.Operations, "--force is ignored unless --format is html or xml")
		}
	}
	result.Operations = append(result.Operations, "gpresult command: "+strings.Join(result.Command, " "))
	if options.DryRun {
		result.Operations = append(result.Operations, "Would run gpresult command")
		return result, nil
	}
	if _, err := runner.LookPath("gpresult"); err != nil {
		return result, fmt.Errorf("Windows gpresult tooling is unavailable: %w", err)
	}
	output, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = output
	if err != nil {
		return result, err
	}
	result.Changed = file != ""
	if file != "" {
		result.Operations = append(result.Operations, "Wrote gpresult report to "+file)
	} else {
		result.Operations = append(result.Operations, "Collected gpresult output")
	}
	return result, nil
}

func refreshWindowsDefaultAssociationsGroupPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyGPUpdateOptions) (WindowsPolicyGPUpdateResult, error) {
	target := strings.ToLower(strings.TrimSpace(options.Target))
	wait := strings.TrimSpace(options.Wait)
	result := WindowsPolicyGPUpdateResult{
		Target: target,
		Force:  options.Force,
		Wait:   wait,
		Logoff: options.Logoff,
		Boot:   options.Boot,
		Sync:   options.Sync,
		Operations: []string{
			"Prepare gpupdate Group Policy refresh command",
		},
	}
	result.Command = append(result.Command, "gpupdate")
	if target != "" {
		switch target {
		case "computer", "user":
			result.Command = append(result.Command, "/target:"+target)
		default:
			return result, fmt.Errorf("gpupdate target must be computer or user")
		}
	}
	if options.Force {
		result.Command = append(result.Command, "/force")
	}
	if wait != "" {
		result.Command = append(result.Command, "/wait:"+wait)
	}
	if options.Logoff {
		result.Command = append(result.Command, "/logoff")
	}
	if options.Boot {
		result.Command = append(result.Command, "/boot")
	}
	if options.Sync {
		result.Command = append(result.Command, "/sync")
	}
	result.Operations = append(result.Operations, "gpupdate command: "+strings.Join(result.Command, " "))
	if options.DryRun {
		result.Operations = append(result.Operations, "Would run gpupdate command")
		return result, nil
	}
	if _, err := runner.LookPath("gpupdate"); err != nil {
		return result, fmt.Errorf("Windows gpupdate tooling is unavailable: %w", err)
	}
	output, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = output
	if err != nil {
		return result, err
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Ran gpupdate Group Policy refresh")
	return result, nil
}

func invokeWindowsDefaultAssociationsGroupPolicyRefresh(ctx context.Context, runner commandRunner, options WindowsPolicyInvokeGPUpdateOptions) (WindowsPolicyInvokeGPUpdateResult, error) {
	computer := strings.TrimSpace(options.Computer)
	target := strings.ToLower(strings.TrimSpace(options.Target))
	randomDelay := strings.TrimSpace(options.RandomDelay)
	output := expandWindowsPolicyPath(options.Output)
	result := WindowsPolicyInvokeGPUpdateResult{
		Computer:    computer,
		Target:      target,
		RandomDelay: randomDelay,
		Force:       options.Force,
		Logoff:      options.Logoff,
		Boot:        options.Boot,
		Sync:        options.Sync,
		AsJob:       options.AsJob,
		OutputFile:  output,
		Operations: []string{
			"Prepare Invoke-GPUpdate remote Group Policy refresh command",
		},
	}
	if target != "" {
		switch target {
		case "computer", "user":
			result.Target = strings.ToLower(target)
		default:
			return result, fmt.Errorf("Invoke-GPUpdate target must be computer or user")
		}
	}
	if randomDelay != "" && !windowsPolicyUnsignedDecimal(randomDelay) {
		return result, fmt.Errorf("Invoke-GPUpdate random delay must be a non-negative integer")
	}
	script := windowsPolicyInvokeGPUpdateScript(computer, target, randomDelay, options.Force, options.Logoff, options.Boot, options.Sync, options.AsJob)
	result.Script = script
	if output != "" {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write Invoke-GPUpdate script to "+output)
		} else {
			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
				return result, fmt.Errorf("create Invoke-GPUpdate script directory: %w", err)
			}
			if err := os.WriteFile(output, []byte(script), 0o644); err != nil {
				return result, fmt.Errorf("write Invoke-GPUpdate script: %w", err)
			}
			result.Changed = true
			result.Operations = append(result.Operations, "Wrote Invoke-GPUpdate script to "+output)
		}
		if options.Script || options.DryRun {
			return result, nil
		}
	}
	result.Command = append(result.Command, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	result.Operations = append(result.Operations, "Invoke-GPUpdate command: "+strings.Join(result.Command, " "))
	if options.Script || options.DryRun {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would run Invoke-GPUpdate command")
		}
		return result, nil
	}
	if _, err := runner.LookPath("powershell"); err != nil {
		return result, fmt.Errorf("Windows PowerShell tooling is unavailable: %w", err)
	}
	outputText, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = outputText
	if err != nil {
		return result, err
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Invoked remote Group Policy refresh")
	return result, nil
}

func windowsDefaultAssociationsPolicyGPOReport(ctx context.Context, runner commandRunner, options WindowsPolicyGPOReportOptions) (WindowsPolicyGPOReportResult, error) {
	name := strings.TrimSpace(options.GPOName)
	guid := strings.TrimSpace(options.GPOGUID)
	reportType := strings.ToLower(strings.TrimSpace(options.ReportType))
	if reportType == "" {
		reportType = "html"
	}
	file := expandWindowsPolicyPath(options.File)
	output := expandWindowsPolicyPath(options.Output)
	result := WindowsPolicyGPOReportResult{
		GPOName:    name,
		GPOGUID:    guid,
		All:        options.All,
		ReportType: reportType,
		File:       file,
		Domain:     strings.TrimSpace(options.Domain),
		Server:     strings.TrimSpace(options.Server),
		OutputFile: output,
		Operations: []string{
			"Prepare Get-GPOReport Group Policy report command",
		},
	}
	switch reportType {
	case "html", "xml":
	default:
		return result, fmt.Errorf("GPO report type must be html or xml")
	}
	selected := 0
	if name != "" {
		selected++
	}
	if guid != "" {
		selected++
	}
	if options.All {
		selected++
	}
	if selected != 1 {
		return result, fmt.Errorf("GPO report requires exactly one of --gpo-name, --gpo-guid, or --all")
	}
	script := windowsPolicyGPOReportScript(name, guid, options.All, reportType, file, result.Domain, result.Server)
	result.Script = script
	if output != "" {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write Get-GPOReport script to "+output)
		} else {
			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
				return result, fmt.Errorf("create Get-GPOReport script directory: %w", err)
			}
			if err := os.WriteFile(output, []byte(script), 0o644); err != nil {
				return result, fmt.Errorf("write Get-GPOReport script: %w", err)
			}
			result.Changed = true
			result.Operations = append(result.Operations, "Wrote Get-GPOReport script to "+output)
		}
		if options.Script || options.DryRun {
			return result, nil
		}
	}
	result.Command = append(result.Command, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	result.Operations = append(result.Operations, "Get-GPOReport command: "+strings.Join(result.Command, " "))
	if options.Script || options.DryRun {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would run Get-GPOReport command")
		}
		return result, nil
	}
	if _, err := runner.LookPath("powershell"); err != nil {
		return result, fmt.Errorf("Windows PowerShell tooling is unavailable: %w", err)
	}
	outputText, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = outputText
	if err != nil {
		return result, err
	}
	result.Changed = file != "" || result.Changed
	if file != "" {
		result.Operations = append(result.Operations, "Wrote GPO report to "+file)
	} else {
		result.Operations = append(result.Operations, "Collected GPO report output")
	}
	return result, nil
}

func windowsDefaultAssociationsPolicyGPOStatus(ctx context.Context, runner commandRunner, options WindowsPolicyGPOStatusOptions) (WindowsPolicyGPOStatusResult, error) {
	name := strings.TrimSpace(options.GPOName)
	guid := strings.TrimSpace(options.GPOGUID)
	output := expandWindowsPolicyPath(options.Output)
	result := WindowsPolicyGPOStatusResult{
		GPOName:     name,
		GPOGUID:     guid,
		RegistryKey: windowsDefaultAssociationsPolicyRegistryKey,
		ValueName:   windowsDefaultAssociationsPolicyRegistryValue,
		Domain:      strings.TrimSpace(options.Domain),
		Server:      strings.TrimSpace(options.Server),
		OutputFile:  output,
		Operations: []string{
			"Prepare Get-GPRegistryValue default-association policy status command",
		},
	}
	if name == "" && guid == "" {
		return result, fmt.Errorf("GPO status requires --gpo-name or --gpo-guid")
	}
	if name != "" && guid != "" {
		return result, fmt.Errorf("GPO name and GUID are mutually exclusive")
	}
	script := windowsPolicyGPOStatusScript(name, guid, result.Domain, result.Server)
	result.Script = script
	if output != "" {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write Get-GPRegistryValue script to "+output)
		} else {
			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
				return result, fmt.Errorf("create Get-GPRegistryValue script directory: %w", err)
			}
			if err := os.WriteFile(output, []byte(script), 0o644); err != nil {
				return result, fmt.Errorf("write Get-GPRegistryValue script: %w", err)
			}
			result.Changed = true
			result.Operations = append(result.Operations, "Wrote Get-GPRegistryValue script to "+output)
		}
		if options.Script || options.DryRun {
			return result, nil
		}
	}
	result.Command = append(result.Command, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	result.Operations = append(result.Operations, "Get-GPRegistryValue command: "+strings.Join(result.Command, " "))
	if options.Script || options.DryRun {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would run Get-GPRegistryValue command")
		}
		return result, nil
	}
	if _, err := runner.LookPath("powershell"); err != nil {
		return result, fmt.Errorf("Windows PowerShell tooling is unavailable: %w", err)
	}
	outputText, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = outputText
	if err != nil {
		return result, err
	}
	result.Operations = append(result.Operations, "Collected GPO default-association policy value")
	return result, nil
}

func restoreWindowsDefaultAssociationsPolicyGPO(ctx context.Context, runner commandRunner, options WindowsPolicyGPORestoreOptions) (WindowsPolicyGPORestoreResult, error) {
	name := strings.TrimSpace(options.GPOName)
	guid := strings.TrimSpace(options.GPOGUID)
	path := expandWindowsPolicyPath(options.Path)
	output := expandWindowsPolicyPath(options.Output)
	result := WindowsPolicyGPORestoreResult{
		GPOName:    name,
		GPOGUID:    guid,
		Path:       path,
		Domain:     strings.TrimSpace(options.Domain),
		Server:     strings.TrimSpace(options.Server),
		WhatIf:     options.WhatIf,
		OutputFile: output,
		Operations: []string{
			"Prepare Restore-GPO command",
		},
	}
	if path == "" {
		return result, fmt.Errorf("GPO restore requires --path")
	}
	selected := 0
	if name != "" {
		selected++
	}
	if guid != "" {
		selected++
	}
	if selected != 1 {
		return result, fmt.Errorf("GPO restore requires --gpo-name or --gpo-guid")
	}
	script := windowsPolicyGPORestoreScript(name, guid, path, result.Domain, result.Server, options.WhatIf)
	result.Script = script
	if output != "" {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write Restore-GPO script to "+output)
		} else {
			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
				return result, fmt.Errorf("create Restore-GPO script directory: %w", err)
			}
			if err := os.WriteFile(output, []byte(script), 0o644); err != nil {
				return result, fmt.Errorf("write Restore-GPO script: %w", err)
			}
			result.Changed = true
			result.Operations = append(result.Operations, "Wrote Restore-GPO script to "+output)
		}
		if options.Script || options.DryRun {
			return result, nil
		}
	}
	result.Command = append(result.Command, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	result.Operations = append(result.Operations, "Restore-GPO command: "+strings.Join(result.Command, " "))
	if options.Script || options.DryRun {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would run Restore-GPO command")
		}
		return result, nil
	}
	if _, err := runner.LookPath("powershell"); err != nil {
		return result, fmt.Errorf("Windows PowerShell tooling is unavailable: %w", err)
	}
	outputText, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = outputText
	if err != nil {
		return result, err
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Restored GPO policy state")
	return result, nil
}

func backupWindowsDefaultAssociationsPolicyGPO(ctx context.Context, runner commandRunner, options WindowsPolicyGPOBackupOptions) (WindowsPolicyGPOBackupResult, error) {
	name := strings.TrimSpace(options.GPOName)
	guid := strings.TrimSpace(options.GPOGUID)
	path := expandWindowsPolicyPath(options.Path)
	output := expandWindowsPolicyPath(options.Output)
	result := WindowsPolicyGPOBackupResult{
		GPOName:    name,
		GPOGUID:    guid,
		All:        options.All,
		Path:       path,
		Comment:    strings.TrimSpace(options.Comment),
		Domain:     strings.TrimSpace(options.Domain),
		Server:     strings.TrimSpace(options.Server),
		WhatIf:     options.WhatIf,
		OutputFile: output,
		Operations: []string{
			"Prepare Backup-GPO command",
		},
	}
	if path == "" {
		return result, fmt.Errorf("GPO backup requires --path")
	}
	selected := 0
	if name != "" {
		selected++
	}
	if guid != "" {
		selected++
	}
	if options.All {
		selected++
	}
	if selected != 1 {
		return result, fmt.Errorf("GPO backup requires exactly one of --gpo-name, --gpo-guid, or --all")
	}
	script := windowsPolicyGPOBackupScript(name, guid, options.All, path, result.Comment, result.Domain, result.Server, options.WhatIf)
	result.Script = script
	if output != "" {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would write Backup-GPO script to "+output)
		} else {
			if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
				return result, fmt.Errorf("create Backup-GPO script directory: %w", err)
			}
			if err := os.WriteFile(output, []byte(script), 0o644); err != nil {
				return result, fmt.Errorf("write Backup-GPO script: %w", err)
			}
			result.Changed = true
			result.Operations = append(result.Operations, "Wrote Backup-GPO script to "+output)
		}
		if options.Script || options.DryRun {
			return result, nil
		}
	}
	result.Command = append(result.Command, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	result.Operations = append(result.Operations, "Backup-GPO command: "+strings.Join(result.Command, " "))
	if options.Script || options.DryRun {
		if options.DryRun {
			result.Operations = append(result.Operations, "Would run Backup-GPO command")
		}
		return result, nil
	}
	if _, err := runner.LookPath("powershell"); err != nil {
		return result, fmt.Errorf("Windows PowerShell tooling is unavailable: %w", err)
	}
	outputText, err := runner.Run(ctx, result.Command[0], result.Command[1:]...)
	result.Output = outputText
	if err != nil {
		return result, err
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Backed up GPO policy state")
	return result, nil
}

func backupWindowsDefaultAssociationsPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyBackupOptions) (WindowsPolicyBackupResult, error) {
	destination := expandWindowsPolicyPath(options.File)
	result := WindowsPolicyBackupResult{
		Destination: destination,
		Operations: []string{
			"Backup active Windows default-association policy XML",
		},
	}
	if destination == "" {
		return result, fmt.Errorf("backup file is required")
	}
	content, source, err := currentWindowsPolicyXMLContent(ctx, runner)
	if err != nil {
		return result, err
	}
	result.Source = source
	result.Validation = ValidateWindowsPolicyXML(content, options.CallbackScheme)
	result.Operations = append(result.Operations, "Read active policy XML: "+source)
	result.Operations = append(result.Operations, fmt.Sprintf("Validate active policy XML: valid=%t complete=%t mandatory=%t", result.Validation.Valid, result.Validation.Complete, result.Validation.Mandatory))
	if options.DryRun {
		result.Operations = append(result.Operations, "Would write active policy XML backup to "+destination)
		return result, nil
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return result, fmt.Errorf("create Windows policy backup directory: %w", err)
	}
	if err := os.WriteFile(destination, content, 0o644); err != nil {
		return result, fmt.Errorf("write Windows policy backup XML: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Wrote active policy XML backup to "+destination)
	return result, nil
}

func windowsDefaultAssociationsPolicyRegistryFile(options WindowsPolicyRegistryFileOptions) (WindowsPolicyRegistryFileResult, error) {
	policyPath := expandWindowsPolicyPath(options.PolicyPath)
	if policyPath == "" && !options.Delete {
		policyPath = windowsDefaultAssociationsPolicyDefaultPath()
	}
	result := WindowsPolicyRegistryFileResult{
		RegistryKey: windowsDefaultAssociationsPolicyRegistryKey,
		ValueName:   windowsDefaultAssociationsPolicyRegistryValue,
		PolicyPath:  policyPath,
		Delete:      options.Delete,
		Operations: []string{
			"Generate offline .reg artifact for Windows default-association policy pointer",
		},
	}
	var builder strings.Builder
	builder.WriteString("Windows Registry Editor Version 5.00\r\n\r\n")
	builder.WriteString("[")
	builder.WriteString(windowsRegistryFileKey(windowsDefaultAssociationsPolicyRegistryKey))
	builder.WriteString("]\r\n")
	if options.Delete {
		builder.WriteString(`"`)
		builder.WriteString(windowsDefaultAssociationsPolicyRegistryValue)
		builder.WriteString(`"=-`)
		builder.WriteString("\r\n")
		result.Operations = append(result.Operations, "Generated registry value delete entry")
	} else {
		builder.WriteString(`"`)
		builder.WriteString(windowsDefaultAssociationsPolicyRegistryValue)
		builder.WriteString(`"="`)
		builder.WriteString(windowsRegistryFileStringEscape(policyPath))
		builder.WriteString(`"`)
		builder.WriteString("\r\n")
		result.Operations = append(result.Operations, "Generated registry value set entry for policy XML path")
	}
	result.Content = builder.String()
	return result, nil
}

func windowsDefaultAssociationsPolicyLGPOText(options WindowsPolicyLGPOTextOptions) (WindowsPolicyLGPOTextResult, error) {
	policyPath := expandWindowsPolicyPath(options.PolicyPath)
	if policyPath == "" && !options.Delete {
		policyPath = windowsDefaultAssociationsPolicyDefaultPath()
	}
	registryKey := windowsLGPORegistryPolicyKey(windowsDefaultAssociationsPolicyRegistryKey)
	result := WindowsPolicyLGPOTextResult{
		Configuration: "Computer",
		RegistryKey:   registryKey,
		ValueName:     windowsDefaultAssociationsPolicyRegistryValue,
		PolicyPath:    policyPath,
		Delete:        options.Delete,
		Operations: []string{
			"Generate LGPO text artifact for Windows default-association policy pointer",
		},
	}
	var builder strings.Builder
	builder.WriteString("; dfx Windows default-association policy pointer\r\n")
	builder.WriteString("; Apply with: LGPO.exe /t <this-file>\r\n\r\n")
	builder.WriteString(result.Configuration)
	builder.WriteString("\r\n")
	builder.WriteString(result.RegistryKey)
	builder.WriteString("\r\n")
	builder.WriteString(result.ValueName)
	builder.WriteString("\r\n")
	if options.Delete {
		builder.WriteString("DELETE\r\n")
		result.Operations = append(result.Operations, "Generated LGPO value delete action")
	} else {
		builder.WriteString("SZ:")
		builder.WriteString(policyPath)
		builder.WriteString("\r\n")
		result.Operations = append(result.Operations, "Generated LGPO REG_SZ set action for policy XML path")
	}
	result.Content = builder.String()
	return result, nil
}

func windowsDefaultAssociationsPolicyRegistryPOL(options WindowsPolicyRegistryPOLOptions) (WindowsPolicyRegistryPOLResult, error) {
	policyPath := expandWindowsPolicyPath(options.PolicyPath)
	output := expandWindowsPolicyPath(options.Output)
	if policyPath == "" && !options.Delete {
		policyPath = windowsDefaultAssociationsPolicyDefaultPath()
	}
	registryKey := windowsLGPORegistryPolicyKey(windowsDefaultAssociationsPolicyRegistryKey)
	result := WindowsPolicyRegistryPOLResult{
		Scope:       "Machine",
		RegistryKey: registryKey,
		ValueName:   windowsDefaultAssociationsPolicyRegistryValue,
		PolicyPath:  policyPath,
		Output:      output,
		Delete:      options.Delete,
		DryRun:      options.DryRun,
		Operations: []string{
			"Generate machine Registry.pol artifact for Windows default-association policy pointer",
		},
	}
	valueName := result.ValueName
	registryType := uint32(1)
	var data []byte
	if options.Delete {
		valueName = "**Del." + result.ValueName
		result.Operations = append(result.Operations, "Generated Registry.pol delete instruction for policy value")
	} else {
		data = windowsUTF16LEBytes(policyPath, true)
		result.Operations = append(result.Operations, "Generated Registry.pol REG_SZ instruction for policy XML path")
	}
	content := windowsRegistryPOLFile(registryKey, valueName, registryType, data)
	result.Bytes = len(content)
	result.ContentBase64 = base64.StdEncoding.EncodeToString(content)
	if output == "" {
		result.Operations = append(result.Operations, "No output file requested; returning base64 Registry.pol content")
		return result, nil
	}
	if options.DryRun {
		result.Operations = append(result.Operations, "Would write Registry.pol artifact to "+output)
		return result, nil
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		return result, fmt.Errorf("create Registry.pol output directory: %w", err)
	}
	if err := os.WriteFile(output, content, 0o644); err != nil {
		return result, fmt.Errorf("write Registry.pol artifact: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Wrote Registry.pol artifact to "+output)
	return result, nil
}

func windowsDefaultAssociationsPolicyGPO(options WindowsPolicyGPOOptions) (WindowsPolicyGPOResult, error) {
	name := strings.TrimSpace(options.GPOName)
	guid := strings.TrimSpace(options.GPOGUID)
	policyPath := expandWindowsPolicyPath(options.PolicyPath)
	if policyPath == "" && !options.Delete {
		policyPath = windowsDefaultAssociationsPolicyDefaultPath()
	}
	result := WindowsPolicyGPOResult{
		GPOName:      name,
		GPOGUID:      guid,
		RegistryKey:  windowsDefaultAssociationsPolicyRegistryKey,
		ValueName:    windowsDefaultAssociationsPolicyRegistryValue,
		PolicyPath:   policyPath,
		Domain:       strings.TrimSpace(options.Domain),
		Server:       strings.TrimSpace(options.Server),
		Create:       options.Create,
		Comment:      strings.TrimSpace(options.Comment),
		LinkTarget:   strings.TrimSpace(options.LinkTarget),
		LinkDisabled: options.LinkDisabled,
		Enforced:     options.Enforced,
		Order:        options.Order,
		Delete:       options.Delete,
		WhatIf:       options.WhatIf,
		Command:      "Set-GPRegistryValue",
		Operations: []string{
			"Generate GroupPolicy PowerShell artifact for Windows default-association policy pointer",
		},
	}
	if name == "" && guid == "" {
		return result, fmt.Errorf("GPO name or GUID is required")
	}
	if name != "" && guid != "" {
		return result, fmt.Errorf("GPO name and GUID are mutually exclusive")
	}
	if options.Create && guid != "" {
		return result, fmt.Errorf("GPO creation requires --gpo-name, not --gpo-guid")
	}
	if options.Create && options.Delete {
		return result, fmt.Errorf("GPO creation cannot be combined with --delete")
	}
	if options.Delete && result.LinkTarget != "" {
		return result, fmt.Errorf("GPO link creation cannot be combined with --delete")
	}
	if result.LinkTarget == "" && (options.LinkDisabled || options.Enforced || options.Order != 0) {
		return result, fmt.Errorf("GPO link options require --link-target")
	}
	if options.Order < 0 {
		return result, fmt.Errorf("GPO link order cannot be negative")
	}
	if options.Create {
		result.Command = "New-GPO; Set-GPRegistryValue"
		result.Operations = append(result.Operations, "Generated New-GPO step before configuring policy")
	}
	if result.LinkTarget != "" {
		result.Command = result.Command + "; New-GPLink"
		result.Operations = append(result.Operations, "Generated New-GPLink step for target "+result.LinkTarget)
	}
	var builder strings.Builder
	builder.WriteString("#requires -Modules GroupPolicy\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("# The policy XML path must be reachable by target computers, typically a UNC path.\n")
	if options.Create {
		builder.WriteString("$gpoParams = @{\n")
		builder.WriteString("\tName = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
		builder.WriteString("'\n")
		if result.Comment != "" {
			builder.WriteString("\tComment = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Comment))
			builder.WriteString("'\n")
		}
		if result.Domain != "" {
			builder.WriteString("\tDomain = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Domain))
			builder.WriteString("'\n")
		}
		if result.Server != "" {
			builder.WriteString("\tServer = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Server))
			builder.WriteString("'\n")
		}
		if options.WhatIf {
			builder.WriteString("\tWhatIf = $true\n")
		}
		builder.WriteString("}\n")
		builder.WriteString("New-GPO @gpoParams | Out-Null\n\n")
	}
	builder.WriteString("$params = @{\n")
	if guid != "" {
		builder.WriteString("\tGuid = [Guid]'")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(guid))
		builder.WriteString("'\n")
	} else {
		builder.WriteString("\tName = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
		builder.WriteString("'\n")
	}
	builder.WriteString("\tKey = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(windowsDefaultAssociationsPolicyRegistryKey))
	builder.WriteString("'\n")
	builder.WriteString("\tValueName = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(windowsDefaultAssociationsPolicyRegistryValue))
	builder.WriteString("'\n")
	if result.Domain != "" {
		builder.WriteString("\tDomain = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Domain))
		builder.WriteString("'\n")
	}
	if result.Server != "" {
		builder.WriteString("\tServer = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Server))
		builder.WriteString("'\n")
	}
	if options.Delete {
		builder.WriteString("\tDisable = $true\n")
		result.Operations = append(result.Operations, "Generated Set-GPRegistryValue -Disable action for client-side value removal")
	} else {
		builder.WriteString("\tType = 'String'\n")
		builder.WriteString("\tValue = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(policyPath))
		builder.WriteString("'\n")
		result.Operations = append(result.Operations, "Generated Set-GPRegistryValue REG_SZ action for policy XML path")
	}
	if options.WhatIf {
		builder.WriteString("\tWhatIf = $true\n")
		result.Operations = append(result.Operations, "Enabled PowerShell WhatIf in generated GroupPolicy command")
	}
	builder.WriteString("}\n\n")
	builder.WriteString("Set-GPRegistryValue @params\n")
	if result.LinkTarget != "" {
		builder.WriteString("\n$linkParams = @{\n")
		if guid != "" {
			builder.WriteString("\tGuid = [Guid]'")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(guid))
			builder.WriteString("'\n")
		} else {
			builder.WriteString("\tName = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
			builder.WriteString("'\n")
		}
		builder.WriteString("\tTarget = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(result.LinkTarget))
		builder.WriteString("'\n")
		if result.LinkDisabled {
			builder.WriteString("\tLinkEnabled = 'No'\n")
		} else {
			builder.WriteString("\tLinkEnabled = 'Yes'\n")
		}
		if result.Enforced {
			builder.WriteString("\tEnforced = 'Yes'\n")
		}
		if result.Order > 0 {
			builder.WriteString(fmt.Sprintf("\tOrder = %d\n", result.Order))
		}
		if result.Domain != "" {
			builder.WriteString("\tDomain = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Domain))
			builder.WriteString("'\n")
		}
		if result.Server != "" {
			builder.WriteString("\tServer = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(result.Server))
			builder.WriteString("'\n")
		}
		if options.WhatIf {
			builder.WriteString("\tWhatIf = $true\n")
		}
		builder.WriteString("}\n")
		builder.WriteString("New-GPLink @linkParams\n")
	}
	result.Content = builder.String()
	return result, nil
}

func windowsPolicyBundleHasGPOOptions(options WindowsPolicyGPOOptions) bool {
	return strings.TrimSpace(options.GPOName) != "" ||
		strings.TrimSpace(options.GPOGUID) != "" ||
		strings.TrimSpace(options.Domain) != "" ||
		strings.TrimSpace(options.Server) != "" ||
		strings.TrimSpace(options.Comment) != "" ||
		strings.TrimSpace(options.LinkTarget) != "" ||
		options.Create ||
		options.LinkDisabled ||
		options.Enforced ||
		options.Order != 0
}

func windowsPolicyInvokeGPUpdateScript(computer string, target string, randomDelay string, force bool, logoff bool, boot bool, sync bool, asJob bool) string {
	var builder strings.Builder
	builder.WriteString("#requires -Modules GroupPolicy\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$params = @{\n")
	if strings.TrimSpace(computer) != "" {
		builder.WriteString("\tComputer = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(computer))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(target) != "" {
		builder.WriteString("\tTarget = '")
		builder.WriteString(windowsPolicyPowerShellTarget(target))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(randomDelay) != "" {
		builder.WriteString("\tRandomDelayInMinutes = ")
		builder.WriteString(strings.TrimSpace(randomDelay))
		builder.WriteString("\n")
	}
	if force {
		builder.WriteString("\tForce = $true\n")
	}
	if logoff {
		builder.WriteString("\tLogOff = $true\n")
	}
	if boot {
		builder.WriteString("\tBoot = $true\n")
	}
	if sync {
		builder.WriteString("\tSync = $true\n")
	}
	if asJob {
		builder.WriteString("\tAsJob = $true\n")
	}
	builder.WriteString("}\n\n")
	builder.WriteString("Invoke-GPUpdate @params\n")
	return builder.String()
}

func windowsPolicyGPOReportScript(name string, guid string, all bool, reportType string, file string, domain string, server string) string {
	var builder strings.Builder
	builder.WriteString("#requires -Modules GroupPolicy\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$params = @{\n")
	if all {
		builder.WriteString("\tAll = $true\n")
	} else if strings.TrimSpace(guid) != "" {
		builder.WriteString("\tGuid = [Guid]'")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(guid))
		builder.WriteString("'\n")
	} else {
		builder.WriteString("\tName = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
		builder.WriteString("'\n")
	}
	builder.WriteString("\tReportType = '")
	builder.WriteString(windowsPolicyPowerShellReportType(reportType))
	builder.WriteString("'\n")
	if strings.TrimSpace(file) != "" {
		builder.WriteString("\tPath = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(file))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(domain) != "" {
		builder.WriteString("\tDomain = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(domain))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(server) != "" {
		builder.WriteString("\tServer = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(server))
		builder.WriteString("'\n")
	}
	builder.WriteString("}\n\n")
	builder.WriteString("Get-GPOReport @params\n")
	return builder.String()
}

func windowsPolicyGPOStatusScript(name string, guid string, domain string, server string) string {
	var builder strings.Builder
	builder.WriteString("#requires -Modules GroupPolicy\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$params = @{\n")
	if strings.TrimSpace(guid) != "" {
		builder.WriteString("\tGuid = [Guid]'")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(guid))
		builder.WriteString("'\n")
	} else {
		builder.WriteString("\tName = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
		builder.WriteString("'\n")
	}
	builder.WriteString("\tKey = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(windowsDefaultAssociationsPolicyRegistryKey))
	builder.WriteString("'\n")
	builder.WriteString("\tValueName = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(windowsDefaultAssociationsPolicyRegistryValue))
	builder.WriteString("'\n")
	if strings.TrimSpace(domain) != "" {
		builder.WriteString("\tDomain = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(domain))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(server) != "" {
		builder.WriteString("\tServer = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(server))
		builder.WriteString("'\n")
	}
	builder.WriteString("}\n\n")
	builder.WriteString("Get-GPRegistryValue @params | Format-List *\n")
	return builder.String()
}

func windowsPolicyGPOBackupScript(name string, guid string, all bool, path string, comment string, domain string, server string, whatIf bool) string {
	var builder strings.Builder
	builder.WriteString("#requires -Modules GroupPolicy\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$params = @{\n")
	if all {
		builder.WriteString("\tAll = $true\n")
	} else if strings.TrimSpace(guid) != "" {
		builder.WriteString("\tGuid = [Guid]'")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(guid))
		builder.WriteString("'\n")
	} else {
		builder.WriteString("\tName = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
		builder.WriteString("'\n")
	}
	builder.WriteString("\tPath = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(path))
	builder.WriteString("'\n")
	if strings.TrimSpace(comment) != "" {
		builder.WriteString("\tComment = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(comment))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(domain) != "" {
		builder.WriteString("\tDomain = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(domain))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(server) != "" {
		builder.WriteString("\tServer = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(server))
		builder.WriteString("'\n")
	}
	if whatIf {
		builder.WriteString("\tWhatIf = $true\n")
	}
	builder.WriteString("}\n\n")
	builder.WriteString("Backup-GPO @params\n")
	return builder.String()
}

func windowsPolicyGPORestoreScript(name string, guid string, path string, domain string, server string, whatIf bool) string {
	var builder strings.Builder
	builder.WriteString("#requires -Modules GroupPolicy\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$params = @{\n")
	builder.WriteString("\tPath = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(path))
	builder.WriteString("'\n")
	if strings.TrimSpace(guid) != "" {
		builder.WriteString("\tGuid = [Guid]'")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(guid))
		builder.WriteString("'\n")
	} else {
		builder.WriteString("\tName = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(name))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(domain) != "" {
		builder.WriteString("\tDomain = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(domain))
		builder.WriteString("'\n")
	}
	if strings.TrimSpace(server) != "" {
		builder.WriteString("\tServer = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(server))
		builder.WriteString("'\n")
	}
	if whatIf {
		builder.WriteString("\tWhatIf = $true\n")
	}
	builder.WriteString("}\n\n")
	builder.WriteString("Restore-GPO @params\n")
	return builder.String()
}

func windowsPolicyPowerShellReportType(reportType string) string {
	switch strings.ToLower(strings.TrimSpace(reportType)) {
	case "xml":
		return "Xml"
	default:
		return "Html"
	}
}

func windowsPolicyPowerShellTarget(target string) string {
	switch strings.ToLower(strings.TrimSpace(target)) {
	case "computer":
		return "Computer"
	case "user":
		return "User"
	default:
		return strings.TrimSpace(target)
	}
}

func windowsPolicyUnsignedDecimal(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func windowsPolicyBundleExpectedFiles(kind string) []WindowsPolicyBundleInspectFile {
	switch kind {
	case "deployment":
		return []WindowsPolicyBundleInspectFile{
			{Path: "ApplicationDefaults.syncml.xml", Type: "syncml", Expected: true},
			{Path: "DefaultAssociations.lgpo.txt", Type: "lgpo-text", Expected: true},
			{Path: "DefaultAssociations.reg", Type: "reg", Expected: true},
			{Path: "DefaultAssociations.xml", Type: "xml", Expected: true},
			{Path: "Deploy-DefaultAssociations.ps1", Type: "powershell", Expected: true},
			{Path: "Intune-CustomOMA.json", Type: "json", Expected: true},
			{Path: "README.txt", Type: "text", Expected: true},
			{Path: "Registry.pol", Type: "registry-pol", Expected: true},
			{Path: "manifest.json", Type: "json", Expected: true},
		}
	case "removal":
		return []WindowsPolicyBundleInspectFile{
			{Path: "ApplicationDefaults.delete.syncml.xml", Type: "syncml", Expected: true},
			{Path: "README.txt", Type: "text", Expected: true},
			{Path: "Registry.pol", Type: "registry-pol", Expected: true},
			{Path: "Remove-DefaultAssociations.lgpo.txt", Type: "lgpo-text", Expected: true},
			{Path: "Remove-DefaultAssociations.ps1", Type: "powershell", Expected: true},
			{Path: "Remove-DefaultAssociations.reg", Type: "reg", Expected: true},
			{Path: "manifest.json", Type: "json", Expected: true},
		}
	default:
		return []WindowsPolicyBundleInspectFile{
			{Path: "manifest.json", Type: "json", Expected: true},
		}
	}
}

func windowsPolicyBundleExpectedFileIndex(files []WindowsPolicyBundleInspectFile, name string) int {
	for index, file := range files {
		if file.Path == name {
			return index
		}
	}
	return -1
}

func windowsPolicyReadZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open Windows policy bundle archive entry %s: %w", file.Name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read Windows policy bundle archive entry %s: %w", file.Name, err)
	}
	return content, nil
}

func windowsPolicyWriteBundleArchive(path string, files map[string][]byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create Windows policy bundle archive directory: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create Windows policy bundle archive: %w", err)
	}
	defer file.Close()
	writer := zip.NewWriter(file)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			_ = writer.Close()
			return fmt.Errorf("create Windows policy bundle archive entry %s: %w", name, err)
		}
		if _, err := entry.Write(files[name]); err != nil {
			_ = writer.Close()
			return fmt.Errorf("write Windows policy bundle archive entry %s: %w", name, err)
		}
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finalize Windows policy bundle archive: %w", err)
	}
	return nil
}

func windowsPolicyBundleDeployScript(policyPath string, refreshPolicy bool) string {
	var builder strings.Builder
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$Source = Join-Path $PSScriptRoot 'DefaultAssociations.xml'\n")
	builder.WriteString("$Destination = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(policyPath))
	builder.WriteString("'\n")
	builder.WriteString("$PolicyKey = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\System'\n")
	builder.WriteString("$PolicyValue = 'DefaultAssociationsConfiguration'\n\n")
	builder.WriteString("if (-not (Test-Path -LiteralPath $Source)) {\n")
	builder.WriteString("    throw \"Bundled DefaultAssociations.xml was not found: $Source\"\n")
	builder.WriteString("}\n")
	builder.WriteString("New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null\n")
	builder.WriteString("Copy-Item -LiteralPath $Source -Destination $Destination -Force\n")
	builder.WriteString("New-Item -Path $PolicyKey -Force | Out-Null\n")
	builder.WriteString("New-ItemProperty -Path $PolicyKey -Name $PolicyValue -Value $Destination -PropertyType String -Force | Out-Null\n")
	if refreshPolicy {
		builder.WriteString("gpupdate /target:computer /force\n")
	} else {
		builder.WriteString("Write-Host 'Default-association policy staged. Run gpupdate /target:computer /force and sign out/in if needed.'\n")
	}
	return builder.String()
}

func windowsPolicyBundleRemoveScript(policyPath string, refreshPolicy bool, deleteFile bool) string {
	var builder strings.Builder
	builder.WriteString("$ErrorActionPreference = 'Stop'\n\n")
	builder.WriteString("$Destination = '")
	builder.WriteString(windowsPowerShellSingleQuoteEscape(policyPath))
	builder.WriteString("'\n")
	builder.WriteString("$PolicyKey = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\System'\n")
	builder.WriteString("$PolicyValue = 'DefaultAssociationsConfiguration'\n\n")
	builder.WriteString("if (Test-Path -Path $PolicyKey) {\n")
	builder.WriteString("    Remove-ItemProperty -Path $PolicyKey -Name $PolicyValue -ErrorAction SilentlyContinue\n")
	builder.WriteString("}\n")
	if deleteFile {
		builder.WriteString("Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue\n")
	}
	if refreshPolicy {
		builder.WriteString("gpupdate /target:computer /force\n")
	} else {
		builder.WriteString("Write-Host 'Default-association policy pointer removed. Run gpupdate /target:computer /force and sign out/in if needed.'\n")
	}
	return builder.String()
}

func windowsPolicyBundleReadme(policyPath string, refreshPolicy bool, includesGPO bool, removal bool, deleteFile bool) string {
	var builder strings.Builder
	if removal {
		builder.WriteString("dfx Windows default-association policy removal bundle\n")
		builder.WriteString("========================================================\n\n")
	} else {
		builder.WriteString("dfx Windows default-association policy bundle\n")
		builder.WriteString("================================================\n\n")
	}
	builder.WriteString("Policy XML destination: ")
	builder.WriteString(policyPath)
	builder.WriteString("\n\n")
	builder.WriteString("Files:\n")
	if removal {
		builder.WriteString("- Remove-DefaultAssociations.ps1: local removal script for the policy pointer.\n")
		builder.WriteString("- Remove-DefaultAssociations.reg: offline registry artifact that removes the machine policy pointer.\n")
		builder.WriteString("- Remove-DefaultAssociations.lgpo.txt: LGPO text artifact that removes the local Group Policy value.\n")
		builder.WriteString("- Registry.pol: machine Registry.pol artifact that removes the policy pointer.\n")
		builder.WriteString("- ApplicationDefaults.delete.syncml.xml: ApplicationDefaults CSP SyncML Delete payload.\n")
		if includesGPO {
			builder.WriteString("- Remove-DomainGPO.ps1: GroupPolicy module script that disables the GPO policy value.\n")
		}
	} else {
		builder.WriteString("- DefaultAssociations.xml: reviewed Windows default-association XML.\n")
		builder.WriteString("- Deploy-DefaultAssociations.ps1: local deployment script for the XML and policy pointer.\n")
		builder.WriteString("- DefaultAssociations.reg: offline registry artifact for the machine policy pointer.\n")
		builder.WriteString("- DefaultAssociations.lgpo.txt: LGPO text artifact for local Group Policy tooling.\n")
		builder.WriteString("- Registry.pol: machine Registry.pol artifact for Group Policy packaging.\n")
		builder.WriteString("- ApplicationDefaults.syncml.xml: ApplicationDefaults CSP SyncML Replace payload.\n")
		builder.WriteString("- Intune-CustomOMA.json: Intune custom OMA-URI setting fields.\n")
		if includesGPO {
			builder.WriteString("- DomainGPO.ps1: GroupPolicy module script for domain GPO deployment.\n")
		}
	}
	builder.WriteString("- manifest.json: machine-readable bundle manifest.\n\n")
	builder.WriteString("Notes:\n")
	if removal {
		builder.WriteString("- These artifacts remove the managed default-association policy pointer or CSP value.\n")
		if deleteFile {
			builder.WriteString("- The local removal script also removes the policy XML file at the destination path.\n")
		}
	} else {
		builder.WriteString("- The XML path must be readable by target computers. Use a UNC path for domain GPO deployments.\n")
	}
	builder.WriteString("- These artifacts do not edit hash-protected per-user UserChoice registry keys.\n")
	if refreshPolicy {
		builder.WriteString("- The local script runs gpupdate /target:computer /force.\n")
	} else {
		builder.WriteString("- Run gpupdate /target:computer /force and require a fresh sign-in when needed.\n")
	}
	return builder.String()
}

func windowsDefaultAssociationsPolicyScript(options WindowsPolicyScriptOptions) (WindowsPolicyScriptResult, error) {
	source := expandWindowsPolicyPath(options.File)
	destination := expandWindowsPolicyPath(options.Destination)
	if destination == "" {
		destination = windowsDefaultAssociationsPolicyDefaultPath()
	}
	result := WindowsPolicyScriptResult{
		Source:      source,
		Destination: destination,
		Delete:      options.Delete,
		DeleteFile:  options.DeleteFile,
		GPUpdate:    options.RefreshPolicy,
		Operations: []string{
			"Generate PowerShell deployment script for Windows default-association policy",
		},
	}
	if !options.Delete && source != "" {
		content, err := os.ReadFile(source)
		if err != nil {
			return result, fmt.Errorf("read Windows default-association policy XML: %w", err)
		}
		validation := ValidateWindowsPolicyXML(content, options.CallbackScheme)
		result.Validation = &validation
		result.Operations = append(result.Operations, fmt.Sprintf("Validate policy XML: valid=%t complete=%t mandatory=%t", validation.Valid, validation.Complete, validation.Mandatory))
		if !validation.Valid {
			return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
		}
	}
	var builder strings.Builder
	builder.WriteString("# Generated by dfx. Review before running as administrator.\n")
	builder.WriteString("$ErrorActionPreference = 'Stop'\n")
	builder.WriteString("$policyRegPath = 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\System'\n")
	builder.WriteString("$policyValueName = 'DefaultAssociationsConfiguration'\n")
	if destination != "" {
		builder.WriteString("$policyXmlPath = '")
		builder.WriteString(windowsPowerShellSingleQuoteEscape(destination))
		builder.WriteString("'\n")
	}
	if options.Delete {
		builder.WriteString("if (Test-Path -LiteralPath $policyRegPath) {\n")
		builder.WriteString("  Remove-ItemProperty -LiteralPath $policyRegPath -Name $policyValueName -ErrorAction SilentlyContinue\n")
		builder.WriteString("}\n")
		if options.DeleteFile {
			builder.WriteString("if ($policyXmlPath -and (Test-Path -LiteralPath $policyXmlPath)) {\n")
			builder.WriteString("  Remove-Item -LiteralPath $policyXmlPath -Force\n")
			builder.WriteString("}\n")
			result.Operations = append(result.Operations, "Generated script to remove policy pointer and XML file")
		} else {
			result.Operations = append(result.Operations, "Generated script to remove policy pointer")
		}
	} else {
		if source != "" {
			builder.WriteString("$sourceXmlPath = '")
			builder.WriteString(windowsPowerShellSingleQuoteEscape(source))
			builder.WriteString("'\n")
			builder.WriteString("New-Item -ItemType Directory -Force -Path (Split-Path -Parent $policyXmlPath) | Out-Null\n")
			builder.WriteString("Copy-Item -LiteralPath $sourceXmlPath -Destination $policyXmlPath -Force\n")
			result.Operations = append(result.Operations, "Generated script to copy policy XML to destination")
		}
		builder.WriteString("New-Item -Path $policyRegPath -Force | Out-Null\n")
		builder.WriteString("New-ItemProperty -Path $policyRegPath -Name $policyValueName -PropertyType String -Value $policyXmlPath -Force | Out-Null\n")
		result.Operations = append(result.Operations, "Generated script to set machine policy pointer")
	}
	if options.RefreshPolicy {
		builder.WriteString("gpupdate /target:computer /force\n")
		builder.WriteString("Write-Host 'Default-association policy refresh requested. Sign out and back in if changes are not immediately visible.'\n")
		result.Operations = append(result.Operations, "Generated script to run gpupdate")
	} else {
		builder.WriteString("Write-Host 'Default-association policy updated. Run gpupdate /target:computer /force and sign out/in if needed.'\n")
	}
	result.Content = builder.String()
	return result, nil
}

func windowsPowerShellSingleQuoteEscape(value string) string {
	return strings.ReplaceAll(value, `'`, `''`)
}

func windowsRegistryPOLFile(key string, value string, registryType uint32, data []byte) []byte {
	var buffer bytes.Buffer
	buffer.Write([]byte{'P', 'R', 'e', 'g'})
	windowsWriteUint32LE(&buffer, 1)
	windowsWriteUTF16LEString(&buffer, "[", false)
	windowsWriteUTF16LEString(&buffer, key, true)
	windowsWriteUTF16LEString(&buffer, ";", false)
	windowsWriteUTF16LEString(&buffer, value, true)
	windowsWriteUTF16LEString(&buffer, ";", false)
	windowsWriteUint32LE(&buffer, registryType)
	windowsWriteUTF16LEString(&buffer, ";", false)
	windowsWriteUint32LE(&buffer, uint32(len(data)))
	windowsWriteUTF16LEString(&buffer, ";", false)
	buffer.Write(data)
	windowsWriteUTF16LEString(&buffer, "]", false)
	return buffer.Bytes()
}

func windowsUTF16LEBytes(value string, terminated bool) []byte {
	var buffer bytes.Buffer
	windowsWriteUTF16LEString(&buffer, value, terminated)
	return buffer.Bytes()
}

func windowsWriteUTF16LEString(buffer *bytes.Buffer, value string, terminated bool) {
	for _, encoded := range utf16.Encode([]rune(value)) {
		windowsWriteUint16LE(buffer, encoded)
	}
	if terminated {
		windowsWriteUint16LE(buffer, 0)
	}
}

func windowsWriteUint16LE(buffer *bytes.Buffer, value uint16) {
	buffer.WriteByte(byte(value))
	buffer.WriteByte(byte(value >> 8))
}

func windowsWriteUint32LE(buffer *bytes.Buffer, value uint32) {
	buffer.WriteByte(byte(value))
	buffer.WriteByte(byte(value >> 8))
	buffer.WriteByte(byte(value >> 16))
	buffer.WriteByte(byte(value >> 24))
}

func windowsLGPORegistryPolicyKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, `HKLM\`)
	key = strings.TrimPrefix(key, `HKEY_LOCAL_MACHINE\`)
	key = strings.TrimPrefix(key, `HKCU\`)
	key = strings.TrimPrefix(key, `HKEY_CURRENT_USER\`)
	return key
}

func windowsRegistryFileKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, `HKLM\`)
	key = strings.TrimPrefix(key, `HKEY_LOCAL_MACHINE\`)
	key = strings.TrimPrefix(key, `HKCU\`)
	key = strings.TrimPrefix(key, `HKEY_CURRENT_USER\`)
	return `HKEY_LOCAL_MACHINE\` + key
}

func windowsRegistryFileStringEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

func normalizeWindowsDefaultAssociationsPolicyXML(options WindowsPolicyNormalizeOptions) (WindowsPolicyNormalizeResult, error) {
	source := expandWindowsPolicyPath(options.File)
	destination := expandWindowsPolicyPath(options.Output)
	if destination == "" {
		destination = source
	}
	result := WindowsPolicyNormalizeResult{
		Source:      source,
		Destination: destination,
		Operations: []string{
			"Normalize Windows default-association policy XML",
		},
	}
	if source == "" {
		return result, fmt.Errorf("policy file is required")
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return result, fmt.Errorf("read Windows default-association policy XML: %w", err)
	}
	result.Operations = append(result.Operations, "Read policy XML: "+source)
	records, issues := parseWindowsPolicyXML(content)
	if len(issues) > 0 {
		return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(issues, "; "))
	}
	version := strings.TrimSpace(options.Version)
	if version == "" {
		version = windowsPolicyVersionFromXML(content)
	}
	records = mergeWindowsPolicyAssociations(records, nil, "", "", false)
	xmlText := windowsPolicyXMLFromAssociationsWithVersion(records, version)
	result.Version = version
	result.XML = xmlText
	result.Validation = ValidateWindowsPolicyXML([]byte(xmlText), "")
	result.Operations = append(result.Operations, fmt.Sprintf("Normalize %d policy association records", len(records)))
	result.Operations = append(result.Operations, fmt.Sprintf("Validate normalized policy XML: valid=%t complete=%t mandatory=%t", result.Validation.Valid, result.Validation.Complete, result.Validation.Mandatory))
	if !result.Validation.Valid {
		return result, fmt.Errorf("normalized Windows default-association policy XML is invalid: %s", strings.Join(result.Validation.Issues, "; "))
	}
	if options.DryRun {
		result.Operations = append(result.Operations, "Would write normalized policy XML to "+destination)
		return result, nil
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return result, fmt.Errorf("create Windows policy XML directory: %w", err)
	}
	if err := os.WriteFile(destination, []byte(xmlText), 0o644); err != nil {
		return result, fmt.Errorf("write normalized Windows policy XML: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Wrote normalized policy XML to "+destination)
	return result, nil
}

func windowsPolicyProfileFromXML(content []byte) (WindowsPolicyProfileResult, error) {
	validation := ValidateWindowsPolicyXML(content, "")
	result := WindowsPolicyProfileResult{
		Validation: validation,
		Operations: []string{
			"Convert Windows default-association XML to dfx profile associations",
		},
	}
	if !validation.Valid {
		return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
	}
	targetProgIDs := windowsPolicyTargetProgIDMap(validation.Records)
	consumed := map[string]struct{}{}
	if browserProgID := windowsPolicyBrowserProgID(targetProgIDs); browserProgID != "" {
		result.Associations = append(result.Associations, Association{Kind: KindBrowser, Value: "default", App: browserProgID})
		for _, target := range []string{"http", "https", "text/html", "application/xhtml+xml"} {
			consumed[target] = struct{}{}
		}
		result.Operations = append(result.Operations, "Coalesced browser policy targets into one browser profile entry")
	}
	targets := make([]string, 0, len(targetProgIDs))
	for target := range targetProgIDs {
		if _, ok := consumed[target]; ok {
			continue
		}
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		progID := strings.TrimSpace(targetProgIDs[target])
		if progID == "" {
			continue
		}
		kind := KindScheme
		if strings.Contains(target, "/") {
			kind = KindMIME
		}
		result.Associations = append(result.Associations, Association{Kind: kind, Value: target, App: progID})
	}
	result.Operations = append(result.Operations, fmt.Sprintf("Generated %d dfx profile associations", len(result.Associations)))
	return result, nil
}

func windowsPolicyBrowserProgID(targetProgIDs map[string]string) string {
	required := []string{"http", "https", "text/html", "application/xhtml+xml"}
	value := ""
	for _, target := range required {
		progID := strings.TrimSpace(targetProgIDs[target])
		if progID == "" {
			return ""
		}
		if value == "" {
			value = progID
			continue
		}
		if !strings.EqualFold(value, progID) {
			return ""
		}
	}
	return value
}

func listWindowsRegisteredApplications(ctx context.Context, runner commandRunner, options WindowsRegisteredApplicationsOptions) (WindowsRegisteredApplicationsResult, error) {
	query := strings.TrimSpace(strings.ToLower(options.Query))
	result := WindowsRegisteredApplicationsResult{
		Platform: "windows",
		Query:    strings.TrimSpace(options.Query),
		Operations: []string{
			"Query Windows RegisteredApplications and Capabilities registry metadata",
		},
	}
	if _, err := runner.LookPath("reg"); err != nil {
		return result, fmt.Errorf("Windows registry tooling is unavailable: %w", err)
	}
	roots := []struct {
		scope string
		key   string
	}{
		{scope: "user", key: `HKCU\Software\RegisteredApplications`},
		{scope: "machine", key: `HKLM\Software\RegisteredApplications`},
	}
	for _, root := range roots {
		values, err := windowsPolicyReadRegValues(ctx, runner, root.key)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			capabilitiesPath := strings.TrimSpace(values[name])
			capabilitiesKey := windowsPolicyCapabilityKey(root.key, capabilitiesPath)
			app := WindowsRegisteredApplication{
				Scope:            root.scope,
				Name:             name,
				CapabilitiesPath: capabilitiesPath,
				CapabilitiesKey:  capabilitiesKey,
			}
			if capabilitiesKey == "" {
				app.Issues = append(app.Issues, "registered application has no resolvable capabilities key")
			} else {
				capabilityValues, err := windowsPolicyReadRegValues(ctx, runner, capabilitiesKey)
				if err != nil {
					app.Issues = append(app.Issues, "capabilities key is not readable: "+err.Error())
				} else {
					app.ApplicationName = strings.TrimSpace(capabilityValues["ApplicationName"])
					app.Description = strings.TrimSpace(capabilityValues["ApplicationDescription"])
				}
				app.Associations = windowsPolicyRegisteredApplicationAssociations(ctx, runner, capabilitiesKey)
				app.BrowserCandidate = windowsPolicyRegisteredApplicationLooksLikeBrowser(app.Associations)
			}
			if query != "" && !windowsPolicyRegisteredApplicationMatches(app, query) {
				continue
			}
			result.Applications = append(result.Applications, app)
		}
	}
	result.Operations = append(result.Operations, fmt.Sprintf("Discovered %d registered application entries", len(result.Applications)))
	return result, nil
}

func resolveWindowsPolicyAssociations(ctx context.Context, runner commandRunner, options WindowsPolicyAppResolutionOptions) (WindowsPolicyAppResolutionResult, error) {
	result := WindowsPolicyAppResolutionResult{
		Operations: []string{
			"Resolve profile app queries to Windows ProgIDs using RegisteredApplications metadata",
		},
	}
	registered, err := listWindowsRegisteredApplications(ctx, runner, WindowsRegisteredApplicationsOptions{})
	if err != nil {
		return result, err
	}
	for index, association := range options.Associations {
		original := association
		association = association.Normalized()
		if err := association.Validate(); err != nil {
			return result, fmt.Errorf("defaults[%d]: %w", index, err)
		}
		resolvedApp, source, candidates, err := resolveWindowsPolicyAppFromRegistered(association, registered.Applications)
		if err != nil {
			return result, fmt.Errorf("defaults[%d]: %w", index, err)
		}
		resolved := association
		resolved.App = resolvedApp
		result.Associations = append(result.Associations, resolved)
		result.Resolutions = append(result.Resolutions, WindowsPolicyAppResolution{
			Query:      association.App,
			Target:     association.Target(),
			App:        resolvedApp,
			Source:     source,
			Candidates: candidates,
			Original:   original,
			Resolved:   resolved,
		})
		result.Operations = append(result.Operations, fmt.Sprintf("Resolved defaults[%d] %s %q -> %s", index, association.Target().String(), association.App, resolvedApp))
	}
	return result, nil
}

type windowsPolicyAppCandidate struct {
	progID string
	source string
	score  int
}

func resolveWindowsPolicyAppFromRegistered(association Association, apps []WindowsRegisteredApplication) (string, string, []string, error) {
	query := strings.TrimSpace(association.App)
	if query == "" {
		return "", "", nil, fmt.Errorf("app is required")
	}
	queryLower := strings.ToLower(query)
	targets := windowsPolicyTargetsForAssociation(association)
	candidates := []windowsPolicyAppCandidate{}
	seen := map[string]int{}
	for _, app := range apps {
		for _, assoc := range app.Associations {
			if !windowsPolicyAssociationCoversAnyTarget(assoc, targets) {
				continue
			}
			score := windowsPolicyRegisteredAppResolutionScore(queryLower, app, assoc)
			if score == 0 {
				continue
			}
			key := strings.ToLower(assoc.ProgID)
			if previous, ok := seen[key]; ok && previous >= score {
				continue
			}
			seen[key] = score
			candidates = append(candidates, windowsPolicyAppCandidate{
				progID: assoc.ProgID,
				source: strings.TrimSpace(app.ApplicationName),
				score:  score,
			})
			if candidates[len(candidates)-1].source == "" {
				candidates[len(candidates)-1].source = app.Name
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].progID < candidates[j].progID
	})
	candidateProgIDs := windowsPolicyAppCandidateProgIDs(candidates)
	if len(candidates) == 0 {
		return "", "", nil, fmt.Errorf("could not resolve app query %q to a Windows ProgID for %s", query, association.Target().String())
	}
	if len(candidates) > 1 && candidates[0].score == candidates[1].score {
		return "", "", candidateProgIDs, fmt.Errorf("app query %q is ambiguous for %s; use an exact ProgID: %s", query, association.Target().String(), strings.Join(candidateProgIDs, ", "))
	}
	return candidates[0].progID, candidates[0].source, candidateProgIDs, nil
}

func windowsPolicyTargetsForAssociation(association Association) map[string]struct{} {
	targets := map[string]struct{}{}
	identifiers, err := windowsPolicyIdentifiersForTarget(association.Target(), "")
	if err != nil {
		targets[association.Target().String()] = struct{}{}
		return targets
	}
	for _, identifier := range identifiers {
		mapped := MapWindowsPolicyIdentifierToTargets(identifier)
		if len(mapped) == 0 {
			targets[strings.ToLower(identifier)] = struct{}{}
			continue
		}
		for _, target := range mapped {
			targets[strings.ToLower(target)] = struct{}{}
		}
	}
	return targets
}

func windowsPolicyAssociationCoversAnyTarget(association WindowsRegisteredApplicationAssociation, targets map[string]struct{}) bool {
	for _, target := range association.Targets {
		if _, ok := targets[strings.ToLower(target)]; ok {
			return true
		}
	}
	if _, ok := targets[strings.ToLower(association.Identifier)]; ok {
		return true
	}
	return false
}

func windowsPolicyRegisteredAppResolutionScore(query string, app WindowsRegisteredApplication, association WindowsRegisteredApplicationAssociation) int {
	values := []struct {
		value string
		score int
	}{
		{association.ProgID, 100},
		{app.Name, 90},
		{app.ApplicationName, 90},
		{association.Identifier, 80},
	}
	for _, target := range association.Targets {
		values = append(values, struct {
			value string
			score int
		}{target, 70})
	}
	for _, item := range values {
		value := strings.ToLower(strings.TrimSpace(item.value))
		if value == "" {
			continue
		}
		if value == query {
			return item.score
		}
	}
	for _, item := range values {
		value := strings.ToLower(strings.TrimSpace(item.value))
		if value == "" {
			continue
		}
		if strings.Contains(value, query) {
			return item.score - 10
		}
	}
	return 0
}

func windowsPolicyAppCandidateProgIDs(candidates []windowsPolicyAppCandidate) []string {
	values := []string{}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		key := strings.ToLower(candidate.progID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		values = append(values, candidate.progID)
	}
	sort.Strings(values)
	return values
}

func windowsPolicyCapabilityKey(rootKey, capabilityPath string) string {
	capabilityPath = strings.TrimSpace(capabilityPath)
	if capabilityPath == "" {
		return ""
	}
	upperPath := strings.ToUpper(capabilityPath)
	switch {
	case strings.HasPrefix(upperPath, `HKCU\`), strings.HasPrefix(upperPath, `HKLM\`), strings.HasPrefix(upperPath, `HKEY_CURRENT_USER\`), strings.HasPrefix(upperPath, `HKEY_LOCAL_MACHINE\`):
		return capabilityPath
	case strings.HasPrefix(strings.ToUpper(rootKey), `HKCU\`), strings.HasPrefix(strings.ToUpper(rootKey), `HKEY_CURRENT_USER\`):
		return `HKCU\` + strings.TrimLeft(capabilityPath, `\`)
	case strings.HasPrefix(strings.ToUpper(rootKey), `HKLM\`), strings.HasPrefix(strings.ToUpper(rootKey), `HKEY_LOCAL_MACHINE\`):
		return `HKLM\` + strings.TrimLeft(capabilityPath, `\`)
	default:
		return ""
	}
}

func windowsPolicyRegisteredApplicationAssociations(ctx context.Context, runner commandRunner, capabilitiesKey string) []WindowsRegisteredApplicationAssociation {
	categories := []struct {
		kind string
		key  string
	}{
		{kind: "scheme", key: capabilitiesKey + `\URLAssociations`},
		{kind: "mime", key: capabilitiesKey + `\MIMEAssociations`},
		{kind: "extension", key: capabilitiesKey + `\FileAssociations`},
	}
	associations := []WindowsRegisteredApplicationAssociation{}
	for _, category := range categories {
		values, err := windowsPolicyReadRegValues(ctx, runner, category.key)
		if err != nil {
			continue
		}
		identifiers := make([]string, 0, len(values))
		for identifier := range values {
			identifiers = append(identifiers, identifier)
		}
		sort.Strings(identifiers)
		for _, identifier := range identifiers {
			progID := strings.TrimSpace(values[identifier])
			if progID == "" {
				continue
			}
			associations = append(associations, WindowsRegisteredApplicationAssociation{
				Kind:       category.kind,
				Identifier: strings.TrimSpace(strings.ToLower(identifier)),
				ProgID:     progID,
				Targets:    MapWindowsPolicyIdentifierToTargets(identifier),
			})
		}
	}
	return associations
}

func windowsPolicyRegisteredApplicationLooksLikeBrowser(associations []WindowsRegisteredApplicationAssociation) bool {
	covered := map[string]struct{}{}
	for _, association := range associations {
		for _, target := range association.Targets {
			covered[target] = struct{}{}
		}
	}
	for _, target := range []string{"http", "https", "text/html", "application/xhtml+xml"} {
		if _, ok := covered[target]; !ok {
			return false
		}
	}
	return true
}

func windowsPolicyRegisteredApplicationMatches(app WindowsRegisteredApplication, query string) bool {
	needles := []string{app.Name, app.ApplicationName, app.Description, app.CapabilitiesPath, app.CapabilitiesKey}
	for _, association := range app.Associations {
		needles = append(needles, association.Identifier, association.ProgID)
		needles = append(needles, association.Targets...)
	}
	for _, needle := range needles {
		if strings.Contains(strings.ToLower(strings.TrimSpace(needle)), query) {
			return true
		}
	}
	return false
}

func windowsPolicySyncML(cmdID, locURI, format, typ, data string) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	builder.WriteByte('\n')
	builder.WriteString(`<SyncML xmlns="SYNCML:SYNCML1.1">`)
	builder.WriteByte('\n')
	builder.WriteString(`  <SyncBody>`)
	builder.WriteByte('\n')
	builder.WriteString(`    <Replace>`)
	builder.WriteByte('\n')
	builder.WriteString(`      <CmdID>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(cmdID))
	builder.WriteString(`</CmdID>`)
	builder.WriteByte('\n')
	builder.WriteString(`      <Item>`)
	builder.WriteByte('\n')
	builder.WriteString(`        <Meta>`)
	builder.WriteByte('\n')
	builder.WriteString(`          <Format>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(format))
	builder.WriteString(`</Format>`)
	builder.WriteByte('\n')
	builder.WriteString(`          <Type>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(typ))
	builder.WriteString(`</Type>`)
	builder.WriteByte('\n')
	builder.WriteString(`        </Meta>`)
	builder.WriteByte('\n')
	builder.WriteString(`        <Target>`)
	builder.WriteByte('\n')
	builder.WriteString(`          <LocURI>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(locURI))
	builder.WriteString(`</LocURI>`)
	builder.WriteByte('\n')
	builder.WriteString(`        </Target>`)
	builder.WriteByte('\n')
	builder.WriteString(`        <Data>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(data))
	builder.WriteString(`</Data>`)
	builder.WriteByte('\n')
	builder.WriteString(`      </Item>`)
	builder.WriteByte('\n')
	builder.WriteString(`    </Replace>`)
	builder.WriteByte('\n')
	builder.WriteString(`    <Final/>`)
	builder.WriteByte('\n')
	builder.WriteString(`  </SyncBody>`)
	builder.WriteByte('\n')
	builder.WriteString(`</SyncML>`)
	builder.WriteByte('\n')
	return builder.String()
}

func windowsPolicyDeleteSyncML(cmdID, locURI string) string {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	builder.WriteByte('\n')
	builder.WriteString(`<SyncML xmlns="SYNCML:SYNCML1.1">`)
	builder.WriteByte('\n')
	builder.WriteString(`  <SyncBody>`)
	builder.WriteByte('\n')
	builder.WriteString(`    <Delete>`)
	builder.WriteByte('\n')
	builder.WriteString(`      <CmdID>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(cmdID))
	builder.WriteString(`</CmdID>`)
	builder.WriteByte('\n')
	builder.WriteString(`      <Item>`)
	builder.WriteByte('\n')
	builder.WriteString(`        <Target>`)
	builder.WriteByte('\n')
	builder.WriteString(`          <LocURI>`)
	builder.WriteString(windowsPolicyXMLAttributeEscape(locURI))
	builder.WriteString(`</LocURI>`)
	builder.WriteByte('\n')
	builder.WriteString(`        </Target>`)
	builder.WriteByte('\n')
	builder.WriteString(`      </Item>`)
	builder.WriteByte('\n')
	builder.WriteString(`    </Delete>`)
	builder.WriteByte('\n')
	builder.WriteString(`    <Final/>`)
	builder.WriteByte('\n')
	builder.WriteString(`  </SyncBody>`)
	builder.WriteByte('\n')
	builder.WriteString(`</SyncML>`)
	builder.WriteByte('\n')
	return builder.String()
}

func diffWindowsPolicyXMLContent(result WindowsPolicyDiffResult, desiredContent, currentContent []byte, callbackScheme string) (WindowsPolicyDiffResult, error) {
	result.DesiredValidation = ValidateWindowsPolicyXML(desiredContent, callbackScheme)
	result.CurrentValidation = ValidateWindowsPolicyXML(currentContent, callbackScheme)
	if !result.DesiredValidation.Valid {
		return result, fmt.Errorf("desired Windows default-association policy XML is invalid: %s", strings.Join(result.DesiredValidation.Issues, "; "))
	}
	if !result.CurrentValidation.Valid {
		return result, fmt.Errorf("current Windows default-association policy XML is invalid: %s", strings.Join(result.CurrentValidation.Issues, "; "))
	}
	desired := windowsPolicyTargetProgIDMap(result.DesiredValidation.Records)
	current := windowsPolicyTargetProgIDMap(result.CurrentValidation.Records)
	targets := windowsPolicyDiffTargets(desired, current)
	result.Equal = true
	for _, target := range targets {
		desiredProgID := desired[target]
		currentProgID := current[target]
		entry := WindowsPolicyDiffEntry{
			Target:        target,
			CurrentProgID: currentProgID,
			DesiredProgID: desiredProgID,
			Status:        "match",
		}
		switch {
		case desiredProgID == "" && currentProgID != "":
			entry.Status = "extra"
		case desiredProgID != "" && currentProgID == "":
			entry.Status = "missing"
		case !strings.EqualFold(desiredProgID, currentProgID):
			entry.Status = "different"
		}
		if entry.Status != "match" {
			result.Equal = false
		}
		result.Entries = append(result.Entries, entry)
	}
	if result.Equal {
		result.Operations = append(result.Operations, "Current policy matches desired policy targets")
	} else {
		result.Operations = append(result.Operations, "Current policy differs from desired policy targets")
	}
	return result, nil
}

func currentWindowsPolicyXMLContent(ctx context.Context, runner commandRunner) ([]byte, string, error) {
	if _, err := runner.LookPath("reg"); err != nil {
		return nil, "", fmt.Errorf("Windows registry policy tooling is unavailable: %w", err)
	}
	for _, source := range windowsDefaultAssociationPolicyRegistrySources() {
		values, err := windowsPolicyReadRegValues(ctx, runner, source.key)
		if err != nil {
			continue
		}
		for _, valueName := range source.valueNames {
			value := strings.TrimSpace(values[valueName])
			if value == "" {
				continue
			}
			raw := normalizeWindowsPolicyAssociationXMLText(value)
			if strings.HasPrefix(raw, "<") {
				return []byte(raw), fmt.Sprintf("%s/%s", source.key, valueName), nil
			}
			path := expandWindowsPolicyPath(firstWindowsPolicyPathValue(value))
			if path == "" {
				continue
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, path, fmt.Errorf("read active Windows default-association policy XML: %w", err)
			}
			return content, path, nil
		}
	}
	return nil, "", fmt.Errorf("no active Windows default-association policy XML source found")
}

func exportWindowsDefaultAssociationsPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyExportOptions) (WindowsPolicyExportResult, error) {
	destination := expandWindowsPolicyPath(options.File)
	if destination == "" {
		return WindowsPolicyExportResult{}, fmt.Errorf("export file is required")
	}
	result := WindowsPolicyExportResult{
		Destination: destination,
		Operations: []string{
			"Export current Windows default associations to: " + destination,
		},
	}
	if options.DryRun {
		result.Operations = append(result.Operations, "Would run dism /Online /Export-DefaultAppAssociations:"+destination)
		result.Operations = append(result.Operations, "Would validate exported default-association XML")
		return result, nil
	}
	if _, err := runner.LookPath("dism"); err != nil {
		return result, fmt.Errorf("Windows DISM tooling is unavailable: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return result, fmt.Errorf("create Windows default-associations export directory: %w", err)
	}
	if _, err := runner.Run(ctx, "dism", "/Online", "/Export-DefaultAppAssociations:"+destination); err != nil {
		return result, fmt.Errorf("export Windows default associations with DISM: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, "Ran dism /Online /Export-DefaultAppAssociations:"+destination)
	content, err := os.ReadFile(destination)
	if err != nil {
		return result, fmt.Errorf("read exported Windows default-association XML: %w", err)
	}
	validation := ValidateWindowsPolicyXML(content, options.CallbackScheme)
	result.Validation = &validation
	result.Operations = append(result.Operations, fmt.Sprintf("Validate exported policy XML: valid=%t complete=%t mandatory=%t", validation.Valid, validation.Complete, validation.Mandatory))
	if !validation.Valid {
		return result, fmt.Errorf("exported Windows default-association XML is invalid: %s", strings.Join(validation.Issues, "; "))
	}
	return result, nil
}

func installWindowsDefaultAssociationsPolicy(ctx context.Context, runner commandRunner, options WindowsPolicyInstallOptions) (WindowsPolicyInstallResult, error) {
	source := expandWindowsPolicyPath(options.File)
	if source == "" {
		return WindowsPolicyInstallResult{}, fmt.Errorf("policy file is required")
	}
	destination := expandWindowsPolicyPath(options.Destination)
	if destination == "" {
		destination = windowsDefaultAssociationsPolicyDefaultPath()
	}

	result := WindowsPolicyInstallResult{
		Source:                 source,
		Destination:            destination,
		PolicyRefreshRequested: options.RefreshPolicy,
		RequiresSignIn:         true,
		Operations: []string{
			"Read Windows default-association policy XML: " + source,
		},
	}
	content, err := os.ReadFile(source)
	if err != nil {
		return result, err
	}
	validation := ValidateWindowsPolicyXML(content, options.CallbackScheme)
	result.Validation = validation
	result.Operations = append(result.Operations, fmt.Sprintf("Validate policy XML: valid=%t complete=%t mandatory=%t", validation.Valid, validation.Complete, validation.Mandatory))
	if !validation.Valid {
		return result, fmt.Errorf("Windows default-association policy XML is invalid: %s", strings.Join(validation.Issues, "; "))
	}
	if !validation.Complete && !options.AllowIncomplete {
		return result, fmt.Errorf("Windows default-association policy XML is incomplete: missing %s", strings.Join(validation.Missing, ", "))
	}
	if options.AllowIncomplete && !validation.Complete {
		result.Operations = append(result.Operations, "Install allows incomplete policy coverage by request")
	}

	result.Operations = append(result.Operations, "Do not edit UserChoice registry keys directly; Windows protects them with per-user hashes")
	if options.DryRun {
		if sameWindowsPolicyPath(source, destination) {
			result.Operations = append(result.Operations, "Would use existing policy XML path: "+destination)
		} else {
			result.Operations = append(result.Operations, fmt.Sprintf("Would copy policy XML to %s", destination))
		}
		result.Operations = append(result.Operations, fmt.Sprintf("Would configure %s/%s=%s", windowsDefaultAssociationsPolicyRegistryKey, windowsDefaultAssociationsPolicyRegistryValue, destination))
		if options.RefreshPolicy {
			result.Operations = append(result.Operations, "Would run gpupdate /target:computer /force")
		}
		return result, nil
	}
	if _, err := runner.LookPath("reg"); err != nil {
		return result, fmt.Errorf("Windows registry policy tooling is unavailable: %w", err)
	}
	if !sameWindowsPolicyPath(source, destination) {
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return result, fmt.Errorf("create Windows default-associations policy directory: %w", err)
		}
		if err := os.WriteFile(destination, content, 0o644); err != nil {
			return result, fmt.Errorf("copy Windows default-associations policy XML: %w", err)
		}
		result.Operations = append(result.Operations, fmt.Sprintf("Copied policy XML to %s", destination))
	} else {
		result.Operations = append(result.Operations, "Using existing policy XML path: "+destination)
	}
	if _, err := runner.Run(
		ctx,
		"reg",
		"add",
		windowsDefaultAssociationsPolicyRegistryKey,
		"/v",
		windowsDefaultAssociationsPolicyRegistryValue,
		"/t",
		"REG_SZ",
		"/d",
		destination,
		"/f",
	); err != nil {
		return result, fmt.Errorf("configure Windows default-associations machine policy: %w", err)
	}
	result.Changed = true
	result.Operations = append(result.Operations, fmt.Sprintf("Configured %s/%s=%s", windowsDefaultAssociationsPolicyRegistryKey, windowsDefaultAssociationsPolicyRegistryValue, destination))
	if options.RefreshPolicy {
		if _, err := runner.LookPath("gpupdate"); err != nil {
			return result, fmt.Errorf("Windows policy was configured, but gpupdate is unavailable: %w", err)
		}
		if _, err := runner.Run(ctx, "gpupdate", "/target:computer", "/force"); err != nil {
			return result, fmt.Errorf("Windows policy was configured, but gpupdate failed: %w", err)
		}
		result.PolicyRefreshed = true
		result.Operations = append(result.Operations, "Ran gpupdate /target:computer /force")
	}
	result.Operations = append(result.Operations, "Windows applies default-association policy during policy processing; run gpupdate /target:computer /force and sign out/in for immediate rollout")
	return result, nil
}

type WindowsPolicyTemplateOptions struct {
	ProgID          string `json:"prog_id"`
	ApplicationName string `json:"application_name,omitempty"`
	CallbackScheme  string `json:"callback_scheme,omitempty"`
	Version         string `json:"version,omitempty"`
	Suggested       bool   `json:"suggested,omitempty"`
}

func WindowsBrowserPolicyXMLTemplate(progID, applicationName, callbackScheme string) (string, error) {
	return WindowsBrowserPolicyXMLTemplateWithOptions(WindowsPolicyTemplateOptions{
		ProgID:          progID,
		ApplicationName: applicationName,
		CallbackScheme:  callbackScheme,
	})
}

func WindowsBrowserPolicyXMLTemplateWithOptions(options WindowsPolicyTemplateOptions) (string, error) {
	progID := strings.TrimSpace(options.ProgID)
	if progID == "" {
		return "", fmt.Errorf("prog id is required")
	}
	applicationName := strings.TrimSpace(options.ApplicationName)
	if applicationName == "" {
		applicationName = progID
	}
	identifiers := []string{"http", "https", ".html", ".htm", ".xhtml", ".xht"}
	callback := NormalizeScheme(options.CallbackScheme)
	if callback != "" && !validURLScheme(callback) {
		return "", fmt.Errorf("invalid callback scheme %q", options.CallbackScheme)
	}
	if callback != "" && callback != "http" && callback != "https" {
		identifiers = append(identifiers, callback)
	}

	var builder strings.Builder
	builder.WriteString("<DefaultAssociations")
	if version := strings.TrimSpace(options.Version); version != "" {
		builder.WriteString(` Version="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(version))
		builder.WriteString(`"`)
	}
	builder.WriteString(">\n")
	for _, identifier := range identifiers {
		builder.WriteString(`  <Association Identifier="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(identifier))
		builder.WriteString(`" ProgId="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(progID))
		builder.WriteString(`" ApplicationName="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(applicationName))
		builder.WriteString(`"`)
		if options.Suggested {
			builder.WriteString(` Suggested="true"`)
		}
		builder.WriteString(` />`)
		builder.WriteByte('\n')
	}
	builder.WriteString("</DefaultAssociations>\n")
	return builder.String(), nil
}

func windowsDefaultAssociationsPolicyDefaultPath() string {
	return windowsPathJoin(windowsProgramDataDir(), "dfx", "DefaultAssociations.xml")
}

func windowsPolicyIdentifiersForTarget(target Target, callbackScheme string) ([]string, error) {
	target = target.Normalized()
	if err := target.Validate(); err != nil {
		return nil, err
	}
	identifiers := []string{}
	switch target.Kind {
	case KindBrowser:
		identifiers = append(identifiers, "http", "https", ".html", ".htm", ".xhtml", ".xht")
	case KindScheme:
		identifiers = append(identifiers, target.Value)
	case KindMIME:
		extensions := windowsPolicyMIMEExtensions(target.Value)
		if len(extensions) == 0 {
			return nil, fmt.Errorf("Windows policy XML requires file-extension mappings for MIME target %q", target.Value)
		}
		identifiers = append(identifiers, extensions...)
	case KindContentType:
		identifiers = append(identifiers, target.Value)
	default:
		return nil, fmt.Errorf("unsupported Windows policy target kind %q", target.Kind)
	}
	callback := NormalizeScheme(callbackScheme)
	if callback != "" {
		if !validURLScheme(callback) {
			return nil, fmt.Errorf("invalid callback scheme %q", callbackScheme)
		}
		if callback != "http" && callback != "https" {
			identifiers = append(identifiers, callback)
		}
	}
	return windowsPolicyUniqueIdentifiers(identifiers), nil
}

func windowsPolicyMIMEExtensions(mime string) []string {
	switch strings.TrimSpace(strings.ToLower(mime)) {
	case "text/html":
		return []string{".html", ".htm"}
	case "application/xhtml+xml":
		return []string{".xhtml", ".xht"}
	case "text/plain":
		return []string{".txt"}
	default:
		return nil
	}
}

func windowsPolicyUniqueIdentifiers(values []string) []string {
	seen := map[string]struct{}{}
	distinct := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(strings.ToLower(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		distinct = append(distinct, value)
	}
	return distinct
}

func mergeWindowsPolicyAssociations(records []WindowsPolicyAssociation, identifiers []string, progID, applicationName string, suggested bool) []WindowsPolicyAssociation {
	recordsByIdentifier := map[string]WindowsPolicyAssociation{}
	order := []string{}
	for _, record := range records {
		identifier := strings.TrimSpace(strings.ToLower(record.Identifier))
		if identifier == "" {
			continue
		}
		if _, ok := recordsByIdentifier[identifier]; !ok {
			order = append(order, identifier)
		}
		record.Identifier = identifier
		recordsByIdentifier[identifier] = record
	}
	for _, identifier := range identifiers {
		identifier = strings.TrimSpace(strings.ToLower(identifier))
		if identifier == "" {
			continue
		}
		if _, ok := recordsByIdentifier[identifier]; !ok {
			order = append(order, identifier)
		}
		recordsByIdentifier[identifier] = WindowsPolicyAssociation{
			Identifier:   identifier,
			ProgID:       progID,
			Application:  applicationName,
			SuggestedSet: suggested,
			Suggested:    suggested,
		}
	}
	sort.Strings(order)
	merged := make([]WindowsPolicyAssociation, 0, len(order))
	for _, identifier := range order {
		merged = append(merged, recordsByIdentifier[identifier])
	}
	return merged
}

func windowsPolicyXMLFromAssociations(records []WindowsPolicyAssociation) string {
	return windowsPolicyXMLFromAssociationsWithVersion(records, "")
}

func windowsPolicyXMLFromAssociationsWithVersion(records []WindowsPolicyAssociation, version string) string {
	var builder strings.Builder
	builder.WriteString("<DefaultAssociations")
	if version = strings.TrimSpace(version); version != "" {
		builder.WriteString(` Version="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(version))
		builder.WriteString(`"`)
	}
	builder.WriteString(">\n")
	for _, record := range records {
		identifier := strings.TrimSpace(strings.ToLower(record.Identifier))
		progID := strings.TrimSpace(record.ProgID)
		if identifier == "" || progID == "" {
			continue
		}
		applicationName := strings.TrimSpace(record.Application)
		if applicationName == "" {
			applicationName = progID
		}
		builder.WriteString(`  <Association Identifier="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(identifier))
		builder.WriteString(`" ProgId="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(progID))
		builder.WriteString(`" ApplicationName="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(applicationName))
		builder.WriteString(`"`)
		if record.SuggestedSet {
			builder.WriteString(` Suggested="`)
			if record.Suggested {
				builder.WriteString("true")
			} else {
				builder.WriteString("false")
			}
			builder.WriteString(`"`)
		}
		builder.WriteString(` />`)
		builder.WriteByte('\n')
	}
	builder.WriteString("</DefaultAssociations>\n")
	return builder.String()
}

func windowsPolicyTargetProgIDMap(records []WindowsPolicyAssociation) map[string]string {
	values := map[string]string{}
	for _, record := range records {
		progID := strings.TrimSpace(record.ProgID)
		if progID == "" {
			continue
		}
		for _, target := range MapWindowsPolicyIdentifierToTargets(record.Identifier) {
			target = strings.TrimSpace(strings.ToLower(target))
			if target == "" {
				continue
			}
			values[target] = progID
		}
	}
	return values
}

func windowsPolicyDiffTargets(desired, current map[string]string) []string {
	seen := map[string]struct{}{}
	targets := []string{}
	for target := range desired {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	for target := range current {
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func windowsDefaultAssociationPolicyRegistrySources() []windowsDefaultAssociationPolicyRegistrySource {
	return []windowsDefaultAssociationPolicyRegistrySource{
		{
			key:               windowsDefaultAssociationsPolicyRegistryKey,
			valueNames:        []string{windowsDefaultAssociationsPolicyRegistryValue},
			requireValueMatch: true,
		},
		{
			key:               `HKCU\Software\Policies\Microsoft\Windows\System`,
			valueNames:        []string{windowsDefaultAssociationsPolicyRegistryValue},
			requireValueMatch: true,
		},
		{
			key:               `HKCU\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`,
			valueNames:        []string{"Associations", "AssociationsFile", windowsDefaultAssociationsPolicyRegistryValue},
			requireValueMatch: false,
		},
		{
			key:               `HKLM\Software\Policies\Microsoft\Windows\System\DefaultAssociationsConfiguration`,
			valueNames:        []string{"Associations", "AssociationsFile", windowsDefaultAssociationsPolicyRegistryValue},
			requireValueMatch: false,
		},
	}
}

func windowsProgramDataDir() string {
	root := strings.TrimSpace(os.Getenv("ProgramData"))
	if root == "" {
		root = `C:\ProgramData`
	}
	return root
}

func windowsPathJoin(root string, parts ...string) string {
	root = strings.TrimRight(strings.TrimSpace(root), `\/`)
	if root == "" {
		return strings.Join(parts, `\`)
	}
	if len(parts) == 0 {
		return root
	}
	return root + `\` + strings.Join(parts, `\`)
}

func expandWindowsPolicyPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	raw = os.ExpandEnv(raw)
	var out strings.Builder
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
		if value, ok := lookupWindowsPolicyEnvCaseFold(name); ok {
			out.WriteString(value)
			i += end + 2
			continue
		}
		out.WriteString(raw[i : i+end+2])
		i += end + 2
	}
	return strings.TrimSpace(out.String())
}

func lookupWindowsPolicyEnvCaseFold(name string) (string, bool) {
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

func sameWindowsPolicyPath(left, right string) bool {
	left = strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(left), "/", `\`), `\`)
	right = strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(right), "/", `\`), `\`)
	return strings.EqualFold(left, right)
}

func windowsPolicyReadRegValues(ctx context.Context, runner commandRunner, key string) (map[string]string, error) {
	output, err := runner.Run(ctx, "reg", "query", key)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		parts := strings.Fields(strings.TrimSpace(line))
		if len(parts) < 3 {
			continue
		}
		if strings.EqualFold(parts[0], "HKEY_CURRENT_USER") || strings.EqualFold(parts[0], "HKEY_LOCAL_MACHINE") {
			continue
		}
		typeIndex := -1
		for i, part := range parts {
			if strings.HasPrefix(strings.ToUpper(part), "REG_") {
				typeIndex = i
				break
			}
		}
		if typeIndex <= 0 || typeIndex >= len(parts)-1 {
			continue
		}
		valueName := strings.TrimSpace(strings.Trim(strings.Join(parts[:typeIndex], " "), `"`))
		if strings.EqualFold(valueName, "(default)") || strings.EqualFold(valueName, "(Default)") {
			valueName = ""
		}
		values[valueName] = strings.Join(parts[typeIndex+1:], " ")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("no values found in %s", key)
	}
	return values, nil
}

func firstWindowsPolicyPathValue(raw string) string {
	raw = strings.TrimSpace(raw)
	for _, path := range strings.FieldsFunc(raw, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
		path = strings.TrimSpace(strings.Trim(path, `"`))
		if path != "" {
			return path
		}
	}
	return ""
}

func windowsPolicyStatusHealthy(result WindowsPolicyStatusResult) bool {
	if !result.Configured || len(result.Sources) == 0 {
		return false
	}
	for _, source := range result.Sources {
		if len(source.Issues) > 0 || !source.Readable || source.Validation == nil {
			return false
		}
		if !source.Validation.Valid || !source.Validation.Complete {
			return false
		}
	}
	return true
}

func parseWindowsPolicyXML(content []byte) ([]WindowsPolicyAssociation, []string) {
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return nil, []string{"policy XML is empty"}
	}
	records := make([]WindowsPolicyAssociation, 0, 16)
	issues := []string{}
	decoder := xml.NewDecoder(bytes.NewReader(content))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return records, dedupeSortedStrings(issues)
		}
		if err != nil {
			return records, dedupeSortedStrings(append(issues, "policy XML parse failed: "+err.Error()))
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "Association") {
			continue
		}
		association := struct {
			Identifier  string `xml:"Identifier,attr"`
			Suggested   string `xml:"Suggested,attr"`
			ProgID1     string `xml:"ProgId,attr"`
			ProgID2     string `xml:"ProgID,attr"`
			Application string `xml:"ApplicationName,attr"`
		}{}
		if err := decoder.DecodeElement(&association, &start); err != nil {
			return records, dedupeSortedStrings(append(issues, "policy XML parse failed: "+err.Error()))
		}
		identifier := strings.TrimSpace(strings.ToLower(association.Identifier))
		if identifier == "" {
			issues = append(issues, "association is missing Identifier")
			continue
		}
		progID := strings.TrimSpace(association.ProgID1)
		if progID == "" {
			progID = strings.TrimSpace(association.ProgID2)
		}
		if progID == "" {
			issues = append(issues, fmt.Sprintf("association %q is missing ProgId", identifier))
		}
		if !windowsPolicyIdentifierLooksValid(identifier) {
			issues = append(issues, fmt.Sprintf("association %q has invalid Identifier syntax", identifier))
		}
		suggestedSet, suggested := windowsPolicySuggestedValue(association.Suggested)
		records = append(records, WindowsPolicyAssociation{
			Identifier:   identifier,
			ProgID:       progID,
			Application:  strings.TrimSpace(association.Application),
			SuggestedSet: suggestedSet,
			Suggested:    suggested,
		})
	}
}

func windowsPolicyVersionFromXML(content []byte) string {
	content = bytes.TrimPrefix(content, []byte{0xEF, 0xBB, 0xBF})
	content = bytes.TrimSpace(content)
	if len(content) == 0 {
		return ""
	}
	decoder := xml.NewDecoder(bytes.NewReader(content))
	for {
		token, err := decoder.Token()
		if err != nil {
			return ""
		}
		start, ok := token.(xml.StartElement)
		if !ok || !strings.EqualFold(start.Name.Local, "DefaultAssociations") {
			continue
		}
		for _, attr := range start.Attr {
			if strings.EqualFold(attr.Name.Local, "Version") {
				return strings.TrimSpace(attr.Value)
			}
		}
		return ""
	}
}

func windowsPolicyRecordsSuggested(records []WindowsPolicyAssociation) bool {
	for _, record := range records {
		if record.SuggestedSet && record.Suggested {
			return true
		}
	}
	return false
}

func windowsPolicyRecordIssues(records []WindowsPolicyAssociation) []string {
	progIDsByTarget := map[string]map[string]struct{}{}
	for _, record := range records {
		progID := strings.TrimSpace(record.ProgID)
		if progID == "" {
			continue
		}
		for _, target := range MapWindowsPolicyIdentifierToTargets(record.Identifier) {
			if _, ok := progIDsByTarget[target]; !ok {
				progIDsByTarget[target] = map[string]struct{}{}
			}
			progIDsByTarget[target][progID] = struct{}{}
		}
	}
	issues := []string{}
	for target, progIDs := range progIDsByTarget {
		if len(progIDs) < 2 {
			continue
		}
		values := make([]string, 0, len(progIDs))
		for progID := range progIDs {
			values = append(values, progID)
		}
		sort.Strings(values)
		issues = append(issues, fmt.Sprintf("%s has conflicting ProgIds: %s", target, strings.Join(values, ", ")))
	}
	return dedupeSortedStrings(issues)
}

func windowsPolicyCoverage(required []string, records []WindowsPolicyAssociation) ([]string, bool) {
	requiredSet := map[string]struct{}{}
	configured := map[string]struct{}{}
	mandatory := false
	for _, target := range required {
		requiredSet[target] = struct{}{}
	}
	for _, record := range records {
		if strings.TrimSpace(record.ProgID) == "" {
			continue
		}
		for _, target := range MapWindowsPolicyIdentifierToTargets(record.Identifier) {
			configured[target] = struct{}{}
			if _, ok := requiredSet[target]; ok && (!record.SuggestedSet || !record.Suggested) {
				mandatory = true
			}
		}
	}
	missing := []string{}
	for _, target := range required {
		if _, ok := configured[target]; !ok {
			missing = append(missing, target)
		}
	}
	sort.Strings(missing)
	return missing, mandatory
}

func windowsPolicyIdentifierLooksValid(identifier string) bool {
	identifier = strings.TrimSpace(strings.ToLower(identifier))
	if identifier == "" {
		return false
	}
	if strings.HasPrefix(identifier, ".") {
		return len(identifier) > 1 && !strings.ContainsAny(identifier, " \t\r\n:/\\")
	}
	if strings.Contains(identifier, "/") {
		return validMIMEType(identifier)
	}
	return validURLScheme(identifier)
}

func MapWindowsPolicyIdentifierToTargets(identifier string) []string {
	identifier = strings.TrimSpace(strings.ToLower(identifier))
	if identifier == "" {
		return nil
	}
	if strings.HasPrefix(identifier, ".") {
		switch identifier {
		case ".html", ".htm":
			return []string{"text/html"}
		case ".xhtml", ".xht":
			return []string{"application/xhtml+xml"}
		default:
			return nil
		}
	}
	switch identifier {
	case "http", "https", "text/html", "application/xhtml+xml":
		return []string{identifier}
	default:
		if validURLScheme(identifier) {
			return []string{identifier}
		}
		return nil
	}
}

func windowsPolicySuggestedValue(raw string) (bool, bool) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return true, false
	default:
		return false, false
	}
}

func windowsPolicyXMLAttributeEscape(value string) string {
	replacer := strings.NewReplacer(
		`&`, `&amp;`,
		`<`, `&lt;`,
		`>`, `&gt;`,
		`"`, `&quot;`,
		`'`, `&apos;`,
	)
	return replacer.Replace(value)
}

func dedupeSortedStrings(values []string) []string {
	result := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
