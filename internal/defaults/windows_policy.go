package defaults

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

type WindowsPolicyAssociation struct {
	Identifier   string `json:"identifier"`
	ProgID       string `json:"prog_id,omitempty"`
	SuggestedSet bool   `json:"suggested_set,omitempty"`
	Suggested    bool   `json:"suggested,omitempty"`
}

type WindowsPolicyValidation struct {
	Valid     bool                       `json:"valid"`
	Complete  bool                       `json:"complete"`
	Mandatory bool                       `json:"mandatory"`
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

func WindowsBrowserPolicyXMLTemplate(progID, applicationName, callbackScheme string) (string, error) {
	progID = strings.TrimSpace(progID)
	if progID == "" {
		return "", fmt.Errorf("prog id is required")
	}
	applicationName = strings.TrimSpace(applicationName)
	if applicationName == "" {
		applicationName = progID
	}
	identifiers := []string{"http", "https", ".html", ".htm", ".xhtml", ".xht"}
	callback := NormalizeScheme(callbackScheme)
	if callback != "" && !validURLScheme(callback) {
		return "", fmt.Errorf("invalid callback scheme %q", callbackScheme)
	}
	if callback != "" && callback != "http" && callback != "https" {
		identifiers = append(identifiers, callback)
	}

	var builder strings.Builder
	builder.WriteString("<DefaultAssociations>\n")
	for _, identifier := range identifiers {
		builder.WriteString(`  <Association Identifier="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(identifier))
		builder.WriteString(`" ProgId="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(progID))
		builder.WriteString(`" ApplicationName="`)
		builder.WriteString(windowsPolicyXMLAttributeEscape(applicationName))
		builder.WriteString(`" />`)
		builder.WriteByte('\n')
	}
	builder.WriteString("</DefaultAssociations>\n")
	return builder.String(), nil
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
			Identifier string `xml:"Identifier,attr"`
			Suggested  string `xml:"Suggested,attr"`
			ProgID1    string `xml:"ProgId,attr"`
			ProgID2    string `xml:"ProgID,attr"`
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
			SuggestedSet: suggestedSet,
			Suggested:    suggested,
		})
	}
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
