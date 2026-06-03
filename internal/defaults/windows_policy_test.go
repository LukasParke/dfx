package defaults

import (
	"context"
	"strings"
	"testing"
)

func TestValidateWindowsPolicyXMLRequiresWebAndCallbackTargets(t *testing.T) {
	validation := ValidateWindowsPolicyXML([]byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier="https" ProgId="ChromeHTML" Suggested="true" />
  <Association Identifier=".html" ProgId="ChromeHTML" Suggested="true" />
</DefaultAssociations>`), "myapp://oauth/callback")
	if !validation.Valid || validation.Complete || strings.Join(validation.Missing, ",") != "application/xhtml+xml,myapp" {
		t.Fatalf("validation=%+v", validation)
	}
}

func TestValidateWindowsPolicyXMLReportsMalformedAndMandatoryPolicy(t *testing.T) {
	validation := ValidateWindowsPolicyXML([]byte(`<DefaultAssociations>
  <Association Identifier="https" ProgId="ChromeHTML" Suggested="false">
</DefaultAssociations>`), "")
	if validation.Valid || validation.Complete || len(validation.Issues) == 0 {
		t.Fatalf("validation=%+v", validation)
	}

	validation = ValidateWindowsPolicyXML([]byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" />
  <Association Identifier="https" ProgId="ChromeHTML" />
  <Association Identifier=".html" ProgId="ChromeHTML" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" />
</DefaultAssociations>`), "")
	if !validation.Valid || !validation.Complete || !validation.Mandatory {
		t.Fatalf("validation=%+v", validation)
	}
}

func TestValidateWindowsPolicyXMLDoesNotCountMissingProgIDAsCoverage(t *testing.T) {
	validation := ValidateWindowsPolicyXML([]byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" />
  <Association Identifier="https" ProgId="ChromeHTML" />
  <Association Identifier=".html" ProgId="ChromeHTML" />
  <Association Identifier=".xhtml" />
</DefaultAssociations>`), "")
	if validation.Valid || validation.Complete || strings.Join(validation.Missing, ",") != "application/xhtml+xml" {
		t.Fatalf("validation=%+v", validation)
	}
	if len(validation.Issues) != 1 || !strings.Contains(validation.Issues[0], "missing ProgId") {
		t.Fatalf("issues=%v", validation.Issues)
	}
}

func TestValidateWindowsPolicyXMLFlagsConflictingEquivalentTargets(t *testing.T) {
	validation := ValidateWindowsPolicyXML([]byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" />
  <Association Identifier="https" ProgId="ChromeHTML" />
  <Association Identifier=".html" ProgId="ChromeHTML" />
  <Association Identifier=".htm" ProgId="FirefoxHTML" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" />
</DefaultAssociations>`), "")
	if validation.Valid || !validation.Complete {
		t.Fatalf("validation=%+v", validation)
	}
	if len(validation.Issues) != 1 || !strings.Contains(validation.Issues[0], "text/html has conflicting ProgIds") {
		t.Fatalf("issues=%v", validation.Issues)
	}
}

func TestValidateWindowsPolicyXMLFlagsInvalidCallbackScheme(t *testing.T) {
	validation := ValidateWindowsPolicyXML([]byte(`<DefaultAssociations>
  <Association Identifier="http" ProgId="ChromeHTML" />
  <Association Identifier="https" ProgId="ChromeHTML" />
  <Association Identifier=".html" ProgId="ChromeHTML" />
  <Association Identifier=".xhtml" ProgId="ChromeHTML" />
</DefaultAssociations>`), "bad_scheme")
	if validation.Valid || !validation.Complete || len(validation.Issues) != 1 || !strings.Contains(validation.Issues[0], "invalid callback scheme") {
		t.Fatalf("validation=%+v", validation)
	}
}

func TestWindowsBrowserPolicyXMLTemplateEscapesAndIncludesCallback(t *testing.T) {
	template, err := WindowsBrowserPolicyXMLTemplate("ChromeHTML", `Chrome & "Beta"`, "myapp://oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<DefaultAssociations>`,
		`Identifier="http" ProgId="ChromeHTML"`,
		`Identifier=".htm" ProgId="ChromeHTML"`,
		`Identifier="myapp" ProgId="ChromeHTML"`,
		`ApplicationName="Chrome &amp; &quot;Beta&quot;"`,
	} {
		if !strings.Contains(template, want) {
			t.Fatalf("missing %q in template:\n%s", want, template)
		}
	}
}

func TestWindowsBrowserPolicyXMLTemplateRejectsInvalidCallback(t *testing.T) {
	if _, err := WindowsBrowserPolicyXMLTemplate("ChromeHTML", "Chrome", "bad_scheme"); err == nil {
		t.Fatal("expected invalid callback scheme error")
	}
}

func TestWindowsBrowserCapabilityAuditTargetsIncludeCallback(t *testing.T) {
	targets := WindowsBrowserCapabilityAuditTargets("myapp://oauth/callback")
	got := make([]string, 0, len(targets))
	for _, target := range targets {
		got = append(got, target.Normalized().String())
	}
	if strings.Join(got, ",") != "scheme:http,scheme:https,mime:text/html,mime:application/xhtml+xml,scheme:myapp" {
		t.Fatalf("targets=%v", got)
	}
}

func TestAuditWindowsProgIDRejectsMissingProgID(t *testing.T) {
	audit, err := AuditWindowsProgID(context.TODO(), "", "")
	if err == nil || audit.Healthy || len(audit.Issues) != 1 || !strings.Contains(audit.Issues[0], "prog id is required") {
		t.Fatalf("audit=%+v err=%v", audit, err)
	}
}
