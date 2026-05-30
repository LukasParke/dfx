//go:build windows

package defaults

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

func AuditWindowsProgID(ctx context.Context, progID, callbackScheme string) (WindowsCapabilityAudit, error) {
	return auditWindowsProgID(ctx, windowsProvider{runner: execRunner{}}, progID, callbackScheme)
}

func auditWindowsProgID(ctx context.Context, provider windowsProvider, progID, callbackScheme string) (WindowsCapabilityAudit, error) {
	progID = strings.TrimSpace(progID)
	audit := WindowsCapabilityAudit{
		Platform: runtime.GOOS,
		ProgID:   progID,
	}
	if progID == "" {
		audit.Issues = []string{"prog id is required"}
		return audit, fmt.Errorf("prog id is required")
	}
	if !provider.regAvailable() {
		audit.Issues = []string{"reg.exe is unavailable; Windows registry capability audit cannot run"}
		return audit, fmt.Errorf("reg.exe is unavailable")
	}

	audit.HasRegistration = provider.hasAssocRegistration(ctx, progID)
	if !audit.HasRegistration {
		audit.Issues = append(audit.Issues, "ProgID is not registered under HKCU/HKLM Classes or Applications")
	}
	if ok, err := provider.readAssocCapabilities(ctx, progID); err != nil {
		audit.Issues = append(audit.Issues, "capabilities block missing: "+err.Error())
	} else {
		audit.HasCapabilities = ok
	}
	if command, err := provider.readAssocCommand(ctx, progID); err != nil {
		audit.Issues = append(audit.Issues, "open command missing: "+err.Error())
	} else {
		audit.Command = command
		if !windowsCommandHasURIPayloadPlaceholder(command) {
			audit.Issues = append(audit.Issues, "open command does not include a URI/file payload placeholder")
		}
	}
	if icon, err := provider.readAssocDefaultIcon(ctx, progID); err != nil {
		audit.Issues = append(audit.Issues, "default icon missing: "+err.Error())
	} else {
		audit.DefaultIcon = icon
	}

	for _, target := range WindowsBrowserCapabilityAuditTargets(callbackScheme) {
		target = target.Normalized()
		result := WindowsCapabilityTargetAudit{Target: target}
		declared, err := provider.assocDeclaresTargetCapability(ctx, progID, target)
		result.Declared = declared
		if err != nil {
			result.Error = err.Error()
			audit.Issues = append(audit.Issues, fmt.Sprintf("%s capability check failed: %v", target.String(), err))
		} else if !declared {
			audit.Issues = append(audit.Issues, fmt.Sprintf("%s capability is not declared by %s", target.String(), progID))
		}
		audit.Targets = append(audit.Targets, result)
	}

	audit.Issues = dedupeSortedStrings(audit.Issues)
	audit.Healthy = len(audit.Issues) == 0
	return audit, nil
}

func windowsCommandHasURIPayloadPlaceholder(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	for _, placeholder := range []string{`%1`, `%l`, `%u`, `%*`} {
		if strings.Contains(command, placeholder) {
			return true
		}
	}
	return false
}
