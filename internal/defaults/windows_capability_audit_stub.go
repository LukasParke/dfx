//go:build !windows

package defaults

import (
	"context"
	"fmt"
	"runtime"
	"strings"
)

func AuditWindowsProgID(_ context.Context, progID, _ string) (WindowsCapabilityAudit, error) {
	progID = strings.TrimSpace(progID)
	audit := WindowsCapabilityAudit{
		Platform: runtime.GOOS,
		ProgID:   progID,
		Healthy:  false,
		Issues:   []string{"Windows ProgID capability audit requires a Windows host"},
	}
	if progID == "" {
		audit.Issues = []string{"prog id is required"}
		return audit, fmt.Errorf("prog id is required")
	}
	return audit, fmt.Errorf("windows ProgID capability audit requires a Windows host")
}
