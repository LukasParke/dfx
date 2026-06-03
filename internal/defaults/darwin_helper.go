//go:build darwin

package defaults

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// darwinHelperAvailable reports whether the embedded LaunchServices helper
// can be extracted and executed. The helper binary is built separately for
// amd64 and arm64 and embedded via //go:embed when available.
func darwinHelperAvailable() bool {
	// When embedded binaries are present, this checks extraction feasibility.
	// Currently returns false until pre-built helpers are embedded.
	return false
}

// darwinHelperSetURLScheme uses the embedded helper to set a URL scheme handler.
func darwinHelperSetURLScheme(scheme, bundleID string) error {
	return darwinRunHelper("set-scheme", scheme, bundleID)
}

// darwinHelperSetContentType uses the embedded helper to set a content-type handler.
func darwinHelperSetContentType(contentType, bundleID string) error {
	return darwinRunHelper("set-content-type", contentType, bundleID)
}

// darwinRunHelper extracts the embedded helper for the current architecture
// to a temporary directory, executes it, and cleans up.
func darwinRunHelper(args ...string) error {
	// Placeholder: when embedded binaries are available, this will:
	// 1. Select the correct binary for runtime.GOARCH
	// 2. Extract to os.TempDir()
	// 3. os.Chmod(0o755)
	// 4. exec.Command(helperPath, args...).Run()
	// 5. os.Remove(helperPath)
	return fmt.Errorf("embedded LaunchServices helper is not yet available for %s", runtime.GOARCH)
}

// darwinAppleScriptSetURLScheme attempts to set a URL scheme handler via
// osascript / System Events. This requires Accessibility permissions and is
// slower than native LaunchServices calls, but works without CGO or helper
// binaries.
func darwinAppleScriptSetURLScheme(scheme, bundleID string) error {
	script := fmt.Sprintf(`
tell application "System Events"
	set default application of URL scheme "%s" to "%s"
end tell
`, scheme, bundleID)
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("osascript set scheme %s: %w (output: %s)", scheme, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// darwinAppleScriptSetContentType attempts to set a content-type handler via
// osascript. Note: System Events does not expose direct UTI handler APIs, so
// this emits a guidance error. Users should use System Settings or install duti.
func darwinAppleScriptSetContentType(contentType, bundleID string) error {
	return fmt.Errorf("osascript cannot directly set UTI handlers for %s; use System Settings or install duti (`brew install duti`)", contentType)
}

// darwinHelperPath returns the path where an extracted helper would live.
func darwinHelperPath() string {
	return filepath.Join(os.TempDir(), "dfx-launchservices-helper")
}
