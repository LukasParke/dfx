//go:build windows

package cli

import (
	"path/filepath"
	"testing"

	"github.com/LukasParke/dfx/internal/defaults"
)

func TestOpenTestFixturesWindows11Release(t *testing.T) {
	provider := defaults.CurrentProvider()
	bin := t.TempDir()
	installOpenTestFixtureFile(t, filepath.Join("windows", "reg.bat"), filepath.Join(bin, "reg.bat"), 0o755)
	prependOpenTestFixturePath(t, bin)

	scheme := runOpenTestJSON(t,
		provider,
		"--scheme", "HTTPS://example.test/callback",
		"--expected", "MSEdgeHTM",
	)
	assertOpenTestMatched(t, scheme, "MSEdgeHTM")

	mime := runOpenTestJSON(t,
		provider,
		"--mime", "text/html",
		"--expected", "MSEdgeHTML",
	)
	assertOpenTestMatched(t, mime, "MSEdgeHTML")

	xhtml := runOpenTestJSON(t,
		provider,
		"--mime", "application/xhtml+xml",
		"--expected", "MSEdgeXHTML",
	)
	assertOpenTestMatched(t, xhtml, "MSEdgeXHTML")

	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")
	callback := runOpenTestJSON(t,
		provider,
		"--callback",
		"--expected", "com.example.callback",
	)
	assertOpenTestMatched(t, callback, "com.example.callback")

	callbackMismatch := runOpenTestJSON(t,
		provider,
		"--callback",
		"--expected", "wrong.com.example.callback",
		"--launch",
	)
	assertOpenTestLaunchSkippedAfterMismatch(t, callbackMismatch)

	browser := runOpenTestJSON(t,
		provider,
		"--browser",
		"--expected", "MSEdgeHTM",
	)
	assertOpenTestMatched(t, browser, "MSEdgeHTM")

	browserMismatch := runOpenTestJSON(t,
		provider,
		"--browser",
		"--expected", "wrong.MSEdgeHTM",
		"--launch",
	)
	assertOpenTestLaunchSkippedAfterMismatch(t, browserMismatch)
}
