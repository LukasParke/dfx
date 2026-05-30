//go:build darwin

package cli

import (
	"path/filepath"
	"testing"

	"github.com/LukasParke/dfx/internal/defaults"
)

func TestOpenTestFixturesDarwinRecentRelease(t *testing.T) {
	provider := defaults.CurrentProvider()
	home := t.TempDir()
	launchServicesPlist := filepath.Join(
		home,
		"Library",
		"Preferences",
		"com.apple.LaunchServices",
		"com.apple.launchservices.secure.plist",
	)
	installOpenTestFixtureFile(t, filepath.Join("darwin", "handlers.json"), launchServicesPlist, 0o644)

	bin := t.TempDir()
	installOpenTestFixtureFile(t, filepath.Join("darwin", "plutil"), filepath.Join(bin, "plutil"), 0o755)
	prependOpenTestFixturePath(t, bin)
	t.Setenv("HOME", home)

	browser := runOpenTestJSON(t,
		provider,
		"--browser",
		"--expected", "com.example.browser",
	)
	assertOpenTestMatched(t, browser, "com.example.browser")

	browserMismatch := runOpenTestJSON(t,
		provider,
		"--browser",
		"--expected", "wrong.com.example.browser",
		"--launch",
	)
	assertOpenTestLaunchSkippedAfterMismatch(t, browserMismatch)

	scheme := runOpenTestJSON(t,
		provider,
		"--scheme", "HTTPS://example.test/callback",
		"--expected", "com.example.browser",
	)
	assertOpenTestMatched(t, scheme, "com.example.browser")

	mime := runOpenTestJSON(t,
		provider,
		"--mime", "application/xhtml+xml",
		"--expected", "com.example.browser.xhtml",
	)
	assertOpenTestMatched(t, mime, "com.example.browser.xhtml")

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
}

func TestOpenTestFixturesDarwinDuplicateHandlerOrder(t *testing.T) {
	provider := defaults.CurrentProvider()
	home := t.TempDir()
	launchServicesPlist := filepath.Join(
		home,
		"Library",
		"Preferences",
		"com.apple.LaunchServices",
		"com.apple.launchservices.secure.plist",
	)
	installOpenTestFixtureFile(t, filepath.Join("darwin", "handlers-duplicate.json"), launchServicesPlist, 0o644)

	bin := t.TempDir()
	installOpenTestFixtureFile(t, filepath.Join("darwin", "plutil"), filepath.Join(bin, "plutil"), 0o755)
	prependOpenTestFixturePath(t, bin)
	t.Setenv("HOME", home)

	scheme := runOpenTestJSON(t,
		provider,
		"--scheme", "HTTPS://example.test/callback",
		"--expected", "com.example.legacy.browser",
	)
	assertOpenTestMatched(t, scheme, "com.example.legacy.browser")

	mime := runOpenTestJSON(t,
		provider,
		"--mime", "text/html",
		"--expected", "com.example.browser",
	)
	assertOpenTestMatched(t, mime, "com.example.browser")
}
