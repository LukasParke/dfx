//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LukasParke/dfx/internal/defaults"
)

func TestOpenTestFixturesLinuxDesktopProfiles(t *testing.T) {
	provider := defaults.CurrentProvider()
	cases := []struct {
		name        string
		desktop     string
		schemeApp   string
		mimeApp     string
		callbackApp string
	}{
		{
			name:        "gnome",
			desktop:     "GNOME",
			schemeApp:   "org.gnome.firefox.desktop",
			mimeApp:     "org.gnome.firefox.xhtml.desktop",
			callbackApp: "org.gnome.oauth.desktop",
		},
		{
			name:        "kde",
			desktop:     "KDE",
			schemeApp:   "org.kde.falkon.desktop",
			mimeApp:     "org.kde.falkon.desktop",
			callbackApp: "org.kde.oauth.desktop",
		},
		{
			name:        "wm-only",
			desktop:     "",
			schemeApp:   "com.wm.custombrowser.desktop",
			mimeApp:     "com.wm.custombrowser.desktop",
			callbackApp: "com.wm.oauth.desktop",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			configHome := filepath.Join(home, ".config")
			dataHome := filepath.Join(home, ".local", "share")
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", configHome)
			t.Setenv("XDG_DATA_HOME", dataHome)
			t.Setenv("XDG_CONFIG_DIRS", filepath.Join(home, "xdg-config"))
			t.Setenv("XDG_DATA_DIRS", filepath.Join(home, "xdg-data"))
			t.Setenv("XDG_CURRENT_DESKTOP", tc.desktop)
			t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")

			listFile := "mimeapps.list"
			if strings.TrimSpace(tc.desktop) != "" {
				listFile = strings.ToLower(tc.desktop) + "-mimeapps.list"
			}
			installOpenTestFixtureFile(t, filepath.Join("linux", tc.name, "mimeapps.list"), filepath.Join(configHome, listFile), 0o644)

			scheme := runOpenTestJSON(t, provider,
				"--scheme", "HTTPS://example.test/callback",
				"--expected", tc.schemeApp,
			)
			assertOpenTestMatched(t, scheme, tc.schemeApp)

			mime := runOpenTestJSON(t, provider,
				"--mime", "application/xhtml+xml",
				"--expected", tc.mimeApp,
			)
			assertOpenTestMatched(t, mime, tc.mimeApp)

			browser := runOpenTestJSON(t, provider,
				"--browser",
				"--expected", tc.schemeApp,
			)
			assertOpenTestMatched(t, browser, tc.schemeApp)

			browserMismatch := runOpenTestJSON(t,
				provider,
				"--browser",
				"--expected", "wrong."+tc.schemeApp,
				"--launch",
			)
			assertOpenTestLaunchSkippedAfterMismatch(t, browserMismatch)

			callback := runOpenTestJSON(t, provider,
				"--callback",
				"--expected", tc.callbackApp,
			)
			assertOpenTestMatched(t, callback, tc.callbackApp)

			callbackMismatch := runOpenTestJSON(t,
				provider,
				"--callback",
				"--expected", "wrong."+tc.callbackApp,
				"--launch",
			)
			assertOpenTestLaunchSkippedAfterMismatch(t, callbackMismatch)
		})
	}
}

func TestOpenTestFixturesLinuxTransitionAndDuplicateHandlers(t *testing.T) {
	provider := defaults.CurrentProvider()
	home := t.TempDir()
	configHome := filepath.Join(home, ".config")
	dataHome := filepath.Join(home, ".local", "share")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(home, "xdg-config"))
	t.Setenv("XDG_DATA_DIRS", filepath.Join(home, "xdg-data"))
	t.Setenv("DFX_CALLBACK_SCHEME", "myapp://oauth/callback")

	t.Run("mixed-desktop-transition-uses-desktop-token-priority", func(t *testing.T) {
		t.Setenv("XDG_CURRENT_DESKTOP", "GNOME:KDE")
		installOpenTestFixtureFile(t, filepath.Join("linux", "gnome", "mimeapps.list"), filepath.Join(configHome, "gnome-mimeapps.list"), 0o644)
		installOpenTestFixtureFile(t, filepath.Join("linux", "kde", "mimeapps.list"), filepath.Join(configHome, "kde-mimeapps.list"), 0o644)

		scheme := runOpenTestJSON(t, provider,
			"--scheme", "HTTPS://example.test/callback",
			"--expected", "org.gnome.firefox.desktop",
		)
		assertOpenTestMatched(t, scheme, "org.gnome.firefox.desktop")
	})

	t.Run("fallback-to-mimeapps-list-when-desktop-specific-missing", func(t *testing.T) {
		t.Setenv("XDG_CURRENT_DESKTOP", "MYSTERY")
		if err := os.WriteFile(filepath.Join(configHome, "mimeapps.list"), []byte(`[Default Applications]
x-scheme-handler/http=org.wm.custombrowser.desktop
x-scheme-handler/https=org.wm.custombrowser.desktop
text/html=org.wm.custombrowser.desktop
application/xhtml+xml=org.wm.custombrowser.desktop
x-scheme-handler/myapp=org.wm.oauth.desktop
`), 0o644); err != nil {
			t.Fatalf("write fallback fixture: %v", err)
		}

		scheme := runOpenTestJSON(t, provider,
			"--scheme", "https://example.test/callback",
			"--expected", "org.wm.custombrowser.desktop",
		)
		assertOpenTestMatched(t, scheme, "org.wm.custombrowser.desktop")
	})

	t.Run("duplicate-handler-list-picks-first-app", func(t *testing.T) {
		t.Setenv("XDG_CURRENT_DESKTOP", "")
		if err := os.WriteFile(filepath.Join(configHome, "mimeapps.list"), []byte(`[Default Applications]
x-scheme-handler/http=com.duplicate.first.desktop;com.duplicate.second.desktop
x-scheme-handler/https=com.duplicate.first.desktop;com.duplicate.second.desktop
text/html=com.duplicate.first.desktop
application/xhtml+xml=com.duplicate.first.desktop
x-scheme-handler/myapp=com.duplicate.callback.desktop
`), 0o644); err != nil {
			t.Fatalf("write duplicate fixture: %v", err)
		}

		scheme := runOpenTestJSON(t, provider,
			"--scheme", "https://example.test/callback",
			"--expected", "com.duplicate.first.desktop",
		)
		assertOpenTestMatched(t, scheme, "com.duplicate.first.desktop")
	})
}
