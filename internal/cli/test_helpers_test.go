package cli

import "os"

func writeTestProfile(path string) error {
	return os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "mime", "value": "Text/HTML", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "https://example.test/path", "app": " firefox.desktop " }
  ]
}`), 0o600)
}
