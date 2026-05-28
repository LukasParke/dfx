package cli

import "os"

func writeTestProfile(path string) error {
	return os.WriteFile(path, []byte(`{
  "defaults": [
    { "kind": "mime", "value": "text/html", "app": "firefox.desktop" },
    { "kind": "scheme", "value": "https", "app": "firefox.desktop" }
  ]
}`), 0o600)
}
