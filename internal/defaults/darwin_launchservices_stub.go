//go:build darwin && !cgo

package defaults

import "fmt"

func darwinNativeWritesAvailable() bool {
	return darwinHelperAvailable()
}

func darwinNativeSetURLSchemeHandler(scheme, bundleID string) error {
	if darwinHelperAvailable() {
		return darwinHelperSetURLScheme(scheme, bundleID)
	}
	return fmt.Errorf("native LaunchServices writes require cgo or embedded helper")
}

func darwinNativeSetContentTypeHandler(contentType, bundleID string) error {
	if darwinHelperAvailable() {
		return darwinHelperSetContentType(contentType, bundleID)
	}
	return fmt.Errorf("native LaunchServices writes require cgo or embedded helper")
}

func darwinNativeContentTypesForMIME(mime string) []string {
	return nil
}
