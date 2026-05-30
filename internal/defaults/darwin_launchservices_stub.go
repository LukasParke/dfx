//go:build darwin && !cgo

package defaults

import "fmt"

func darwinNativeWritesAvailable() bool {
	return false
}

func darwinNativeSetURLSchemeHandler(string, string) error {
	return fmt.Errorf("native LaunchServices writes require cgo")
}

func darwinNativeSetContentTypeHandler(string, string) error {
	return fmt.Errorf("native LaunchServices writes require cgo")
}

func darwinNativeContentTypesForMIME(string) []string {
	return nil
}
