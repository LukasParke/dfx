//go:build !windows

package defaults

func newWindowsProvider() Provider {
	return unsupportedProvider{platform: "windows", reason: "windows adapter is only available in windows builds"}
}
