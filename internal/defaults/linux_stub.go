//go:build !linux

package defaults

func newLinuxProvider() Provider {
	return unsupportedProvider{platform: "linux", reason: "linux adapter is only available in linux builds"}
}
