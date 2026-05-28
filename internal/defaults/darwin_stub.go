//go:build !darwin

package defaults

func newDarwinProvider() Provider {
	return unsupportedProvider{platform: "darwin", reason: "darwin adapter is only available in darwin builds"}
}
