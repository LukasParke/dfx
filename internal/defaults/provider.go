package defaults

import "runtime"

func CurrentProvider() Provider {
	switch runtime.GOOS {
	case "linux":
		return newLinuxProvider()
	case "darwin":
		return newDarwinProvider()
	case "windows":
		return newWindowsProvider()
	default:
		return unsupportedProvider{platform: runtime.GOOS, reason: "platform adapter is not implemented"}
	}
}
