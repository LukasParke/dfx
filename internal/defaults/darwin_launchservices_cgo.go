//go:build darwin && cgo

package defaults

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <CoreServices/CoreServices.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

static OSStatus dfxLSSetURLScheme(const char *scheme, const char *bundleID) {
	CFStringRef schemeRef = CFStringCreateWithCString(kCFAllocatorDefault, scheme, kCFStringEncodingUTF8);
	CFStringRef bundleRef = CFStringCreateWithCString(kCFAllocatorDefault, bundleID, kCFStringEncodingUTF8);
	if (schemeRef == NULL || bundleRef == NULL) {
		if (schemeRef != NULL) {
			CFRelease(schemeRef);
		}
		if (bundleRef != NULL) {
			CFRelease(bundleRef);
		}
		return -50;
	}
	OSStatus status = LSSetDefaultHandlerForURLScheme(schemeRef, bundleRef);
	CFRelease(schemeRef);
	CFRelease(bundleRef);
	return status;
}

static OSStatus dfxLSSetContentType(const char *contentType, const char *bundleID) {
	CFStringRef contentTypeRef = CFStringCreateWithCString(kCFAllocatorDefault, contentType, kCFStringEncodingUTF8);
	CFStringRef bundleRef = CFStringCreateWithCString(kCFAllocatorDefault, bundleID, kCFStringEncodingUTF8);
	if (contentTypeRef == NULL || bundleRef == NULL) {
		if (contentTypeRef != NULL) {
			CFRelease(contentTypeRef);
		}
		if (bundleRef != NULL) {
			CFRelease(bundleRef);
		}
		return -50;
	}
	OSStatus status = LSSetDefaultRoleHandlerForContentType(contentTypeRef, kLSRolesAll, bundleRef);
	CFRelease(contentTypeRef);
	CFRelease(bundleRef);
	return status;
}

static char *dfxCopyCString(CFStringRef value) {
	CFIndex length = CFStringGetLength(value);
	CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
	char *buffer = (char *)malloc(maxSize);
	if (buffer == NULL) {
		return NULL;
	}
	if (!CFStringGetCString(value, buffer, maxSize, kCFStringEncodingUTF8)) {
		free(buffer);
		return NULL;
	}
	return buffer;
}

static char *dfxCopyPreferredUTIForMIME(const char *mime) {
	CFStringRef mimeRef = CFStringCreateWithCString(kCFAllocatorDefault, mime, kCFStringEncodingUTF8);
	if (mimeRef == NULL) {
		return NULL;
	}
	CFStringRef utiRef = UTTypeCreatePreferredIdentifierForTag(kUTTagClassMIMEType, mimeRef, NULL);
	CFRelease(mimeRef);
	if (utiRef == NULL) {
		return NULL;
	}
	char *out = dfxCopyCString(utiRef);
	CFRelease(utiRef);
	return out;
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

func darwinNativeWritesAvailable() bool {
	return true
}

func darwinNativeSetURLSchemeHandler(scheme, bundleID string) error {
	scheme = strings.TrimSpace(scheme)
	bundleID = strings.TrimSpace(bundleID)
	if scheme == "" || bundleID == "" {
		return fmt.Errorf("scheme and bundle identifier are required")
	}
	cScheme := C.CString(scheme)
	defer C.free(unsafe.Pointer(cScheme))
	cBundleID := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cBundleID))
	if status := C.dfxLSSetURLScheme(cScheme, cBundleID); status != 0 {
		return fmt.Errorf("LaunchServices returned OSStatus %d", int(status))
	}
	return nil
}

func darwinNativeSetContentTypeHandler(contentType, bundleID string) error {
	contentType = strings.TrimSpace(contentType)
	bundleID = strings.TrimSpace(bundleID)
	if contentType == "" || bundleID == "" {
		return fmt.Errorf("content type and bundle identifier are required")
	}
	cContentType := C.CString(contentType)
	defer C.free(unsafe.Pointer(cContentType))
	cBundleID := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cBundleID))
	if status := C.dfxLSSetContentType(cContentType, cBundleID); status != 0 {
		return fmt.Errorf("LaunchServices returned OSStatus %d", int(status))
	}
	return nil
}

func darwinNativeContentTypesForMIME(mime string) []string {
	mime = strings.TrimSpace(strings.ToLower(mime))
	if mime == "" || !strings.Contains(mime, "/") {
		return nil
	}
	cMIME := C.CString(mime)
	defer C.free(unsafe.Pointer(cMIME))
	cUTI := C.dfxCopyPreferredUTIForMIME(cMIME)
	if cUTI == nil {
		return nil
	}
	defer C.free(unsafe.Pointer(cUTI))
	return []string{C.GoString(cUTI)}
}
