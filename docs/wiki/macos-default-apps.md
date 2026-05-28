# macOS Default Applications Reference

## Core Model

macOS defaults are managed by Launch Services and type systems based on UTI/UTType and URL schemes.

- URL scheme defaults: per-scheme handler bundle identifiers.
- Content type defaults: role handler for UTI/content type.
- User preference and system registration both affect resolution.

References:
- Launch Services: https://developer.apple.com/documentation/coreservices/launch_services
- Uniform Type Identifiers: https://developer.apple.com/documentation/uniformtypeidentifiers

## Association Axes

- Protocol handlers: `http`, `https`, custom schemes.
- File/content handlers: extensions mapped to UTIs, then UTIs mapped to apps by role.
- Role-specific handlers: viewer/editor/shell roles can differ.

References:
- `LSCopyDefaultHandlerForURLScheme`: https://developer.apple.com/documentation/coreservices/1441725-lscopydefaulthandlerforurlscheme
- `LSCopyDefaultRoleHandlerForContentType`: https://developer.apple.com/documentation/coreservices/1442793-lscopydefaultrolehandlerforconte

## Registration Inputs

- Application `Info.plist` contributes declared document and URL capabilities:
- `CFBundleDocumentTypes`
- `CFBundleURLTypes`

References:
- `CFBundleDocumentTypes`: https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundledocumenttypes
- `CFBundleURLTypes`: https://developer.apple.com/documentation/bundleresources/information_property_list/cfbundleurltypes

## Operational Constraints For dfx

- Some Launch Services APIs have deprecation notes, but they remain the published interface for many association tasks.
- Direct database manipulation is unsafe and not supported.
- Bundle ID correctness and app registration timing matter for deterministic results.

References:
- `LSSetDefaultHandlerForURLScheme`: https://developer.apple.com/documentation/coreservices/1447760-lssetdefaulthandlerforurlscheme
- `LSSetDefaultRoleHandlerForContentType`: https://developer.apple.com/documentation/coreservices/1440042-lssetdefaultrolehandlerforcontent

## Practical Verification Axes

- Current URL scheme handler by bundle id.
- Current content-role handler by UTI.
- Installed app declaration coverage (scheme + UTI + role).
- Post-install/post-update re-registration behavior.
