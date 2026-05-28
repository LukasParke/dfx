# Windows Default Applications Reference

## Core Model

Windows default apps are based on registered capabilities plus protected user choice assignment for file types and protocols.

- App registration advertises supported file extensions, MIME types, and protocols.
- User-selected defaults are protected and not intended for silent arbitrary rewrites.
- Enterprise policy can pre-stage or suggest defaults via XML/CSP paths.

References:
- Default Programs (Win32): https://learn.microsoft.com/en-us/windows/win32/shell/default-programs
- File type/URI model: https://learn.microsoft.com/en-us/windows/compatibility/file-type-and-protocol-associations-model

## Critical Concepts

- `ProgID` and capability registration determine candidate handlers.
- `UserChoice` protections make direct registry forcing brittle and unsupported.
- Modern flows prefer Settings UI, app-driven prompts, or managed policy.

References:
- Default apps platform: https://learn.microsoft.com/en-us/windows/apps/develop/windows-integration/default-apps-platform
- User support path: https://support.microsoft.com/windows/e5d82cad-17d1-c53b-3505-f10a32e1894d

## Policy and Fleet Paths

- Export defaults to XML with DISM.
- Import defaults in image provisioning or through policy.
- MDM policy (`ApplicationDefaults` CSP) supports managed assignment behavior.

References:
- DISM XML import/export: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/export-or-import-default-application-associations?view=windows-11
- Policy CSP: https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-applicationdefaults

## Launch Behavior Notes

- URI launch path can be platform-specific (`LaunchUriAsync`, Shell execution, protocol activation).
- Some system URIs can intentionally bypass user browser defaults (for platform reasons).

Reference:
- Launch default app for URI: https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-default-app

## Operational Constraints For dfx

- `dfx` should not promise unsupported forced changes to protected defaults.
- Verification should distinguish:
- Declared capabilities
- Current user defaults
- Policy-enforced defaults
- Fallback behavior when no valid handler is present
