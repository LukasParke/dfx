# Issue Matrix

Status legend:
- `todo`: not implemented
- `partial`: intentionally deferred / not implemented in this release
- `safe`: detection + remediation guidance + tests in place; actions are non-mutating
  by design (platform-native writes are intentionally disabled)
- `done`: detection + remediation + tests in place

For macOS and Windows, remediation is intentionally safe-only in this build; `safe`
means `set --dry-run` and `doctor --browser --fix --dry-run` emit explicit,
finding-specific guidance while direct native writes remain intentionally disabled
until a safe LaunchServices/UserChoice workflow is available. See the
[Remediation Guide](./remediation-guide.md) for the operator workflow.

## Linux

| ID | Issue | Detect | Remediate | Tests | Status |
|---|---|---|---|---|---|
| L01 | `http`/`https` differs from `text/html` | done | done | done | done |
| L02 | `xdg-mime` differs from portal/toolkit path | done | done | done | done |
| L03 | missing `application/xhtml+xml` | done | done | done | done |
| L04 | desktop-specific `mimeapps.list` precedence | done | done | done | done |
| L05 | stale desktop entry references | done | done | done | done |
| L06 | invalid desktop `Exec` URL placeholders | done | done | done | done |
| L07 | Flatpak portal mismatch | done | done | done | done |
| L08 | bad/missing portal backend | done | done | done | done |
| L09 | Wayland/X11 open path differences | done | done | done | done |
| L10 | `BROWSER` env fallback surprises | done | done | done | done |
| L11 | WM-only missing xdg components | done | done | done | done |
| L12 | AppImage registration missing | done | done | done | done |
| L13 | duplicate desktop IDs | done | done | done | done |
| L14 | Snap/Flatpak desktop shadowing | done | done | done | done |
| L15 | desktop DB not refreshed | done | done | done | done |
| L16 | stale MIME cache | done | done | done | done |
| L17 | undeclared MIME in desktop file | done | done | done | done |
| L18 | override removed but UI stale | done | done | done | done |
| L19 | Qt/KIO vs GIO disagreement | done | done | done | done |
| L20 | custom callback scheme missing | done | done | done | done |
| L21 | callback scheme assigned to browser | done | done | done | done |
| L22 | root-owned user config files | done | done | done | done |
| L23 | malformed `mimeapps.list` | done | done | done | done |
| L24 | bad `XDG_CURRENT_DESKTOP` context | done | done | done | done |
| L25 | browser self-prompt partial update | done | done | done | done |
| L26 | missing helper tools (`gio`, `xdg-settings`) | done | done | done | done |
| L27 | cross-desktop config conflicts | done | done | done | done |
| L28 | MIME sniff/extension mismatch | done | done | done | done |
| L29 | file manager cache lag | done | done | done | done |
| L30 | local vs portal file open differences | done | done | done | done |

## macOS

| ID | Issue | Detect | Remediate | Tests | Status |
|---|---|---|---|---|---|
| M01 | scheme and file defaults diverge | done | safe | done | safe |
| M02 | bundle ID typo/no-op | done | safe | done | safe |
| M03 | scheme claimed, callback unsupported | done | safe | done | safe |
| M04 | channel conflict (stable/beta/dev) | done | safe | done | safe |
| M05 | updates reclaim defaults | done | safe | done | safe |
| M06 | UTI inheritance mismatch | done | safe | done | safe |
| M07 | role mismatch viewer/editor | done | safe | done | safe |
| M08 | extension->UTI confusion | done | safe | done | safe |
| M09 | stale LS references after uninstall | done | safe | done | safe |
| M10 | delayed registration after install | done | safe | done | safe |
| M11 | sandbox path differences | done | safe | done | safe |
| M12 | MDM policy restrictions | done | safe | done | safe |
| M13 | browser prompt partial coverage | done | safe | done | safe |
| M14 | per-user vs system conflict | done | safe | done | safe |
| M15 | iCloud/provider path differences | done | safe | done | safe |
| M16 | Intel/ASI channel expectations | done | safe | done | safe |
| M17 | bad `CFBundleURLTypes` | done | safe | done | safe |
| M18 | bad `CFBundleDocumentTypes` | done | safe | done | safe |
| M19 | undocumented LS tools reliance | done | safe | done | safe |
| M20 | API drift across releases | done | safe | done | safe |
| M21 | terminal vs Finder open differences | done | safe | done | safe |
| M22 | headless/remote user domain mismatch | done | safe | done | safe |
| M23 | LS cache corruption | done | safe | done | safe |
| M24 | custom scheme collision | done | safe | done | safe |
| M25 | browser profile affects deep-link result | done | safe | done | safe |
| M26 | uninstalled app still selected | done | safe | done | safe |
| M27 | endpoint security URL interception | done | safe | done | safe |
| M28 | signing/notarization edge effects | done | safe | done | safe |
| M29 | conflicting UTI declarations | done | safe | done | safe |
| M30 | callback returns to browser loop | done | safe | done | safe |

## Windows

| ID | Issue | Detect | Remediate | Tests | Status |
|---|---|---|---|---|---|
| W01 | direct registry edit blocked by `UserChoice` | done | safe | done | safe |
| W02 | app capability set but not default | done | safe | done | safe |
| W03 | protocol vs extension split | done | safe | done | safe |
| W04 | browser change misses related protocols | done | safe | done | safe |
| W05 | per-user profile divergence | done | safe | done | safe |
| W06 | policy defaults overridden by user | done | safe | done | safe |
| W07 | invalid XML partial apply | done | safe | done | safe |
| W08 | XML missing new mappings | done | safe | done | safe |
| W09 | import applies only to new users | done | safe | done | safe |
| W10 | ProgID change on update | done | safe | done | safe |
| W11 | orphaned ProgID after uninstall | done | safe | done | safe |
| W12 | Store + desktop duplicate handlers | done | safe | done | safe |
| W13 | hash reset notifications | done | safe | done | safe |
| W14 | `assoc`/`ftype` limitations | done | safe | done | safe |
| W15 | wrong architecture/channel handler | done | safe | done | safe |
| W16 | hardening blocks UI/prompts | done | safe | done | safe |
| W17 | VDI/RemoteApp launch path differences | done | safe | done | safe |
| W18 | UWP/AppContainer activation differences | done | safe | done | safe |
| W19 | mapped extension but broken handler | done | safe | done | safe |
| W20 | URI launch constraints/special routing | done | safe | done | safe |
| W21 | `mailto` legacy vs modern conflicts | done | safe | done | safe |
| W22 | incomplete declared capabilities | done | safe | done | safe |
| W23 | stable/beta/dev race for defaults | done | safe | done | safe |
| W24 | icon/verb registry masking issues | done | safe | done | safe |
| W25 | chooser sets one extension only | done | safe | done | safe |
| W26 | mandatory policy blocks remediation | done | safe | done | safe |
| W27 | suggested policy re-applies | done | safe | done | safe |
| W28 | feature update resets defaults | done | safe | done | safe |
| W29 | browser repair tool policy conflict | done | safe | done | safe |
| W30 | missing OAuth callback protocol | done | safe | done | safe |
