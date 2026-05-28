# Issue Matrix

Status legend:
- `todo`: not implemented
- `partial`: detection or remediation exists, but incomplete
- `done`: detection + remediation + tests in place

## Linux

| ID | Issue | Detect | Remediate | Tests | Status |
|---|---|---|---|---|---|
| L01 | `http`/`https` differs from `text/html` | planned | planned | planned | partial |
| L02 | `xdg-mime` differs from portal/toolkit path | planned | planned | planned | todo |
| L03 | missing `application/xhtml+xml` | partial | partial | partial | partial |
| L04 | desktop-specific `mimeapps.list` precedence | partial | planned | partial | partial |
| L05 | stale desktop entry references | planned | planned | planned | todo |
| L06 | invalid desktop `Exec` URL placeholders | planned | planned | planned | todo |
| L07 | Flatpak portal mismatch | planned | planned | planned | todo |
| L08 | bad/missing portal backend | planned | planned | planned | todo |
| L09 | Wayland/X11 open path differences | planned | planned | planned | todo |
| L10 | `BROWSER` env fallback surprises | planned | planned | planned | todo |
| L11 | WM-only missing xdg components | partial | planned | planned | partial |
| L12 | AppImage registration missing | planned | planned | planned | todo |
| L13 | duplicate desktop IDs | planned | planned | planned | todo |
| L14 | Snap/Flatpak desktop shadowing | planned | planned | planned | todo |
| L15 | desktop DB not refreshed | planned | planned | planned | todo |
| L16 | stale MIME cache | planned | planned | planned | todo |
| L17 | undeclared MIME in desktop file | planned | planned | planned | todo |
| L18 | override removed but UI stale | planned | planned | planned | todo |
| L19 | Qt/KIO vs GIO disagreement | planned | planned | planned | todo |
| L20 | custom callback scheme missing | planned | planned | planned | todo |
| L21 | callback scheme assigned to browser | planned | planned | planned | todo |
| L22 | root-owned user config files | planned | planned | planned | todo |
| L23 | malformed `mimeapps.list` | planned | planned | planned | todo |
| L24 | bad `XDG_CURRENT_DESKTOP` context | planned | planned | planned | todo |
| L25 | browser self-prompt partial update | partial | partial | partial | partial |
| L26 | missing helper tools (`gio`, `xdg-settings`) | partial | partial | planned | partial |
| L27 | cross-desktop config conflicts | planned | planned | planned | todo |
| L28 | MIME sniff/extension mismatch | planned | planned | planned | todo |
| L29 | file manager cache lag | planned | planned | planned | todo |
| L30 | local vs portal file open differences | planned | planned | planned | todo |

## macOS

| ID | Issue | Detect | Remediate | Tests | Status |
|---|---|---|---|---|---|
| M01 | scheme and file defaults diverge | planned | planned | planned | todo |
| M02 | bundle ID typo/no-op | planned | planned | planned | todo |
| M03 | scheme claimed, callback unsupported | planned | planned | planned | todo |
| M04 | channel conflict (stable/beta/dev) | planned | planned | planned | todo |
| M05 | updates reclaim defaults | planned | planned | planned | todo |
| M06 | UTI inheritance mismatch | planned | planned | planned | todo |
| M07 | role mismatch viewer/editor | planned | planned | planned | todo |
| M08 | extension->UTI confusion | planned | planned | planned | todo |
| M09 | stale LS references after uninstall | planned | planned | planned | todo |
| M10 | delayed registration after install | planned | planned | planned | todo |
| M11 | sandbox path differences | planned | planned | planned | todo |
| M12 | MDM policy restrictions | planned | planned | planned | todo |
| M13 | browser prompt partial coverage | planned | planned | planned | todo |
| M14 | per-user vs system conflict | planned | planned | planned | todo |
| M15 | iCloud/provider path differences | planned | planned | planned | todo |
| M16 | Intel/ASI channel expectations | planned | planned | planned | todo |
| M17 | bad `CFBundleURLTypes` | planned | planned | planned | todo |
| M18 | bad `CFBundleDocumentTypes` | planned | planned | planned | todo |
| M19 | undocumented LS tools reliance | planned | planned | planned | todo |
| M20 | API drift across releases | planned | planned | planned | todo |
| M21 | terminal vs Finder open differences | planned | planned | planned | todo |
| M22 | headless/remote user domain mismatch | planned | planned | planned | todo |
| M23 | LS cache corruption | planned | planned | planned | todo |
| M24 | custom scheme collision | planned | planned | planned | todo |
| M25 | browser profile affects deep-link result | planned | planned | planned | todo |
| M26 | uninstalled app still selected | planned | planned | planned | todo |
| M27 | endpoint security URL interception | planned | planned | planned | todo |
| M28 | signing/notarization edge effects | planned | planned | planned | todo |
| M29 | conflicting UTI declarations | planned | planned | planned | todo |
| M30 | callback returns to browser loop | planned | planned | planned | todo |

## Windows

| ID | Issue | Detect | Remediate | Tests | Status |
|---|---|---|---|---|---|
| W01 | direct registry edit blocked by `UserChoice` | partial | planned | planned | partial |
| W02 | app capability set but not default | planned | planned | planned | todo |
| W03 | protocol vs extension split | planned | planned | planned | todo |
| W04 | browser change misses related protocols | planned | planned | planned | todo |
| W05 | per-user profile divergence | planned | planned | planned | todo |
| W06 | policy defaults overridden by user | planned | planned | planned | todo |
| W07 | invalid XML partial apply | planned | planned | planned | todo |
| W08 | XML missing new mappings | planned | planned | planned | todo |
| W09 | import applies only to new users | planned | planned | planned | todo |
| W10 | ProgID change on update | planned | planned | planned | todo |
| W11 | orphaned ProgID after uninstall | planned | planned | planned | todo |
| W12 | Store + desktop duplicate handlers | planned | planned | planned | todo |
| W13 | hash reset notifications | planned | planned | planned | todo |
| W14 | `assoc`/`ftype` limitations | planned | planned | planned | todo |
| W15 | wrong architecture/channel handler | planned | planned | planned | todo |
| W16 | hardening blocks UI/prompts | planned | planned | planned | todo |
| W17 | VDI/RemoteApp launch path differences | planned | planned | planned | todo |
| W18 | UWP/AppContainer activation differences | planned | planned | planned | todo |
| W19 | mapped extension but broken handler | planned | planned | planned | todo |
| W20 | URI launch constraints/special routing | planned | planned | planned | todo |
| W21 | `mailto` legacy vs modern conflicts | planned | planned | planned | todo |
| W22 | incomplete declared capabilities | planned | planned | planned | todo |
| W23 | stable/beta/dev race for defaults | planned | planned | planned | todo |
| W24 | icon/verb registry masking issues | planned | planned | planned | todo |
| W25 | chooser sets one extension only | planned | planned | planned | todo |
| W26 | mandatory policy blocks remediation | planned | planned | planned | todo |
| W27 | suggested policy re-applies | planned | planned | planned | todo |
| W28 | feature update resets defaults | planned | planned | planned | todo |
| W29 | browser repair tool policy conflict | planned | planned | planned | todo |
| W30 | missing OAuth callback protocol | planned | planned | planned | todo |

