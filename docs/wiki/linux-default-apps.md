# Linux Default Applications Reference

## Core Model

Linux desktop defaults are specified by Freedesktop standards and then interpreted by desktop environments and launch tools.

- Associations are MIME-centric via `mimeapps.list`.
- URL schemes are represented as pseudo-MIME entries like `x-scheme-handler/https`.
- Resolution depends on file precedence and desktop-specific overrides.
- Tools (`xdg-open`, `xdg-mime`, `gio`, portals) can observe or mutate overlapping but not always identical views.

Primary references:
- MIME Apps spec: https://specifications.freedesktop.org/mime-apps-spec/latest/
- Desktop Entry spec: https://specifications.freedesktop.org/desktop-entry-spec/latest/
- Shared MIME-info spec: https://specifications.freedesktop.org/shared-mime-info-spec/latest/

## Resolution Layers

1. MIME detection from shared MIME database.
2. Candidate applications from desktop entries (`MimeType=`).
3. Default lookup from `mimeapps.list` precedence rules.
4. Desktop-/session-specific behavior in launchers and portal backends.

Reference:
- File lookup and precedence: https://specifications.freedesktop.org/mime-apps-spec/latest/file.html

## Common Data Locations

- User config: `~/.config/mimeapps.list`
- User data fallback: `~/.local/share/applications/mimeapps.list`
- System config: `/etc/xdg/mimeapps.list`
- Desktop-specific system overrides: e.g. `/etc/xdg/xfce-mimeapps.list`
- System application entries: `/usr/share/applications/*.desktop`

Reference:
- ArchWiki XDG MIME Applications: https://wiki.archlinux.org/title/XDG_MIME_Applications

## Key Launch Paths

- `xdg-open` (generic launcher)
- `gio open` / `gio mime` (GLib/GIO path)
- Toolkit/direct environment openers (Qt/KIO, GNOME/GIO)
- XDG Desktop Portal OpenURI for sandboxed apps or Wayland-heavy flows

References:
- `xdg-open`: https://man.archlinux.org/man/xdg-open.1.en
- OpenURI portal: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.OpenURI.html

## Desktop Environment Considerations

- GNOME: Settings and GIO tooling may write/interpret defaults differently than CLI-only workflows.
- KDE: file association ordering and default app modules add user-level behavior over base spec.
- Non-DE WMs (Hyprland/Sway/i3): behavior is often determined by installed portal backend + xdg-utils + toolkit stack.

References:
- GNOME admin guide: https://help.gnome.org/admin/system-admin-guide/stable/mime-types-application.html.en
- KDE file associations: https://docs.kde.org/stable5/en/kde-cli-tools/kcontrol5/filetypes/

## Sandboxed App Behavior

- Flatpak apps frequently use portals for URI/file opens.
- Host default associations are still relevant, but the portal backend and permissions can alter observed behavior.
- Missing or mismatched portal backends are a major source of “opens wrong app” reports.

References:
- Portal API reference: https://flatpak.github.io/xdg-desktop-portal/docs/api-reference.html
- Flatpak portal docs: https://docs.flatpak.org/en/latest/portal-api-reference.html
