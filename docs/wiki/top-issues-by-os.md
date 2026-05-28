# Top 30 Issues Per OS

These are the most common default-app failure patterns `dfx` should explicitly model and test.

## Linux: 30 Common Issues

1. `http`/`https` scheme defaults differ from `text/html` defaults.
2. `xdg-mime` shows expected default but app opens via another stack (`gio`/portal/toolkit).
3. Missing `application/xhtml+xml` association causes browser mismatch.
4. Desktop-specific `mimeapps.list` overrides unexpectedly win over generic files.
5. Stale `mimeapps.list` entries reference removed `.desktop` files.
6. `.desktop` file exists but missing valid `Exec` URL placeholders (`%u`/`%U`).
7. Flatpak app sees different behavior via portal backend than host CLI checks.
8. Missing or wrong `xdg-desktop-portal-*` backend causes bad URI handling.
9. Wayland session behavior differs from X11 due to portal path usage.
10. `xdg-open` falls back to `BROWSER` env path unexpectedly.
11. WM-only setups lack components expected by `xdg-utils`.
12. AppImage entries are not registered persistently in application dirs.
13. Duplicate desktop IDs across package sources create nondeterministic picks.
14. Snap/Flatpak exported desktop entries shadow native package desktop files.
15. `update-desktop-database` not run after manual desktop file changes.
16. MIME cache stale vs desktop entry reality.
17. Desktop file `MimeType=` does not declare needed type despite actual support.
18. User override removes associations but UI still displays old candidates.
19. Toolkit-specific openers (Qt/KIO vs GIO) disagree in edge cases.
20. Custom URL scheme not registered (`x-scheme-handler/...`) for OAuth callback.
21. OAuth callback scheme registered to browser instead of desktop client.
22. Root-created config files in user paths block user-level writes.
23. Non-ASCII or malformed `mimeapps.list` breaks parser behavior.
24. Session environment (`XDG_CURRENT_DESKTOP`) inconsistent with expected backend.
25. Browser self-prompt updates only one layer, leaving others stale.
26. Minimal distros omit helper commands (`xdg-settings`, `gio`) by default.
27. Cross-desktop migrations leave conflicting config files in multiple locations.
28. MIME sniffing result differs from extension expectation.
29. File managers cache associations and lag behind CLI updates.
30. Association works for local files but not for remote/document-portal files.

## macOS: 30 Common Issues

1. URL scheme default set, but file type default unchanged (and vice versa).
2. Bundle identifier typo leads to silent no-op or fallback behavior.
3. App claims scheme but not actually prepared to handle real callback payloads.
4. Multiple browser channels (stable/beta/dev) compete for same scheme.
5. App updates re-register handlers and unexpectedly reclaim defaults.
6. UTI inheritance confusion leads to wrong app for subtype content.
7. Role-specific defaults (viewer/editor) differ from user expectation.
8. Extension appears mapped but UTI resolution points elsewhere.
9. Removed apps leave stale Launch Services references.
10. Newly installed app not fully registered until launch/login cycle.
11. Sandboxed app restrictions alter open behavior for certain paths.
12. MDM/device policy limits user ability to change defaults.
13. Browser prompt changes `http`/`https` but not all related content types.
14. Per-user preference conflicts with system-level registration.
15. iCloud/document-provider paths open differently than local files.
16. Mixed Intel/Apple Silicon installs complicate handler registration expectations.
17. Invalid or incomplete `CFBundleURLTypes` declarations.
18. Invalid or incomplete `CFBundleDocumentTypes` declarations.
19. Third-party tools rely on undocumented Launch Services internals.
20. Deprecated API usage works on one release but breaks on another.
21. Open-from-terminal behavior differs from Finder workflow.
22. Headless/remote sessions miss expected user domain context.
23. Corrupt Launch Services caches cause persistent mismatch.
24. Custom scheme collisions between apps create unstable routing.
25. Browser-specific profiles alter deep link outcome despite OS default.
26. Uninstalled app remains selected as default until re-selection occurs.
27. Enterprise security tooling intercepts URL opens.
28. Signed/notarization state affects activation path in edge cases.
29. UTI declaration conflicts across third-party apps.
30. Callback opens browser instead of returning to native app due to scheme mismatch.

## Windows: 30 Common Issues

1. Direct registry edits fail due to `UserChoice` protections.
2. App registers capabilities but does not become default automatically.
3. Protocol default (`https`) differs from extension defaults (`.html`, `.htm`).
4. Browser default changes do not include all related protocols.
5. Multiple per-user profiles on same machine have different defaults.
6. GPO/MDM XML defaults apply then get overridden by user choice.
7. Bad XML association file causes partial or ignored policy application.
8. XML missing newly introduced extensions/protocols causes reset prompts.
9. Imported defaults only apply to new users in some deployment flows.
10. App update changes ProgID and breaks existing association mapping.
11. Uninstall leaves orphaned ProgID references.
12. Duplicate handlers from Store + desktop app produce confusing chooser behavior.
13. Hash-protected association resets trigger “app reset” notifications.
14. Assoc/ftype legacy tooling does not control modern user defaults fully.
15. Protocol handlers invoke wrong app architecture/channel variant.
16. Corporate hardening blocks default app UI or prompts.
17. RemoteApp/VDI environment introduces alternate launch behavior.
18. AppContainer/UWP activation path differs from Win32 shell execution.
19. File extension points to app, but app cannot handle real content.
20. URL launch APIs use constrained URI sets with special behavior.
21. `mailto`/custom protocol defaults differ between legacy and modern clients.
22. App advertised capabilities incomplete for expected MIME/protocol set.
23. Side-by-side installs (stable/beta/dev) race for defaults.
24. Broken icon/verb registration masks underlying handler issues.
25. Default app chooser UI sets one extension but not full family.
26. Policy marked mandatory prevents user remediation.
27. Policy marked suggested reapplies unexpectedly after refresh cadence.
28. Windows feature updates reset selected defaults.
29. Browser vendor “repair default” tools conflict with enterprise policy.
30. OAuth callback protocol not registered for native app, causing browser loop.
