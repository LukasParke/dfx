Output docs/previews/dfx-automation.gif

Require dfx

Set Shell "bash"
Set FontSize 20
Set FontFamily "DejaVu Sans Mono"
Set Width 1400
Set Height 900
Set Padding 24
Set LetterSpacing 0
Set LineHeight 1.1
Set BorderRadius 16
Set WindowBar "Colorful"
Set Theme "TokyoNight"
Set TypingSpeed 18ms

Env HOME "/tmp/dfx-vhs-home"

Hide
Type "rm -rf /tmp/dfx-vhs-home && mkdir -p /tmp/dfx-vhs-home/.local/share/applications"
Enter
Type 'printf "%s\n" "[Desktop Entry]" "Name=Vivaldi" "Exec=/usr/bin/vivaldi-stable %U" "MimeType=x-scheme-handler/http;x-scheme-handler/https;text/html;application/xhtml+xml;" > /tmp/dfx-vhs-home/.local/share/applications/vivaldi-stable.desktop'
Enter
Type 'printf "%s\n" "{\"defaults\":[{\"kind\":\"browser\",\"app\":\"viv\"}]}" > /tmp/dfx-profile.json'
Enter
Type "clear"
Enter
Show

Type "dfx profile validate /tmp/dfx-profile.json"
Enter
Sleep 1s

Type "dfx apply --dry-run /tmp/dfx-profile.json"
Enter
Sleep 2s
