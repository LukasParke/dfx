Output docs/previews/dfx-features.gif

Require dfx

Set Shell "bash"
Set FontSize 24
Set FontFamily "Liberation Mono"
Set Width 1100
Set Height 650
Set Padding 24
Set BorderRadius 16
Set WindowBar "Colorful"
Set Theme "TokyoNight"
Set TypingSpeed 18ms

Env HOME "/tmp/dfx-vhs-home"
Env PATH "/home/luke/.local/bin:/usr/local/bin:/usr/bin:/bin"

Hide
Type "rm -rf /tmp/dfx-vhs-home && mkdir -p /tmp/dfx-vhs-home/.local/share/applications"
Enter
Type 'printf "%s\n" "[Desktop Entry]" "Name=Firefox" "Exec=/usr/bin/firefox %U" "MimeType=x-scheme-handler/http;x-scheme-handler/https;text/html;application/xhtml+xml;" > /tmp/dfx-vhs-home/.local/share/applications/firefox.desktop'
Enter
Type "clear"
Enter
Show

Type "dfx get --content-type text/html"
Enter
Sleep 1s

Type "dfx doctor --mime text/html --json"
Enter
Sleep 1.5s

Type "dfx set --browser --app firefox.desktop --dry-run"
Enter
Sleep 1.5s
