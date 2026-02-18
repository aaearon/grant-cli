# Hero demo: interactive multi-CSP elevation with fuzzy search
Output demo/demo.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 600
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set PlaybackSpeed 1

Env PATH "/home/tim/sca-cli:/snap/bin:/usr/local/bin:/usr/bin:/bin"

# Clean prompt
Hide
Type `export PS1="$ "`
Enter
Type "clear"
Enter
Show

Sleep 500ms

Type "grant"
Sleep 300ms
Enter

# Hide the eligibility fetch delay (multi-CSP API call)
Hide
Sleep 12s
Show

# Full unfiltered target list now visible with (aws) and (azure) labels
Sleep 3s

# Fuzzy search filtering
Type "Admin"
Sleep 2s

# Select AdministratorAccess (aws) — first filtered result
Enter

# Hide the elevation API delay
Hide
Sleep 12s
Show

# Elevation success output now visible
Sleep 5s
