# Secondary demo: grant env + grant status workflow
Output demo/demo-env-status.gif

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

# Show eval + grant env pattern
Type "eval $(grant env --provider aws)"
Sleep 300ms
Enter

# Hide the eligibility fetch delay
Hide
Sleep 12s
Show

# Select AdministratorAccess
Type "Admin"
Sleep 1.5s
Enter

# Hide the elevation API delay
Hide
Sleep 12s
Show

# Show credentials were set
Sleep 500ms
Type "echo $AWS_ACCESS_KEY_ID"
Sleep 300ms
Enter
Sleep 1.5s

# Show active sessions
Sleep 500ms
Type "grant status --provider aws"
Sleep 300ms
Enter

# Wait for status output
Sleep 5s

# Pause to read
Sleep 4s
