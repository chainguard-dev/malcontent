
rule macos_LaunchAgents : notable {
  meta:
    description = "persist via LaunchAgents"
    platforms = "darwin"
  strings:
    $val = /[\~\/\.\w]{0,32}LaunchAgents[\/\w\%\$]{0,32}/ fullword
  condition:
    any of them
}

rule launchctl : notable {
  meta:
    description = "sets up a LaunchAgent and launches it"
    platforms = "darwin"
  strings:
    $upper_val = /[\~\/\.\w]{0,32}LaunchAgents[\/\w\%\$]{0,32}/ fullword
    $lower_val = /[\~\/\.\w]{0,32}launchagents[\/\w\%\$]{0,32}/ fullword
    $launch = "launchctl"
  condition:
    $launch and ($upper_val or $lower_val)
}

rule macos_personal_launch_agent : notable {
  meta:
    description = "sets up a personal launch agent"
  strings:
    $home_val = /\$HOME\/Library\/LaunchAgents[\.\/\w ]{0,32}/
    $tilde_val = /\~\/Library\/LaunchAgents[\.\/\w ]{0,32}/
    $tilde_lower_val = /\~\/library\/launchagents[\.\/\w ]{0,32}/
    $not_apple_private = "com.apple.private"
    $not_git = "GIT_CONFIG"
    $not_apple_program = "@(#)PROGRAM:"
  condition:
    ($home_val or $tilde_val or $tilde_lower_val) and none of ($not*)
}
