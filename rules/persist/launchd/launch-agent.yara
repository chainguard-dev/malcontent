rule macos_LaunchAgents: medium {
  meta:
    description = "persist via LaunchAgents"
    platforms   = "darwin"

    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"

  strings:
    $val = /[\~\/\.\w]{0,32}LaunchAgents[\/\w\%\$\.]{0,32}/ fullword

  condition:
    any of them
}

rule launchctl: medium {
  meta:
    description = "sets up a LaunchAgent and launches it"
    platforms   = "darwin"

    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"

  strings:
    $upper_val = /[\~\/\.\w]{0,32}LaunchAgents[\/\w\%\$\.]{0,32}/ fullword
    $lower_val = /[\~\/\.\w]{0,32}launchagents[\/\w\%\$\.]{0,32}/ fullword
    $launch    = "launchctl"

  condition:
    $launch and ($upper_val or $lower_val)
}

rule launchctl_embedded: high {
  meta:
    description = "sets up an embedded LaunchAgent and launches it"

  strings:
    $upper_val        = /[\~\/\.\w]{0,32}[Ll]aunch[aA]gents[\/\w\%\$\.]{0,32}/ fullword
    $launch           = "launchctl load"
    $programArguments = "<key>ProgramArguments</key>"

  condition:
    all of them
}

rule fake_launchd: critical {
  meta:
    description = "interacts with deceptively named LaunchAgent"

  strings:
    $f_launch  = /\/Library\/LaunchAgents\/launched.{0,16}.plist/
    $f_apple   = /[\/\w \.]{0,64}\/apple.plist/
    $launchctl = "launchctl"

  condition:
    $launchctl and any of ($f*)
}

rule macos_personal_launch_agent: medium {
  meta:
    description = "sets up a personal launch agent"

    hash_2017_CallMe = "c4b6845e50fd4dce0fa69b25c7e9f7d25e6a04bbca23c279cc13f8b274d865c7"

  strings:
    $home_val          = /\$HOME\/Library\/LaunchAgents[\.\/\w ]{0,32}/
    $tilde_val         = /\~\/Library\/LaunchAgents[\.\/\w ]{0,32}/
    $tilde_lower_val   = /\~\/library\/launchagents[\.\/\w ]{0,32}/
    $not_apple_private = "com.apple.private"
    $not_git           = "GIT_CONFIG"
    $not_apple_program = "@(#)PROGRAM:"

  condition:
    ($home_val or $tilde_val or $tilde_lower_val) and none of ($not*)
}
