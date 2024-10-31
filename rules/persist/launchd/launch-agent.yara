
rule macos_LaunchAgents : medium {
  meta:
    description = "persist via LaunchAgents"
    platforms = "darwin"
    hash_2024_2019_02_Shlayer_Malware_a2ec = "a2ec5d9c80794c26a7eaac8586521f7b0eb24aba9ad393c194c86cfd150e5189"
    hash_2024_2019_02_Shlayer_Malware_fd93 = "fd93c08678392eae99a1281577a54875a0e1920c49cdea6d56b53dabc4597803"
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
  strings:
    $val = /[\~\/\.\w]{0,32}LaunchAgents[\/\w\%\$]{0,32}/ fullword
  condition:
    any of them
}

rule launchctl : medium {
  meta:
    description = "sets up a LaunchAgent and launches it"
    platforms = "darwin"
    hash_2024_2019_02_Shlayer_Malware_a2ec = "a2ec5d9c80794c26a7eaac8586521f7b0eb24aba9ad393c194c86cfd150e5189"
    hash_2024_2019_02_Shlayer_Malware_fd93 = "fd93c08678392eae99a1281577a54875a0e1920c49cdea6d56b53dabc4597803"
    hash_2021_CDDS_client = "623f99cbe20af8b79cbfea7f485d47d3462d927153d24cac4745d7043c15619a"
  strings:
    $upper_val = /[\~\/\.\w]{0,32}LaunchAgents[\/\w\%\$]{0,32}/ fullword
    $lower_val = /[\~\/\.\w]{0,32}launchagents[\/\w\%\$]{0,32}/ fullword
    $launch = "launchctl"
  condition:
    $launch and ($upper_val or $lower_val)
}

rule macos_personal_launch_agent : medium {
  meta:
    description = "sets up a personal launch agent"
    hash_2024_2019_02_Shlayer_Malware_a2ec = "a2ec5d9c80794c26a7eaac8586521f7b0eb24aba9ad393c194c86cfd150e5189"
    hash_2024_2019_02_Shlayer_Malware_fd93 = "fd93c08678392eae99a1281577a54875a0e1920c49cdea6d56b53dabc4597803"
    hash_2017_CallMe = "c4b6845e50fd4dce0fa69b25c7e9f7d25e6a04bbca23c279cc13f8b274d865c7"
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
