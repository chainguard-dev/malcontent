
rule sleep_and_background : notable {
  meta:
    description = "calls sleep and runs shell code in the background"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Linux_Malware_Samples_3059 = "305901aa920493695729132cfd20cbddc9db2cf861071450a646c6a07b4a50f3"
    hash_2023_Linux_Malware_Samples_3668 = "3668b167f5c9083a9738cfc4bd863a07379a5b02ee14f48a10fb1240f3e421a6"
  strings:
    $s_sleep_time = /sleep \d{1,128}/
    $s_nohup = "nohup"
    $s_sleep = "_sleep"
    $cmd_bg = /\/[a-z]{1,128}\/[\w\/\- \.]{0,32} &[^&]/
    $cmd_bg_redir = "2>&1 &"
    $hash_bang = "#!"
    $not_perldyn = "bin/parldyn"
    $not_perlxsi = "perlxsi"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_node = "NODE_DEBUG_NATIVE"
    $not_private = "/Library/Developer/PrivateFrameworks/"
  condition:
    1 of ($s_*) and 1 of ($cmd_*) and not $hash_bang in (0..2) and none of ($not*)
}
