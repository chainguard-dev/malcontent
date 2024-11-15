rule sleep_and_background: medium {
  meta:
    description = "calls sleep and runs shell code in the background"

  strings:
    $s_sleep_time = /sleep \d{1,128}/
    $s_nohup      = "nohup"
    $s_sleep      = "_sleep"
    $cmd_bg       = /\/[a-z]{1,128}\/[\w\/\- \.]{0,32} &[^&]/
    $cmd_bg_redir = "2>&1 &"
    $hash_bang    = "#!"
    $not_perldyn  = "bin/parldyn"
    $not_perlxsi  = "perlxsi"
    $not_electron = "ELECTRON_RUN_AS_NODE"
    $not_node     = "NODE_DEBUG_NATIVE"
    $not_private  = "/Library/Developer/PrivateFrameworks/"

  condition:
    1 of ($s_*) and 1 of ($cmd_*) and not $hash_bang in (0..2) and none of ($not*)
}
