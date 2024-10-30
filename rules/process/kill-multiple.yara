rule killall_generic: medium {
  meta:
    description = "kills multiple processes by name"

  strings:
    $ref = /killall \w{2,16}/ fullword

  condition:
    $ref
}

rule sigkill_multiple: medium {
  meta:
    description              = "forcibly kills multiple processes"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
    hash_2023_Downloads_f864 = "f864922f947a6bb7d894245b53795b54b9378c0f7633c521240488e86f60c2c5"

  strings:
    $s_xargs_kill_9        = "xargs kill -9"
    $s_xargs_kill_r9       = "xargs -r kill -9"
    $s_kill_9_backtick     = "kill -9 `"
    $s_pkill_9             = "pkill -9"
    $s_kill_9_subshell     = "kill -9 $("
    $s_killall_9           = "killall -9"
    $s_xargs_I_kill        = /xargs -I [\w%]{1,64} kill -9/
    $s_xargs_I_docker_kill = /xargs -I \w{1,64} docker kill/
    $not_official          = "All Rights Reserved"
    $not_sysdiagnose       = "PROGRAM:sysdiagnose"
    $not_postfix           = "Postfix"

  condition:
    any of ($s*) and none of ($not*)
}
