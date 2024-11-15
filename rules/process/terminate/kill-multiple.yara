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
    description = "forcibly kills multiple processes"

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
