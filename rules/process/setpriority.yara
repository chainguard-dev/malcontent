rule nice: harmless {
  meta:
    capability  = "CAP_SYS_NICE"
    syscall     = "nice"
    description = "adjust the process nice value"

  strings:
    $ref  = "nice" fullword
    $ref2 = "renice" fullword

  condition:
    any of them
}

rule setpriority: harmless {
  meta:
    capability  = "CAP_SYS_NICE"
    syscall     = "setpriority"
    description = "adjust the process nice value"

  strings:
    $ref = "setpriority" fullword

  condition:
    any of them
}
