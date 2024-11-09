rule ptrace: medium {
  meta:
    capability                                                                           = "CAP_SYS_PTRACE"
    description                                                                          = "trace or modify system calls"
    hash_2023_Downloads_21b3                                                             = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2023_Downloads_21ca                                                             = "21ca44d382102e0ae33d02f499a5aa2a01e0749be956cbd417aae64085f28368"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"

  strings:
    $ref = "ptrace" fullword

  condition:
    any of them
}

rule ptrace_injector: high {
  meta:
    description                 = "may inject code into other processes"
    hash_2024_procinject_infect = "cb7c09e58c5314e0429ace2f0e1f3ebd0b802489273e4b8e7531ea41fa107973"

  strings:
    $maps         = /\/{0,1}proc\/[%{][%}\w]{0,1}\/maps/
    $ptrace       = "ptrace" fullword
    $proc         = "process" fullword
    $not_qemu     = "QEMU_IS_ALIGNED"
    $not_chromium = "CHROMIUM_TIMESTAMP"
    $not_crashpad = "CRASHPAD" fullword

  condition:
    filesize < 67108864 and $maps and $ptrace and $proc and none of ($not*)
}
