rule ptrace: medium {
  meta:
    capability  = "CAP_SYS_PTRACE"
    description = "trace or modify system calls"

  strings:
    $ref = "ptrace" fullword

  condition:
    any of them
}

rule ptrace_injector: medium {
  meta:
    description = "may inject code into other processes"

  strings:
    $maps   = /\/{0,1}proc\/[%{][%}\w]{0,1}\/maps/
    $ptrace = "ptrace" fullword
    $proc   = "process" fullword

  condition:
    filesize < 67108864 and $maps and $ptrace and $proc
}

rule ptrace_injector_unknown: high {
  meta:
    description = "may inject code into other processes"

  strings:
    $maps   = /\/{0,1}proc\/[%{][%}\w]{0,1}\/maps/
    $ptrace = "ptrace" fullword
    $proc   = "process" fullword

    $not_bpftool = "bpftool" fullword
    $not_libdw   = "invalid DWARF"

  condition:
    filesize < 67108864 and $maps and $ptrace and $proc and none of ($not*)
}
