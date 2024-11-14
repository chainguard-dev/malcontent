rule ptrace: medium {
  meta:
    capability               = "CAP_SYS_PTRACE"
    description              = "trace or modify system calls"



  strings:
    $ref = "ptrace" fullword

  condition:
    any of them
}

rule ptrace_injector: high {
  meta:
    description = "may inject code into other processes"

  strings:
    $maps   = /\/{0,1}proc\/[%{][%}\w]{0,1}\/maps/
    $ptrace = "ptrace" fullword
    $proc   = "process" fullword

  condition:
    filesize < 67108864 and $maps and $ptrace and $proc
}

rule known_ptrace_injectors: override {
  meta:
    description     = "known"
    ptrace_injector = "medium"
    proc_d_exe_high = "medium"

  strings:
    $not_qemu     = "QEMU_IS_ALIGNED"
    $not_chromium = "CHROMIUM_TIMESTAMP"
    $not_crashpad = "CRASHPAD" fullword
    $not_perf     = "PERF_SAMPLE" fullword
    $not_trace    = "TRACE_REQ" fullword
    $not_bpf      = "BPF" fullword

  condition:
    ptrace and any of them
}
