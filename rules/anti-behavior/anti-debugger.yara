rule win_debugger_present: medium windows {
  meta:
    description = "Detects if process is being executed within a debugger"
    filetypes   = "exe,pe,ps1"

  strings:
    $debug_idp = "IsDebuggerPresent"
    $debug_uhf = "UnhandledExceptionFilter"

  condition:
    filesize < 25MB and any of them
}

rule win_debugger_or_vm: medium windows {
  meta:
    description = "Detects if process is being executed within a debugger or VM"
    filetypes   = "exe,pe,ps1"

  strings:
    $cpu_pfp   = "IsProcessorFeaturePresent"
    $debug_qpc = "QueryPerformanceCounter"
    $debug_idp = "IsDebuggerPresent"
    $debug_uhf = "UnhandledExceptionFilter"

  condition:
    filesize < 25MB and 2 of ($debug*) and any of ($cpu*)
}

rule multiple_linux_methods: high linux {
  meta:
    description = "possible debugger detection across multiple methods"
    filetypes   = "elf"

  strings:
    $ld_profile    = "LD_PROFILE" fullword
    $ld_debug      = "LD_DEBUG" fullword
    $proc_exe      = /\/proc\/.{0,5}\/exe/
    $proc_status   = /\/proc\/.{0,5}\/status/
    $sys_kern      = "/proc/sys/kernel/osrelease"
    $sys_device    = "/sys/devices/system/cpu"
    $sys_cpuinfo   = "/proc/cpuinfo"
    $not_busybox   = "BusyBox"
    $not_rtld      = "RTLD_NEXT"
    $not_rtld2     = "HRTIMER_SOFTIRQ"
    $not_snapd     = "SNAPD" fullword
    $not_ld_origin = "LD_ORIGIN_PATH"
    $not_ld_mask   = "LD_HWCAP_MASK"

  condition:
    filesize < 8MB and all of ($ld*) and any of ($proc*) and any of ($sys*) and none of ($not*)
}
