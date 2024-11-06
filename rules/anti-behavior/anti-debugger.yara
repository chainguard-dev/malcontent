rule win_debugger_present: medium windows {
  meta:
    description = "Detects if process is being executed within a debugger"

  strings:
    $debug_idp = "IsDebuggerPresent"
    $debug_uhf = "UnhandledExceptionFilter"

  condition:
    filesize < 25MB and any of them
}

rule win_debugger_or_vm: medium windows {
  meta:
    description = "Detects if process is being executed within a debugger or VM"

  strings:
    $cpu_pfp   = "IsProcessorFeaturePresent"
    $debug_qpc = "QueryPerformanceCounter"
    $debug_idp = "IsDebuggerPresent"
    $debug_uhf = "UnhandledExceptionFilter"

  condition:
    filesize < 25MB and 2 of ($debug*) and any of ($cpu*)
}
