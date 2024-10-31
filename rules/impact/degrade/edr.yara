rule win_kill_proc: medium windows {
  meta:
    description = "may be able to bypass or kill EDR software"

  strings:
    $f_gcp     = "GetCurrentProcess"
    $f_gct     = "GetCurrentThread"
    $f_time    = "GetSystemTimeAsFileTime"
    $debug_pfp = "IsProcessorFeaturePresent"
    $debug_qpc = "QueryPerformanceCounter"
    $debug_idp = "IsDebuggerPresent"
    $debug_uhf = "UnhandledExceptionFilter"
    $kill_gmh  = "GetModuleHandle"
    $kill_tp   = "TerminateProcess"

  condition:
    filesize < 1MB and all of ($kill*) and 3 of ($debug*) and 1 of ($f*)
}

rule edr_stopper: critical windows {
  meta:
    description = "Stops EDR/Antivirus services"
    filetypes   = "exe,dll"

  strings:
    $kind_malwarebytes = "alwarebytes"
    $stop              = "stopservice"

  condition:
    filesize < 1MB and $stop and any of ($kind*)
}
