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

rule win_edr_stopper: critical windows {
  meta:
    description = "Stops EDR/Antivirus services"
    filetypes   = "bat,exe,pe"

  strings:
    $kind_malwarebytes = "alwarebytes"
    $stop              = "stopservice"

  condition:
    filesize < 1MB and $stop and any of ($kind*)
}

rule linux_edr_killall: critical linux {
  meta:
    description = "Kills EDR/Antivirus services"

  strings:
    $kind_aliyun = /killall.{0,4}AliYunDun.{0,16}/
    $kind_aegis  = /killall.{0,4}aegis_cli/

  condition:
    filesize < 1MB and any of ($kind*)
}

rule linux_edr_stop: critical linux {
  meta:
    description = "Stops EDR/Antivirus services"

  strings:
    $aegis_stop = "/etc/init.d/aegis stop"

  condition:
    filesize < 1MB and any of them
}

rule linux_edr_unistall: critical linux {
  meta:
    description = "Stops EDR/Antivirus services"

  strings:
    $aegis = /\/etc\/init\.d\/aegis {0,3}uninstall/

  condition:
    filesize < 1MB and any of them
}

rule linux_edr_kill: high linux {
  meta:
    description = "Kills EDR/Antivirus services"
    filetypes   = "bat,exe,pe"

  strings:
    $kill           = "kill"
    $kind_aliyundun = "AliYunDun" fullword
    $kind_aegis_cli = "aegis_cli" fullword
    $kind_quartz    = "aegis_quartz" fullword

  condition:
    filesize < 1MB and $kill and any of ($kind*)
}
