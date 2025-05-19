rule activity_monitor_checker: high macos {
  meta:
    description = "checks if 'Activity Monitor' is running"
    filetypes   = "macho"

  strings:
    $ps             = "ps" fullword
    $pgrep          = "pgrep" fullword
    $am             = "Activity Monitor" fullword
    $not_macos_text = "macOS Activity Monitor"
    $not_path       = "/Applications/Utilities/Activity Monitor.app"

  condition:
    filesize < 100MB and $am and any of ($p*) and none of ($not*)
}

rule linux_monitors: high linux {
  meta:
    description = "checks if various process monitors are running"
    filetypes   = "elf"

  strings:
    $pgrep = "pgrep" fullword
    $ps    = "ps" fullword

    $x_top     = "top" fullword
    $x_htop    = "htop" fullword
    $x_atop    = "atop" fullword
    $x_mate    = "mate-system-mon" fullword
    $x_iostat  = "iostat" fullword
    $x_mpstat  = "mpstat" fullword
    $x_sar     = "sar" fullword
    $x_glances = "glances" fullword
    $x_dstat   = "dstat" fullword
    $x_nmon    = "nmon" fullword
    $x_vmstat  = "vmstat" fullword
    $x_ps      = "ps" fullword

    $not_renice     = "renice" fullword
    $not_ddrescue   = "ddrescue" fullword
    $not_traceroute = "traceroute" fullword

  condition:
    filesize < 100KB and any of ($p*) and 3 of ($x*) and none of ($not*)
}

rule anti_rootkit_hunter: high linux {
  meta:
    description = "checks if rootkit detectors are running"
    filetypes   = "elf"

  strings:
    $proc       = "/proc/"
    $chkrootkit = "chkrootkit"
    $lsrootkit  = "lsrootkit"

  condition:
    filesize < 10MB and all of them
}
