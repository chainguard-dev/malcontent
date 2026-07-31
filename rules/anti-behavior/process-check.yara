rule activity_monitor_checker: high macos {
  meta:
    description = "checks if 'Activity Monitor' is running"
    filetypes   = "macho"

  strings:
    $ps             = "ps" fullword
    $pgrep          = "pgrep" fullword
    $am             = "Activity Monitor" fullword
    $not_macos_text = "macOS Activity Monitor" fullword
    $not_path       = "/Applications/Utilities/Activity Monitor.app"

  // $am matches inside both accepted spellings, so their mere presence hid a
  // separate bare "Activity Monitor" pgrep target elsewhere in the file. Compare
  // occurrence counts instead: fire only on an "Activity Monitor" that neither
  // accepted spelling accounts for. $not_macos_text carries $am's fullword so
  // both agree on where the token ends; $not_path needs none because $am is
  // always bounded by "/" and "." inside it.

  condition:
    filesize < 100MB and $am and any of ($p*) and #am > #not_macos_text + #not_path
}

rule linux_monitors: high linux {
  meta:
    description = "checks if various process monitors are running"
    filetypes   = "elf"

  strings:
    // "ps" belongs to this group only. It was also listed as an $x* monitor, which
    // let one match satisfy both "any of ($p*)" and one of the three required
    // monitors, so the threshold really only asked for two monitors beyond ps --
    // and bare "ps" occurs in a large share of ordinary binaries.
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
