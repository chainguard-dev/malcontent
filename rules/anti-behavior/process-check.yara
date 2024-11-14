rule activity_monitor_checker: high macos {
  meta:
    description = "checks if 'Activity Monitor' is running"

  strings:
    $ps             = "ps" fullword
    $pgrep          = "pgrep" fullword
    $am             = "Activity Monitor" fullword
    $not_macos_text = "macOS Activity Monitor"
    $not_path       = "/Applications/Utilities/Activity Monitor.app"

  condition:
    filesize < 100MB and $am and any of ($p*) and none of ($not*)
}

rule anti_rootkit_hunter: high linux {
  meta:
    description = "checks if rootkit detectors are running"

  strings:
    $proc       = "/proc/"
    $chkrootkit = "chkrootkit"
    $lsrootkit  = "lsrootkit"

  condition:
    filesize < 10MB and all of them
}
