rule activity_monitor_checker: high macos {
  meta:
    hash_2020_BirdMiner_tonsillith = "9f8dba1cea7c8a4d7701a6a3e2d826202ba7e00e30e9c836c734ad6842b8cb5e"
    hash_2020_BirdMiner_tormina    = "4179cdef4de0eef44039e9d03d42b3aeca06df533be74fc65f5235b21c9f0fb1"
    description                    = "checks if 'Activity Monitor' is running"

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
