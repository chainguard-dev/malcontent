rule procfs_unhide: high {
  meta:
    description = "kills processes hidden by procfs bindmounts"

  strings:
    $p_mounts = "/proc/mounts"
    $p_proc_d = "/proc/\\d"
    $p_grep   = "grep"

    $k_kill    = "kill" fullword
    $k_pkill   = "pkill" fullword
    $k_killall = "killall" fullword

  condition:
    filesize < 100KB and all of ($p*) and any of ($k*)
}
