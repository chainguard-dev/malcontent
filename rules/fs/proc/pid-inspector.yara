rule pid_inspector: medium {
  meta:
    description = "accesses information about other pids via /proc"

  strings:
    $proc_exe      = /\/proc\/[\%\@]\w{1,3}\/exe/
    $proc_cmdline  = /\/proc\/[\%\@]\w{1,3}\/cmdline/
    $proc_loginuid = /\/proc\/[\%\@]\w{1,3}\/loginuid/
    $proc_comm     = /\/proc\/[\%\@]\w{1,3}\/comm/
    $proc_cgroup   = /\/proc\/[\%\@]\w{1,3}\/cgroup/
    $proc_auxv     = /\/proc\/[\%\@]\w{1,3}\/auxv/
    $proc_uid_map  = /\/proc\/[\%\@]\w{1,3}\/uid_map/

  condition:
    2 of ($proc*)
}

rule pid_inspector_high: high {
  meta:
    description = "accesses unusual process information"

  strings:
    $proc_exe              = /\/proc\/[\%\@]\w{1,3}\/exe/
    $proc_cmdline          = /\/proc\/[\%\@]\w{1,3}\/cmdline/
    $proc_loginuid         = /\/proc\/[\%\@]\w{1,3}\/loginuid/
    $proc_comm             = /\/proc\/[\%\@]\w{1,3}\/comm/
    $proc_cgroup           = /\/proc\/[\%\@]\w{1,3}\/cgroup/
    $proc_auxv             = /\/proc\/[\%\@]\w{1,3}\/auxv/
    $proc_uid_map          = /\/proc\/[\%\@]\w{1,3}\/uid_map/
    $not_network_manager   = "org.freedesktop.NetworkManager"
    $not_systemd           = "SYSTEMD_MACHINE_ID_PATH"
    $not_cgroups           = "/proc/cgroups"
    $not_duplicate_cmdline = "/proc/%d/cmdline"  // handled via proc_d_cmdline
    $not_duplicate_exe     = "/proc/%d/exe"  // handled via proc_d_exe

  // $proc_cmdline/$proc_exe match the "%d" dedup strings verbatim, so a single
  // "/proc/%d/exe" would otherwise disable the rule for the whole file. Compare
  // occurrence counts per family instead: a family disqualifies the file only
  // when every one of its matches is the dedup spelling. NetworkManager, systemd
  // and /proc/cgroups stay independently conclusive.

  condition:
    filesize < 104857600 and 3 of ($proc*) and (#proc_cmdline > #not_duplicate_cmdline or #proc_cmdline == 0) and (#proc_exe > #not_duplicate_exe or #proc_exe == 0) and none of ($not_network_manager, $not_systemd, $not_cgroups)
}
