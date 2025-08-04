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

  condition:
    filesize < 104857600 and 3 of ($proc*) and none of ($not*)
}
