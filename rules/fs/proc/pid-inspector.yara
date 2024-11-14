rule pid_inspector: medium {
  meta:
    description                      = "accesses information about other pids via /proc"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"

    hash_2023_Unix_Trojan_Mirai_1233 = "12330634ae5c2ac7da6d8d00f3d680630d596df154f74e03ff37e6942f90639e"

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
    description                      = "accesses unusual process information"
    hash_2023_Sysrv_Hello_sys_x86_64 = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"

    hash_2023_Unix_Trojan_Mirai_1233 = "12330634ae5c2ac7da6d8d00f3d680630d596df154f74e03ff37e6942f90639e"

  strings:
    $proc_exe            = /\/proc\/[\%\@]\w{1,3}\/exe/
    $proc_cmdline        = /\/proc\/[\%\@]\w{1,3}\/cmdline/
    $proc_loginuid       = /\/proc\/[\%\@]\w{1,3}\/loginuid/
    $proc_comm           = /\/proc\/[\%\@]\w{1,3}\/comm/
    $proc_cgroup         = /\/proc\/[\%\@]\w{1,3}\/cgroup/
    $proc_auxv           = /\/proc\/[\%\@]\w{1,3}\/auxv/
    $proc_uid_map        = /\/proc\/[\%\@]\w{1,3}\/uid_map/
    $not_network_manager = "org.freedesktop.NetworkManager"
    $not_systemd         = "SYSTEMD_MACHINE_ID_PATH"
    $not_cgroups         = "/proc/cgroups"

  condition:
    filesize < 104857600 and 3 of ($proc*) and none of ($not*)
}
