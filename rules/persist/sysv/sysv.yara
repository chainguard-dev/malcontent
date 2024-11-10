rule sysv_persist: high {
  meta:
    description = "installs arbitrary files into SYSV-style init directories"

  strings:
    $rc_d   = "/etc/rc%d.d/S%d%s"
    $init_d = "/etc/init.d/%s"

  condition:
    filesize < 5MB and any of them
}
