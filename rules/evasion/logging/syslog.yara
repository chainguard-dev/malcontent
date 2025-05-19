rule var_log_syslog: medium {
  meta:
    description = "accesses system logs"

  strings:
    $ref              = "/var/log/messages" fullword
    $ref2             = "/var/log/syslog" fullword
    $not_syslog_conf  = "/etc/syslog.conf"
    $not_rsyslog_conf = "/etc/rsyslog.conf"

  condition:
    filesize < 10MB and any of them
}

rule var_log_syslog_elf: high {
  meta:
    description = "ELF binary that accesses system logs"
    filetypes   = "elf"

  strings:
    $ref              = "/var/log/messages" fullword
    $ref2             = "/var/log/syslog" fullword
    $not_syslog_conf  = "/etc/syslog.conf"
    $not_rsyslog_conf = "/etc/rsyslog.conf"
    $not_rsyslog      = "RSYSLOG" fullword
    $not_top          = "~/.toprc"

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and any of ($ref*) and none of ($not*)
}
