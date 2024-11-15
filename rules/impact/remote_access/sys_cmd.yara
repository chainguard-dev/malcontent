rule multiple_sys_commands: high {
  meta:
    description = "mentions multiple unrelated system commands"

  strings:
    $cron    = "/usr/sbin/cron"
    $rsyslog = "/usr/sbin/rsyslogd"
    $systemd = "systemd/systemd"
    $auditd  = "auditd" fullword
    $sshd    = "/usr/sbin/sshd"
    $busybox = "/bin/busybox"
    $sdpd    = "/usr/sbin/sdpd"
    $gam     = "/usr/libexec/gam_server"

  condition:
    filesize < 67108864 and 3 of them
}
