rule multiple_sys_commands: high {
  meta:
    description = "mentions multiple unrelated system commands"

    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

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
