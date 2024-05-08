
rule multiple_sys_commands : high {
  meta:
    description = "mentions multiple unrelated system commands"
    hash_2023_Unix_Trojan_Xorddos_c9bd = "c9bd6d01eb7258fef88ec5c9276431c1db45f063b316f83943e45b6a40a76783"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"
  strings:
    $cron = "/usr/sbin/cron"
    $rsyslog = "/usr/sbin/rsyslogd"
    $systemd = "systemd/systemd"
    $auditd = "auditd" fullword
    $sshd = "/usr/sbin/sshd"
    $busybox = "/bin/busybox"
    $sdpd = "/usr/sbin/sdpd"
    $gam = "/usr/libexec/gam_server"
  condition:
    filesize < 67108864 and 3 of them
}
