rule systemctl_botnet_client: critical {
  meta:
    description = "botnet client that uses systemd"

  strings:
    $bash_history  = ".bash_history"
    $id_rsa        = "id_rsa"
    $systemctl     = "systemctl"
    $known_hosts   = "known_hosts"
    $daemon_reload = "daemon-reload"
    $SELINUX       = "SELINUX"
    $crontab       = "crontab"
    $mozilla       = "Mozilla/5.0"

  condition:
    all of them
}
