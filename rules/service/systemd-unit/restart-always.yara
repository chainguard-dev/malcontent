rule systemd_restart_always : notable {
  strings:
    $restart = "Restart=always"
  condition:
    filesize < 4KB and any of them
}
