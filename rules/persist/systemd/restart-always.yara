rule systemd_restart_always: medium {
  meta:
    description = "service restarts no matter how many times it crashes"

  strings:
    $restart = "Restart=always"

  condition:
    filesize < 4096 and any of them
}
