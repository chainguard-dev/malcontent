rule systemd_restart_always : notable {
  meta:
	description = "service restarts no matter how many times it crashes"
  strings:
    $restart = "Restart=always"
  condition:
    filesize < 4KB and any of them
}
