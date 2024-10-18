rule systemd : override {
  meta:
    description = "systemd"
    world_writeable_dirs = "medium"
	hidden_short_path = "medium"
	dev_shm_file = "medium"
	selinux_firewall = "medium"
	linux_critical_system_paths_high = "medium"
	pseudoterminal_tunnel = "medium"
  strings:
	$log_level = "SYSTEMD_LOG_LEVEL"
	$exec_pid = "SYSTEMD_EXEC_PID"
  condition:
    any of them
}
