rule systemd : override linux {
  meta:
    description = "systemd"
	world_writeable_dirs_chmod = "medium"
	hidden_short_path = "medium"
	dev_shm_file = "medium"
	selinux_firewall = "medium"
	linux_critical_system_paths_high = "medium"
	pseudoterminal_tunnel = "medium"
	systemd_not_in_dependency_tree = "ignore"
	filetypes = "elf,so"
  strings:
	$log_level = "SYSTEMD_LOG_LEVEL"
	$exec_pid = "SYSTEMD_EXEC_PID"
	$cgroup = "SYSTEMD_CGROUP"
	$sysv_path = "SYSTEMD_SYSVRCND_PATH"
  condition:
    filesize < 3MB and any of them
}
