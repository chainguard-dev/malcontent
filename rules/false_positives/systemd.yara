rule systemd: override {
  meta:
    description                           = "systemd"
    world_writeable_dirs_chmod            = "low"
    hidden_short_path                     = "low"
    dev_shm_file                          = "low"
    selinux_firewall                      = "medium"
    linux_critical_system_paths_small_elf = "medium"
    pseudoterminal_tunnel                 = "low"
    systemd_not_in_dependency_tree        = "ignore"
    filetypes                             = "elf,so"

  strings:
    $log_level = "SYSTEMD_LOG_LEVEL"
    $exec_pid  = "SYSTEMD_EXEC_PID"
    $cgroup    = "SYSTEMD_CGROUP"
    $sysv_path = "SYSTEMD_SYSVRCND_PATH"
    $analyze   = "SYSTEMD_ANALYZE_DEBUG"
    $unit      = "SYSTEMD_UNIT_PATH"

  condition:
    filesize < 3MB and any of them
}
