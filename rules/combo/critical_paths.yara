
rule linux_critical_system_paths : medium {
  meta:
    description = "accesses multiple critical Linux paths"
  strings:
    $p_etc_crontab = "/etc/crontab"
	$p_etc_sysctl_conf = "/etc/sysctl.conf"
	$p_etc_init_d = /\/etc\/init.d[\w\/\.\-]{0,32}/
	$p_etc_cron_d = /\/etc\/cron.d[\w\/\.\-]{0,32}/
	$p_etc_selinux = /\/etc\/selinux[\w\/\.\-]{0,32}/
	$p_etc_systemd = /\/etc\/systemd[\w\/\.\-]{0,32}/
    $p_var_run = /\/var\/run[\w\/\.\-]{0,32}/
    $p_var_log = /\/var\/log[\w\/\.\-]{0,32}/
    $p_usr_libexec = /\/usr\/libexec[\w\/\.\-]{0,32}/
    $p_tmp = /\/tmp\/[\w\/\.\-]{0,32}/
    $p_usr_bin = /\/usr\/bin[\w\/\.\-]{0,32}/
    $p_sbin = /\/sbin\/[\w\/\.\-]{0,32}/
    $p_lib_systemd = /\/lib\/systemd[\w\/\.\-]{0,32}/
    $p_boot = /\/boot\/[\w\/\.\-]{0,32}/
    $p_proc = /\/proc\/[\w\/\.\-]{0,32}/
    $p_sys = /\/sys\/(devices|class)[\w\/\.\-]{0,32}/
    $p_sysctl = /sysctl[ -a-z]{0,32}/
	$p_dev_watchdog = "/dev/watchdog"
	$p_ps = "/usr/bin/ps"
	$p_ss = "/usr/bin/lsof"
  condition:
    5 of ($p*)
}

rule linux_critical_system_paths_small_elf : high {
  meta:
    description = "accesses multiple critical Linux paths"
  condition:
    filesize < 8MB and uint32(0) == 1179403647 and linux_critical_system_paths
}

rule linux_critical_system_paths_small_shell : high {
  meta:
    description = "accesses multiple critical Linux paths"
  strings:
    $hash_bang = "#!"
  condition:
    filesize < 32KB and $hash_bang in (0..2) and linux_critical_system_paths
}
