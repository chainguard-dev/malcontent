rule linux_critical_system_paths: medium {
  meta:
    description = "accesses multiple critical Linux paths"

  strings:
    $p_etc_crontab     = "/etc/crontab"
    $p_etc_sysctl_conf = "/etc/sysctl.conf"
    $p_etc_init_d      = /\/etc\/init\.d[\w\/\.\-]{0,32}/
    $p_etc_cron_d      = /\/etc\/cron\.d[\w\/\.\-]{0,32}/
    $p_etc_selinux     = /\/etc\/selinux[\w\/\.\-]{0,32}/
    $p_etc_systemd     = /\/etc\/systemd[\w\/\.\-]{0,32}/
    $p_etc_preload     = "/etc/ld.so.preload"
    $p_ld_so_cache     = "/etc/ld.so.cache"
    $p_var_run         = /\/var\/run[\w\/\.\-]{0,32}/
    $p_var_log         = /\/var\/log[\w\/\.\-]{0,32}/
    $p_usr_libexec     = /\/usr\/libexec[\w\/\.\-]{0,32}/
    $p_tmp             = /\/tmp\/[\w\/\.\-]{0,32}/
    $p_sbin            = /\/sbin\/[\w\/\.\-]{0,32}/
    $p_lib_systemd     = /\/lib\/systemd[\w\/\.\-]{0,32}/
    $p_boot            = /\/boot\/[\w\/\.\-]{0,32}/
    $proc_self_cmdline = "/proc/self/cmdline"
    $proc_self_cgroup  = "/proc/self/cgroup"
    $p_lib             = "/usr/lib/x86_64-linux-gnu/"
    $p_lib_ld          = "/lib64/ld-linux-x86-64.so.2"
    $p_dev_sys         = /\/sys\/devices\/system\/(cpu|node)\/[\w\/\.\-]{0,32}/
    $p_sysctl          = /sysctl[ -a-z]{0,32}/
    $p_dev_watchdog    = "/dev/watchdog"
    $p_ps              = "/usr/bin/ps"
    $p_ss              = "/usr/bin/lsof"
    $p_ssh             = "/usr/bin/ssh"
    $p_dev_shm         = "/dev/shm"

  condition:
    filesize < 120MB and any of ($p_etc*) and 40 % of ($p*)
}

rule linux_critical_system_paths_small_elf: high {
  meta:
    description                 = "ELF accesses multiple critical Linux paths"
    linux_critical_system_paths = "high"

  strings:
    // a repeat of linux_critical_system_paths because we can't see
    // the strings in our results otherwise
    $p_etc_crontab     = "/etc/crontab"
    $p_etc_sysctl_conf = "/etc/sysctl.conf"
    $p_etc_init_d      = /\/etc\/init.d[\w\/\.\-]{0,32}/
    $p_etc_cron_d      = /\/etc\/cron.d[\w\/\.\-]{0,32}/
    $p_etc_selinux     = /\/etc\/selinux[\w\/\.\-]{0,32}/
    $p_etc_systemd     = /\/etc\/systemd[\w\/\.\-]{0,32}/
    $p_etc_preload     = "/etc/ld.so.preload"
    $p_etc_ld_so_cache = "/etc/ld.so.cache"
    $p_var_run         = /\/var\/run[\w\/\.\-]{0,32}/
    $p_var_log         = /\/var\/log[\w\/\.\-]{0,32}/
    $p_usr_libexec     = /\/usr\/libexec[\w\/\.\-]{0,32}/
    $p_tmp             = /\/tmp\/[\w\/\.\-]{0,32}/
    $p_sbin            = /\/sbin\/[\w\/\.\-]{0,32}/
    $p_lib_systemd     = /\/lib\/systemd[\w\/\.\-]{0,32}/
    $p_boot            = /\/boot\/[\w\/\.\-]{0,32}/
    $proc_self_cmdline = "/proc/self/cmdline"
    $proc_self_cgroup  = "/proc/self/cgroup"
    $p_lib             = "/usr/lib/x86_64-linux-gnu/"
    $p_lib_ld          = "/lib64/ld-linux-x86-64.so.2"
    $p_dev_sys         = /\/sys\/devices\/system\/(cpu|node)\/[\w\/\.\-]{0,32}/
    $p_sysctl          = /sysctl[ -a-z]{0,32}/
    $p_dev_watchdog    = "/dev/watchdog"
    $p_ps              = "/usr/bin/ps"
    $p_ss              = "/usr/bin/lsof"
    $p_ssh             = "/usr/bin/ssh"
    $p_dev_shm         = "/dev/shm"

    $not_vim     = "VIMRUNTIME" fullword
    $not_systemd = "SYSTEMD_OS_RELEASE"
    $not_vio     = "/sys/devices/vio"

  condition:
    filesize < 2MB and uint32(0) == 1179403647 and any of ($p_etc*) and 40 % of ($p*) and none of ($not*)
}

rule linux_critical_system_paths_small_shell: high {
  meta:
    description = "script accesses multiple critical Linux paths"

  strings:
    $hash_bang         = "#!"
    // a repeat of linux_critical_system_paths because we can't see
    // the strings in our results otherwise
    $p_etc_crontab     = "/etc/crontab"
    $p_etc_sysctl_conf = "/etc/sysctl.conf"
    $p_etc_init_d      = /\/etc\/init.d[\w\/\.\-]{0,32}/
    $p_etc_cron_d      = /\/etc\/cron.d[\w\/\.\-]{0,32}/
    $p_etc_selinux     = /\/etc\/selinux[\w\/\.\-]{0,32}/
    $p_etc_systemd     = /\/etc\/systemd[\w\/\.\-]{0,32}/
    $p_etc_preload     = "/etc/ld.so.preload"
    $p_ld_so_cache     = "/etc/ld.so.cache"
    $p_var_run         = /\/var\/run[\w\/\.\-]{0,32}/
    $p_var_log         = /\/var\/log[\w\/\.\-]{0,32}/
    $p_usr_libexec     = /\/usr\/libexec[\w\/\.\-]{0,32}/
    $p_tmp             = /\/tmp\/[\w\/\.\-]{0,32}/
    $p_sbin            = /\/sbin\/[\w\/\.\-]{0,32}/
    $p_lib_systemd     = /\/lib\/systemd[\w\/\.\-]{0,32}/
    $p_boot            = /\/boot\/[\w\/\.\-]{0,32}/
    $proc_self_cmdline = "/proc/self/cmdline"
    $proc_self_cgroup  = "/proc/self/cgroup"
    $p_lib             = "/usr/lib/x86_64-linux-gnu/"
    $p_lib_ld          = "/lib64/ld-linux-x86-64.so.2"
    $p_sys             = /\/sys\/(devices|class)[\w\/\.\-]{0,32}/
    $p_sysctl          = /sysctl[ -a-z]{0,32}/
    $p_dev_watchdog    = "/dev/watchdog"
    $p_ps              = "/usr/bin/ps"
    $p_ss              = "/usr/bin/lsof"
    $p_ssh             = "/usr/bin/ssh"
    $p_dev_shm         = "/dev/shm"

  condition:
    filesize < 64KB and $hash_bang in (0..2) and any of ($p_etc*) and 40 % of ($p*)
}
