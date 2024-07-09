
rule linux_critical_system_paths_medium : medium {
  meta:
    description = "accesses multiple critical Linux paths"
  strings:
    $p_var_run = /\/var\/run[\w\/\.\-]{0,32}/
    $p_tmp = /\/tmp\/[\w\/\.\-]{0,32}/
    $p_usr_bin = /\/usr\/bin[\w\/\.\-]{0,32}/
    $p_boot = /\/boot\/[\w\/\.\-]{0,32}/
    $p_etc = /\/etc\/[\w\/\.\-]{0,32}/
    $p_proc = /\/proc\/[\w\/\.\-]{0,32}/
    $p_sys_devices = /\/sys\/devices[\w\/\.\-]{0,32}/
    $p_sys_class = /\/sys\/class[\w\/\.\-]{0,32}/
    $p_sysctl = /sysctl[ -a-z]{0,32}/
  condition:
    75% of ($p*)
}

rule linux_critical_system_paths_high : high {
  meta:
    description = "accesses multiple critical Linux paths"
  strings:
    $p_var_run = /\/var\/run[\w\/\.\-]{0,32}/
    $p_tmp = /\/tmp\/[\w\/\.\-]{0,32}/
    $p_usr_bin = /\/usr\/bin[\w\/\.\-]{0,32}/
    $p_boot = /\/boot\/[\w\/\.\-]{0,32}/
    $p_etc = /\/etc\/[\w\/\.\-]{0,32}/
    $p_proc = /\/proc\/[\w\/\.\-]{0,32}/
    $p_sys_devices = /\/sys\/devices[\w\/\.\-]{0,32}/
    $p_sys_class = /\/sys\/class[\w\/\.\-]{0,32}/
    $p_sysctl = /sysctl[ -a-z]{0,32}/
    $not_dirty = "/proc/sys/vm/dirty_bytes"
    $not_swappy = "/proc/sys/vm/swappiness"
    $not_somaxconn = "/prkyioc/sys/kernel/threads-max"
    $not_mime = "/etc/apache/mime.types"
    $not_clickhouse = "/tmp/jemalloc_clickhouse"
    $not_falco = "/etc/falco/certs"
    $not_pki = "/etc/pki/tls/cacert.pem"
    $not_docker = "/var/run/docker"
    $not_bpf = "/proc/sys/kernel/bpf_stats_enabled"
  condition:
    85% of ($p*) and none of ($not*)
}
