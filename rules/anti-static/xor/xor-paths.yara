rule xor_paths: high {
  meta:
    description = "paths obfuscated using xor"

  strings:
    $dev_shm       = "/dev/shm" xor(1-31)
    $dev_shm2      = "/dev/shm" xor(33-255)
    $dev_null      = "/dev/null" xor(1-31)
    $dev_null2     = "/dev/null" xor(33-255)
    $dev_stdin     = "/dev/stdin" xor(1-31)
    $dev_stdin2    = "/dev/stdin" xor(33-255)
    $dev_stderr    = "/dev/stderr" xor(1-31)
    $dev_stderr2   = "/dev/stderr" xor(33-255)
    $proc_net_tcp  = "/proc/net/tcp" xor(1-31)
    $proc_net_tcp2 = "/proc/net/tcp" xor(33-255)
    $var_log_wtmp  = "/var/log/wtmp" xor(1-31)
    $var_log_wtmp2 = "/var/log/wtmp" xor(33-255)
    $var_run_utmp  = "/var/run/utmp" xor(1-31)
    $var_run_utmp2 = "/var/run/utmp" xor(33-255)
    $usr_bin       = "/usr/bin" xor(1-31)
    $usr_sbin      = "/usr/sbin" xor(1-31)
    $var_tmp       = "/var/tmp" xor(1-31)
    $var_run       = "/var/run" xor(1-31)
    $usr_bin2      = "/usr/bin" xor(33-255)
    $usr_sbin2     = "/usr/sbin" xor(33-255)
    $var_tmp2      = "/var/tmp" xor(33-255)
    $var_run2      = "/var/run" xor(33-255)

  condition:
    filesize < 10MB and any of them
}

