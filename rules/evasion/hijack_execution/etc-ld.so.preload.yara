rule etc_ld_preload: medium linux {
  meta:
    description = "References /etc/ld.so.preload"

  strings:
    $ref = "/etc/ld.so.preload"

  condition:
    any of them
}

rule etc_ld_preload_not_ld: high linux {
  meta:
    description = "unexpected reference to /etc/ld.so.preload"

  strings:
    $ref           = "/etc/ld.so.preload"
    $not_env_aux   = "LD_SHOW_AUXV"
    $not_env_hwcap = "LD_HWCAP_MASK"
    $not_env_audit = "LD_AUDIT"
    $not_cache     = "ld.so.cache"
    $not_man       = "MAN_DISABLE_SECCOMP"

  condition:
    $ref and none of ($not*)
}
