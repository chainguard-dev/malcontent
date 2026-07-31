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
    $ref     = "/etc/ld.so.preload"
    $not_man = "MAN_DISABLE_SECCOMP"

    $notld_aux   = "LD_SHOW_AUXV"
    $notld_hwcap = "LD_HWCAP_MASK"
    $notld_audit = "LD_AUDIT"
    $notld_cache = "ld.so.cache"

  condition:
    // the four loader strings together describe glibc's own ld.so; individually they
    // are ordinary dynamic-linker vocabulary that rootkits use too, so require the
    // complete set before suppressing
    $ref and none of ($not_*) and not all of ($notld_*)
}
