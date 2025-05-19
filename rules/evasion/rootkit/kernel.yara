rule linux_kernel_module_getdents64: critical linux {
  meta:
    description = "kernel module that intercepts directory listing"
    ref         = "https://github.com/m0nad/Diamorphine"

    filetypes = "elf,so"

  strings:
    $getdents64 = "getdents64"
    $kprobe     = "register_kprobe"
    $kallsyms   = "kallsyms_lookup_name"

  condition:
    filesize < 1MB and $getdents64 and any of ($k*)
}

rule linux_kernel_module_orig: high linux {
  meta:
    description = "kernel module that intercepts directory listing and signals"
    filetypes   = "elf,so"

  strings:
    $getdents64 = "orig_getdents64"
    $orig_kill  = "orig_kill"

  condition:
    filesize < 1MB and all of them
}

rule funky_high_signal_killer: high {
  meta:
    description = "Uses high signals to communicate to a rootkit"

  strings:
    $odd_teen_sig = /kill -1[012346789]/ fullword
    $high_sig     = /kill -[23456]\d/ fullword

  condition:
    filesize < 10MB and any of them
}

rule lkm_dirent: high {
  meta:
    description = "kernel rootkit designed to hide files (linux_dirent)"

    filetypes = "so"

  strings:
    $l_dirent     = "linux_dirent"
    $linux        = "Linux"
    $not_syscalls = "#define _LINUX_SYSCALLS_H"
    $not_itimer   = "__kernel_old_itimerval"
    $not_internal = "internal_getdents"

  condition:
    filesize < 2MB and all of ($l*) and none of ($not*)
}

rule unhide: high {
  meta:
    description = "userspace rootkit designed to hide itself"

  strings:
    $hiding_self = /\w{0,2}[Hh]iding self/ fullword
    $o_getdents  = "getdents"

  condition:
    filesize < 256KB and uint32(0) == 1179403647 and all of them
}
