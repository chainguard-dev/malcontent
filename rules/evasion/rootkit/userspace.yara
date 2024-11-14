rule readdir_intercept_source: high {
  meta:
    description = "userland rootkit source designed to hide files (DECLARE_READDIR)"
    filetypes   = "so,c"

  strings:
    $declare = "DECLARE_READDIR"
    $hide    = "hide"

  condition:
    filesize < 200KB and all of them
}

rule hide_dir_contents: high {
  meta:
    description = "userland rootkit source designed to hide files"
    filetypes   = "so,c"

  strings:
    $readdir64 = "readdir64"

    $ref1 = "hidedircontents"
    $ref2 = "unhide_self"
    $ref3 = "unhide_path"
    $ref4 = "hidemyass"

  condition:
    filesize < 300KB and $readdir64 and any of ($ref*)
}

rule readdir_intercept: high {
  meta:
    description        = "userland rootkit designed to hide files (readdir64)"
    hash_2023_lib_pkit = "8faa04955eeb6f45043003e23af39b86f1dbfaa12695e0e1a1f0bc7a15d0d116"

    hash_2023_lib_skit = "427b1d16f16736cf8cee43a7c54cd448ca46ac9b573614def400d2d8d998e586"
    filetypes          = "so,c"

  strings:
    $r_new65      = "readdir64" fullword
    $r_old64      = "_readdir64"
    $r_new32      = "readdir" fullword
    $r_old32      = "_readdir"
    $not_ld_debug = "LD_DEBUG"
    $not_libc     = "getusershell"

  condition:
    filesize < 2MB and uint32(0) == 1179403647 and all of ($r*) and none of ($not*)
}

rule readdir_tcp_wrapper_intercept: high {
  meta:
    description = "userland rootkit designed to hide files and bypass tcp-wrappers"
    ref         = "https://github.com/ldpreload/Medusa"
    filetypes   = "so,c"

  strings:
    $r_new65        = "readdir64" fullword
    $r_old64        = "_readdir64"
    $r_new32        = "readdir" fullword
    $r_old32        = "_readdir"
    $r_hosts_access = "hosts_access"

  condition:
    filesize < 2MB and uint32(0) == 1179403647 and all of ($r*)
}

rule medusa_like_ld_preload: critical linux {
  meta:
    description = "LD_PRELOAD rootkit"
    ref         = "https://github.com/ldpreload/Medusa"

  strings:
    $cloned_thread   = "DYNAMIC LINKER BUG!"
    $__execve        = "__execve" fullword
    $lxstat64        = "__lxstat64" fullword
    $syslog          = "syslog" fullword
    $LD_PRELOAD      = "LD_PRELOAD" fullword
    $LD_LIBRARY_PATH = "LD_LIBRARY_PATH" fullword
    $archloaded      = "archloaded" fullword
    $rkload          = "rkload" fullword
    $wcs             = "wcsmbsload" fullword
    $readdir64       = "readdir64" fullword

  condition:
    filesize < 2MB and 85 % of them
}

rule linux_rootkit_terms: critical linux {
  meta:
    description = "appears to be a Linux rootkit"
    filetypes   = "elf,so"

  strings:
    $s_Rootkit = "Rootkit"
    $s_r00tkit = "r00tkit"
    $s_r00tk1t = "r00tk1t"
    $s_rootkit = "rootkit" fullword

    $o_systemctl = "systemctl" fullword
    $o_sshd      = "sshd" fullword
    $o_miner     = "miner" fullword

  condition:
    filesize < 10MB and any of ($s*) and any of ($o*)
}

rule linux_process_hider: critical linux {
  meta:
    description        = "userland rootkit designed to hide processes"
    ref                = "prochid.c"
    hash_2023_OK_c38c  = "c38c21120d8c17688f9aeb2af5bdafb6b75e1d2673b025b720e50232f888808a"
    hash_2023_lib_pkit = "8faa04955eeb6f45043003e23af39b86f1dbfaa12695e0e1a1f0bc7a15d0d116"

  strings:
    $f_proc_self_fd      = "/proc/self/fd/%d"
    $f_proc_stat         = "/proc/%s/stat"
    $f_readdir           = "readdir"
    $f_dlsym             = "dlsym"
    $f_readlink          = "readlink"
    $x_hide_process      = "hide_proc" fullword
    $x_proc_hide         = "proc_hide" fullword
    $x_process_hide      = "process_hide" fullword
    $x_process_hiding    = "process_hiding" fullword
    $x_hidden_proc       = "hidden_proc" fullword
    $x_prochide          = "processhide"
    $x_process_to_filter = "process_to_filter"
    $x_old_readdir       = "old_readdir"
    $x_orig_readdir      = "orig_readdir"
    $x_original_readdir  = "original_readdir"
    $x_readdirOriginal   = "readdirOriginal"
    $x_backdoor          = "backdoor" fullword
    $x_is_hidden         = "is_hidden" fullword
    $x_hidden_gid        = "HIDDEN_GID" fullword
    $x_revshell          = "revshell" fullword
    $x_cmdline           = "/proc/self/cmdline"
    $not_bpf             = "/sys/fs/bpf"

  condition:
    filesize < 250KB and all of ($f*) and any of ($x*) and none of ($not*)
}

rule unhide_myself: high {
  meta:
    description = "userspace rootkit designed to hide itself"

  strings:
    $hiding_self = /\w{0,2}[Hh]iding self/ fullword
    $o_readdir64 = "readdir64"

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and all of them
}
