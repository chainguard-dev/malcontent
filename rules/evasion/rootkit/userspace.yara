rule readdir_intercept_source: high {
  meta:
    description = "userland rootkit source designed to hide files (DECLARE_READDIR)"
    filetypes   = "c,so"

  strings:
    $declare = "DECLARE_READDIR"
    $hide    = "hide"

  condition:
    filesize < 200KB and all of them
}

rule hide_dir_contents: high {
  meta:
    description = "userland rootkit source designed to hide files"
    filetypes   = "c,so"

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
    description = "userland rootkit designed to hide files (readdir64)"

    filetypes = "c,so"

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

rule readdir_dlsym_interceptor: high {
  meta:
    description = "userland rootkit designed to hide files (readdir64+readlink)"

    filetypes = "c,so"

  strings:
    $f_dlsym                     = "dlsym" fullword
    $f_readdir64                 = "readdir64" fullword
    $f_readlink_maybe_not_needed = "readlink"
    $f_proc                      = "/proc"

    $not_j9   = "j9port_"
    $not_sbcl = "SBCL_HOME" fullword

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and all of ($f*) and none of ($not*)
}

rule readdir_tcp_wrapper_intercept: high {
  meta:
    description = "userland rootkit designed to hide files and bypass tcp-wrappers"
    ref         = "https://github.com/ldpreload/Medusa"
    filetypes   = "c,so"

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

    $not_pypi_index = "testpack-id-lb001"

  condition:
    filesize < 10MB and any of ($s*) and any of ($o*) and none of ($not*)
}

rule linux_process_hider: critical linux {
  meta:
    description = "userland rootkit designed to hide processes"
    ref         = "prochid.c"

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
    $x_is_invisible      = "is_invisible" fullword
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
