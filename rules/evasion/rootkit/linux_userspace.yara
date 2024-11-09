rule readdir_intercept: high {
  meta:
    description           = "userland rootkit designed to hide files (readdir64)"
    hash_2023_lib_pkit    = "8faa04955eeb6f45043003e23af39b86f1dbfaa12695e0e1a1f0bc7a15d0d116"
    hash_2023_lib_pkitarm = "67de6ba64ee94f2a686e3162f2563c77a7d78b7e0404e338a891dc38ced5bd71"
    hash_2023_lib_skit    = "427b1d16f16736cf8cee43a7c54cd448ca46ac9b573614def400d2d8d998e586"
    filetypes             = "so,c"

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

rule elf_processhide: high {
  meta:
    description                          = "userland rootkit designed to hide processes"
    hash_2023_Unix_Coinminer_Xanthe_0e6d = "0e6d37099dd89c7eed44063420bd05a2d7b0865a0f690e12457fbec68f9b67a8"
    hash_2023_Unix_Malware_Agent_7337    = "73376cbb9666d7a9528b9397d4341d0817540448f62b22b51de8f6a3fb537a3d"
    hash_2023_Unix_Trojan_Prochider_234c = "234c0dd014a958cf5958a9be058140e29f46fca99eb26f5755f5ae935af92787"

  strings:
    $prochide          = "processhide"
    $process_to_filter = "process_to_filter"

  condition:
    all of them
}

rule linux_process_hider: critical linux {
  meta:
    description           = "userland rootkit designed to hide processes"
    ref                   = "prochid.c"
    hash_2023_OK_c38c     = "c38c21120d8c17688f9aeb2af5bdafb6b75e1d2673b025b720e50232f888808a"
    hash_2023_lib_pkit    = "8faa04955eeb6f45043003e23af39b86f1dbfaa12695e0e1a1f0bc7a15d0d116"
    hash_2023_lib_pkitarm = "67de6ba64ee94f2a686e3162f2563c77a7d78b7e0404e338a891dc38ced5bd71"

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

rule process_hider: high {
  meta:
    description = "possible userland rootkit designed to hide processes"

  strings:
    $hide_process   = "hide_proc" fullword
    $proc_hide      = "proc_hide" fullword
    $process_hide   = "process_hide" fullword
    $process_hiding = "process_hiding" fullword
    $hidden_proc    = "hidden_proc" fullword

  condition:
    filesize < 250KB and any of them
}
