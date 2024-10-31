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
