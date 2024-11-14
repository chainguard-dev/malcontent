rule linux_kernel_module_getdents64: critical linux {
  meta:
    description = "kernel module that intercepts directory listing"
    ref         = "https://github.com/m0nad/Diamorphine"

    filetypes = "elf,so"

  strings:
    $register_kprobe = "register_kprobe"
    $f_getdents64    = "getdents64"
    $f_filldir64     = "filldir64"

  condition:
    filesize < 1MB and $register_kprobe and any of ($f*)
}

rule linux_kernel_module_hider: critical linux {
  meta:
    description = "kernel module that hides files and open ports"
    ref         = "https://github.com/m0nad/Diamorphine"

    filetypes = "elf,so"

  strings:
    $register_kprobe = "register_kprobe"
    $f_getdents64    = "getdents64"
    $f_filldir64     = "filldir64"
    $n_tcp4_seq_show = "tcp4_seq_show"

  condition:
    filesize < 1MB and $register_kprobe and any of ($f*) and any of ($n*)
}

rule linux_kernel_module_hide_self: critical linux {
  meta:
    description = "kernel module that hides itself"
    filetypes   = "elf,so"

  strings:
    $register_kprobe = "register_kprobe"
    $hide_self       = "hide_self"
    $hide_module     = "hide_module"

  condition:
    filesize < 1MB and $register_kprobe and any of ($hide*)
}

rule funky_high_signal_killer: high {
  meta:
    description = "Uses high signals to communicate to a rootkit"

    hash_2023_Qubitstrike_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"

  strings:
    $odd_teen_sig = /kill -1[012346789]/ fullword
    $high_sig     = /kill -[23456]\d/ fullword

  condition:
    filesize < 10MB and any of them
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
