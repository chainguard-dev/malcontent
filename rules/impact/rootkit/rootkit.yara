rule linux_register_kprobe_getdents64: critical linux {
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
