rule kallsyms_lookup: high {
  meta:
    description = "access unexported kernel symbols"
    ref         = "https://lwn.net/Articles/813350/"

    filetypes = "c,elf,so"

  strings:
    $ref           = "kallsyms_lookup_name" fullword
    $not_bpf       = "BPF_FUNC_kallsyms_lookup_name"
    $not_linux_src = "GPL-2.0 WITH Linux"
    $not_include   = "#define "

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule kallsyms: medium {
  meta:
    description = "access kernel symbols"
    filetypes   = "c,elf,so"

  strings:
    $kallsyms = "/proc/kallsyms"

  condition:
    any of them
}

rule bpftrace: medium {
  meta:
    description = "bpftrace"
    filetypes   = "c,elf,so"

  strings:
    $ref2 = "BPFTRACE" fullword

  condition:
    filesize < 2MB and any of them
}

rule bpf: override {
  meta:
    description     = "libbpf"
    filetypes       = "c,so,elf"
    kallsyms_lookup = "medium"
    proc_d_exe_high = "medium"
    proc_d_cmdline  = "medium"

  strings:
    $ref  = "BPF" fullword
    $ref2 = "LIBBPF" fullword

  condition:
    filesize < 2MB and any of them
}
