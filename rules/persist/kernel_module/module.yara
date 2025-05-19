import "elf"

rule register_kprobe: medium {
  meta:
    description = "registers a kernel probe (possibly kernel module)"

  strings:
    $ref = "register_kprobe"

  condition:
    any of them
}

rule lkm: medium {
  meta:
    description = "Linux kernel module"
    capability  = "CAP_SYS_MODULE"

  strings:
    $vergmagic  = "vermagic="
    $srcversion = "srcversion="

  condition:
    all of them
}

rule lkm_embedded_in_elf: high {
  meta:
    description = "Contains embedded Linux kernel module"
    capability  = "CAP_SYS_MODULE"

  strings:
    $vergmagic  = "vermagic="
    $srcversion = "srcversion="

  condition:
    elf.type == elf.ET_EXEC and all of them
}

rule init_module: medium linux {
  meta:
    description = "Linux kernel module"
    syscall     = "init_module"
    capability  = "CAP_SYS_MODULE"

    filetypes = "elf,ko,so"

  strings:
    $ref = "init_module" fullword

  condition:
    filesize < 1MB and all of them
}
