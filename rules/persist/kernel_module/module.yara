import "elf"

rule lkm: medium {
  meta:
    description = "Linux kernel module"
    capability  = "CAP_SYS_MODULE"

    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"

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

    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"

  strings:
    $vergmagic  = "vermagic="
    $srcversion = "srcversion="

  condition:
    elf.type == elf.ET_EXEC and all of them
}

rule delete_module: medium {
  meta:
    description = "Unload Linux kernel module"
    syscall     = "delete_module"
    capability  = "CAP_SYS_MODULE"

  strings:
    $ref = "delete_module" fullword

  condition:
    all of them
}
