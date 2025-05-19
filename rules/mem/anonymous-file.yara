rule memfd_create: medium {
  meta:
    syscall     = "memfd_create"
    description = "create an anonymous file"
    capability  = "CAP_IPC_LOCK"

  strings:
    $ref = "memfd_create" fullword
    $go  = "MemfdCreate"

  condition:
    any of them
}

rule go_memfd_create: high {
  meta:
    syscall     = "memfd_create"
    description = "create an anonymous file"
    capability  = "CAP_IPC_LOCK"
    filetypes   = "elf,go,macho"

  strings:
    $go = "MemfdCreate"

  condition:
    any of them
}
