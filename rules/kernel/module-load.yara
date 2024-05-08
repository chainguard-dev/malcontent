
rule init_module : notable {
  meta:
    description = "Load Linux kernel module"
    syscall = "init_module"
    capability = "CAP_SYS_MODULE"
  strings:
    $ref = "init_module" fullword
  condition:
    all of them
}

rule kernel_module_loader : suspicious {
  meta:
    hash_2023_init_d_vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"
    hash_2023_rc0_d_K70vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"
    hash_2023_rc1_d_K70vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"
  strings:
    $insmod = /insmod [ \$\%\w\.\/_-]{1,32}\.ko/
  condition:
    all of them
}
