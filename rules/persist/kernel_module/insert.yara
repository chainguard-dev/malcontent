rule kernel_module_loader: medium linux {
  meta:
    description               = "loads Linux kernel module via insmod"
    hash_2023_init_d_vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"

  strings:
    $insmod = /insmod [ \$\%\w\.\/_-]{1,32}/

  condition:
    filesize < 10MB and all of them
}

rule kernel_module_loader_ko: high linux {
  meta:
    description               = "loads Linux kernel module .ko via insmod"
    hash_2023_init_d_vm_agent = "663b75b098890a9b8b02ee4ec568636eeb7f53414a71e2dbfbb9af477a4c7c3d"

  strings:
    $insmod = /insmod [ \$\%\w\.\/_-]{1,32}\.ko/

  condition:
    filesize < 10MB and all of them
}

rule kernel_module_loader_sus_redir: high linux {
  meta:
    description = "suspiciously loads Linux kernel module via insmod"

  strings:
    $insmod = /insmod [ \$\%\w\.\/_-]{1,32} .{0,16}\/dev\/null 2\>\&1/

  condition:
    filesize < 10MB and all of them
}

rule cha_cha_tests: override linux {
  meta:
    description             = "test_cipher.ko"
    filetypes               = "sh"
    kernel_module_loader_ko = "medium"

  strings:
    $test = "insmod test_cipher.ko size"

  condition:
    filesize < 2KB and any of them
}

rule init_module: medium linux {
  meta:
    description = "Linux kernel module"
    syscall     = "init_module"
    capability  = "CAP_SYS_MODULE"

    hash_2023_LQvKibDTq4_diamorphine = "e93e524797907d57cb37effc8ebe14e6968f6bca899600561971e39dfd49831d"
    filetypes                        = "ko,elf,so"

  strings:
    $ref = "init_module" fullword

  condition:
    filesize < 1MB and all of them
}

