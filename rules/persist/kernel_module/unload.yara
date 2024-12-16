rule kernel_module_unloader: medium linux {
  meta:
    description = "unloads Linux kernel module via rmmod"

  strings:
    $insmod = /rmmod [ \#\{\}\$\%\w\.\/_-]{1,32}/

  condition:
    filesize < 10MB and all of them
}

rule kernel_module_unloader_sus: high linux {
  meta:
    description = "unloads Linux kernel module via rmmod, discarding output"

  strings:
    $insmod = /rmmod.{0,32}2\>\s{0,2}\/dev\/null/

  condition:
    filesize < 10MB and any of them
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

rule system_kext_unloader: high {
  meta:
    description = "unloads system kernel extensions"

  strings:
    $kextunload_sys_lib_ext = "kextunload /System/Library/Extensions/"

  condition:
    filesize < 10485760 and any of them
}
