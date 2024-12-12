rule is_busybox: low {
  meta:
    description = "busybox binary"

  strings:
    $ref  = "Usage: busybox" fullword
    $ref2 = "BusyBox is copyrighted" fullword
    $re3  = "is a multi-call binary that" fullword

  condition:
    filesize < 3MB and all of them
}

rule busybox: override {
  meta:
    description                           = "busybox"
    ubi                                   = "low"
    dev_mem                               = "low"
    linux_critical_system_paths_small_elf = "low"
    possible_reverse_shell                = "ignore"

  condition:
    is_busybox
}
