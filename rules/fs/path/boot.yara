rule boot_path: medium {
  meta:
    description = "path reference within /boot"

  strings:
    $ref = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    $ref
}

rule elf_boot_path: medium {
  meta:
    description = "path reference within /boot"
    filetypes   = "elf"

  strings:
    $ref              = /\/boot\/[\%\w\.\-\/]{4,32}/ fullword
    $not_kern         = "/boot/vmlinux-%s"
    $not_include_path = "_PATH_UNIX" fullword

  condition:
    // $ref matches "/boot/vmlinux-%s" in full, one match per occurrence, so require a
    // /boot path beyond that accepted spelling; _PATH_UNIX marks a <paths.h> consumer
    // regardless of which /boot path is present, so it stays an absolute suppressor
    uint32(0) == 1179403647 and #ref > #not_kern and not $not_include_path
}
