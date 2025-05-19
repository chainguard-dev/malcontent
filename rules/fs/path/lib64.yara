rule elf_lib_dir_refs: harmless {
  meta:
    description = "references /lib64 path"
    filetypes   = "elf"

  strings:
    $ref  = /\/lib64\/[\%\w\.\-\/]{4,32}/ fullword
    $ref2 = /usr\/lib64\/[\%\w\.\-\/]{4,32}/ fullword

  condition:
    uint32(0) == 1179403647 and any of them
}
