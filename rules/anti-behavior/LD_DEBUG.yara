rule env_LD_DEBUG: medium {
  meta:
    description = "may check if dynamic linker debugging is enabled"
    filetypes   = "elf,macho"

  strings:
    $val = "LD_DEBUG" fullword

  condition:
    all of them
}
