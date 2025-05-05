rule env_LD_DEBUG: medium {
  meta:
    description = "may check if dynamic linker debugging is enabled"
    filetypes   = "application/x-elf,application/x-mach-binary"

  strings:
    $val = "LD_DEBUG" fullword

  condition:
    all of them
}
