rule env_LD_PROFILE: medium {
  meta:
    description = "may check if dynamic linker profiling is enabled"
    filetypes   = "elf,macho"

  strings:
    $val = "LD_PROFILE" fullword

  condition:
    all of them
}
