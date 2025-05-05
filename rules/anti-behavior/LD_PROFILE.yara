rule env_LD_PROFILE: medium {
  meta:
    description = "may check if dynamic linker profiling is enabled"
    filetypes   = "application/x-elf,application/x-mach-binary"

  strings:
    $val = "LD_PROFILE" fullword

  condition:
    all of them
}
