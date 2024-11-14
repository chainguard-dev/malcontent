rule env_LD_PROFILE: medium {
  meta:
    description = "may check if dynamic linker profiling is enabled"

  strings:
    $val = "LD_PROFILE" fullword

  condition:
    all of them
}
