rule env_LD_DEBUG: medium {
  meta:
    description = "may check if dynamic linker debugging is enabled"

  strings:
    $val = "LD_DEBUG" fullword

  condition:
    all of them
}
