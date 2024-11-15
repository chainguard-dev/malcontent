rule proc_stat: medium {
  meta:
    description = "gets kernel/system statistics"

  strings:
    $ref = "/proc/stat" fullword

  condition:
    any of them
}
