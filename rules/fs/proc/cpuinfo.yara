rule proc_cpuinfo: medium {
  meta:
    description = "get CPU info"

  strings:
    $ref = "/proc/cpuinfo" fullword

  condition:
    any of them
}
