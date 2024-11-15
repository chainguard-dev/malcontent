rule proc_self_status: medium {
  meta:
    description = "gets status associated to this process, including capabilities"
    pledge      = "stdio"

  strings:
    $ref = "/proc/self/status" fullword

  condition:
    any of them
}
