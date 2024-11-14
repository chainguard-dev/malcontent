rule proc_mounts: medium {
  meta:
    description              = "Parses active mounts (/proc/mounts"
    pledge                   = "stdio"
    hash_2023_Downloads_311c = "311c93575efd4eeeb9c6674d0ab8de263b72a8fb060d04450daccc78ec095151"

  strings:
    $ref = "/proc/mounts" fullword

  condition:
    any of them
}
