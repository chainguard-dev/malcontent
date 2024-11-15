rule proc_self_cmdline: medium linux {
  meta:
    description = "gets process command-line"
    pledge      = "stdio"

  strings:
    $ref = "/proc/self/cmdline" fullword

  condition:
    any of them
}
