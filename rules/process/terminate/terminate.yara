rule TerminateProcess: medium {
  meta:
    description = "terminate a process"

  strings:
    $kill = "KillProcess" fullword
    $term = "TerminateProcess" fullword

  condition:
    any of them
}

