rule getppid {
  meta:
    description = "gets parent process ID"

  strings:
    $ref  = "getppid" fullword
    $ref2 = "process.ppid" fullword

  condition:
    any of them
}
