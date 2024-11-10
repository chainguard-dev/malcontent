rule getpid: harmless {
  meta:
    syscall     = "getpid"
    description = "gets the active process ID"

  strings:
    $ref    = "getpid" fullword
    $Getpid = "Getpid" fullword
    $procID = "processID" fullword

  condition:
    any of them
}
