rule flock {
  meta:
    pledge      = "flock"
    syscall     = "flock"
    description = "apply or remove an advisory lock on a file"

  strings:
    $ref = "flock" fullword

  condition:
    any of them
}

rule lockf {
  meta:
    pledge      = "flock"
    syscall     = "flock"
    description = "apply or remove an advisory lock on a file"

  strings:
    $ref = "lockf" fullword

  condition:
    any of them
}

