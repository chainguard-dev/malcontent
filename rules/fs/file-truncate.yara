rule ftruncate {
  meta:
    syscall     = "ftruncate"
    description = "truncate a file to a specified length"

  strings:
    $ref  = "ftruncate64" fullword
    $ref2 = "ftruncate" fullword

  condition:
    any of them
}

rule truncate: harmless {
  meta:
    syscall     = "truncate"
    description = "truncate a file to a specified length"

  strings:
    $ref = "truncate" fullword

  condition:
    any of them
}

