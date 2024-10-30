rule madvise: harmless {
  meta:
    syscall     = "madvise"
    description = "give advice about use of memory"

  strings:
    $ref = "madvise" fullword

  condition:
    any of them
}
