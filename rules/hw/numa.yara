rule move_pages: harmless {
  meta:
    capability  = "CAP_SYS_NICE"
    syscall     = "move_pages"
    description = "move pages of a process to another node"

  strings:
    $ref = "move_pages" fullword

  condition:
    any of them
}

rule migrate_pages: harmless {
  meta:
    capability  = "CAP_SYS_NICE"
    syscall     = "migrate_pages"
    description = "migrate pages of a process to another node"

  strings:
    $ref = "migrate_pages" fullword

  condition:
    any of them
}
