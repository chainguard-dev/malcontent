rule symlink: harmless {
  meta:
    syscall     = "symlink"
    pledge      = "cpath"
    description = "creates symbolic links"

  strings:
    $ref = "symlink" fullword
    $ls  = "symlink to"

  condition:
    $ref and not $ls
}

rule _symlink: harmless {
  meta:
    syscall     = "symlink"
    pledge      = "cpath"
    description = "creates symbolic links"

  strings:
    $ref = "_symlink" fullword

  condition:
    any of them
}

rule symlinkat: harmless {
  meta:
    syscall     = "symlinkat"
    pledge      = "cpath"
    description = "creates symbolic links"

  strings:
    $ref = "symlinkat" fullword

  condition:
    any of them
}
