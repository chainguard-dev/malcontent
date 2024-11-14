rule fts {
  meta:
    description = "traverse filesystem hierarchy"
    syscall     = "openat,getdents"
    pledge      = "rpath"

  strings:
    $fts_open     = "_fts_open" fullword
    $fts_read     = "_fts_read" fullword
    $fts_children = "_fts_children" fullword
    $fts_set      = "_fts_set" fullword
    $fts_close    = "_fts_close" fullword

  condition:
    2 of them
}

rule py_walk: medium {
  meta:
    description                = "traverse filesystem hierarchy"

    hash_2021_A_g              = "ffb0a802fdf054d4988d68762d9922820bdc3728f0378fcd6c4ed28c06da5cf0"

  strings:
    $walk = "os.walk"

  condition:
    any of them
}
